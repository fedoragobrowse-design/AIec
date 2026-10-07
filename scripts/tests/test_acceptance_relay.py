"""Exercise the actual relay CLI with pressure in both directions and half-close."""

import hashlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import urlsplit

RELAY = Path(__file__).resolve().parents[1] / "acceptance-relay.py"


class AcceptanceRelayTest(unittest.TestCase):
    def test_backpressure_and_half_close_preserve_the_entire_exchange(self):
        upload = b"x" * 65536
        download = b"y" * 65536
        expected_upload = hashlib.sha256()
        for _ in range(256):
            expected_upload.update(upload)
        expected_response = hashlib.sha256(expected_upload.digest())
        for _ in range(128):
            expected_response.update(download)
        upstream_result = {}

        with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(10)

            def upstream():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(10)
                        # Kernel buffers cannot hold the whole upload. Until we
                        # read, the relay must pause rather than close or drop.
                        time.sleep(.5)
                        received = hashlib.sha256()
                        size = 0
                        while chunk := connection.recv(65536):
                            size += len(chunk)
                            received.update(chunk)
                        upstream_result["size"] = size
                        upstream_result["digest"] = received.digest()
                        connection.sendall(received.digest())
                        for _ in range(128):
                            connection.sendall(download)
                except Exception as error:
                    upstream_result["error"] = repr(error)

            thread = threading.Thread(target=upstream, daemon=True)
            thread.start()
            address = str(Path(directory) / "relay.sock")
            relay = subprocess.Popen(
                ["python3", str(RELAY), "unix", address, "tcp",
                 f"127.0.0.1:{listener.getsockname()[1]}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 5
                while not Path(address).exists() and time.monotonic() < deadline:
                    self.assertIsNone(relay.poll(), "relay exited before listening")
                    time.sleep(.01)
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(10)
                    client.connect(address)
                    for _ in range(256):
                        client.sendall(upload)
                    # The final response is produced only after upload EOF.
                    # Closing both sockets here loses an otherwise valid reply.
                    client.shutdown(socket.SHUT_WR)
                    # Apply independent pressure to the reverse direction.
                    time.sleep(.5)
                    response = hashlib.sha256()
                    size = 0
                    while chunk := client.recv(65536):
                        size += len(chunk)
                        response.update(chunk)
                thread.join(15)
                self.assertFalse(thread.is_alive(), "upstream did not finish")
                self.assertNotIn("error", upstream_result, upstream_result)
                self.assertEqual(upstream_result["size"], 256 * len(upload))
                self.assertEqual(upstream_result["digest"], expected_upload.digest())
                self.assertEqual(size, 128 * len(download) + 32)
                self.assertEqual(response.digest(), expected_response.digest())
            finally:
                relay.terminate()
                relay.communicate(timeout=5)
                thread.join(15)

    def test_relay_authenticates_the_original_database_tls_identity(self):
        openssl = shutil.which("openssl")
        if openssl is None:
            self.skipTest("openssl is required to create the isolated TLS fixture")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(
                [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-days", "1", "-subj", "/CN=relay-fixture",
                 "-addext", "subjectAltName=IP:127.0.0.1",
                 "-addext", "basicConstraints=critical,CA:FALSE",
                 "-keyout", str(key), "-out", str(cert)],
                check=True, capture_output=True, timeout=20,
            )
            key.chmod(0o600)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert, key)
            client_context = ssl.create_default_context(cafile=str(cert))
            # A query host overrides the URI authority. The negative case must
            # still reject a certificate for a different database identity.
            for authority, query, trusted in (
                ("127.0.0.1", "", True),
                ("wrong.invalid", "&ho%73t=127.0.0.1", True),
                ("wrong.invalid", "", False),
            ):
                with self.subTest(authority=authority, query=query):
                    with socket.socket() as listener:
                        listener.bind(("127.0.0.1", 0))
                        listener.listen()
                        listener.settimeout(5)
                        errors = []

                        def upstream():
                            try:
                                connection, _ = listener.accept()
                                with connection:
                                    connection.settimeout(5)
                                    with server_context.wrap_socket(
                                        connection, server_side=True,
                                    ) as stream:
                                        stream.recv(1)
                            except ssl.SSLError:
                                if trusted:
                                    errors.append("trusted TLS handshake refused")
                            except Exception as error:
                                errors.append(repr(error))

                        thread = threading.Thread(target=upstream, daemon=True)
                        thread.start()
                        address = root / ".s.PGSQL.5432"
                        relay = subprocess.Popen(
                            ["python3", str(RELAY), "unix", str(address), "tcp",
                             f"127.0.0.1:{listener.getsockname()[1]}"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                        )
                        try:
                            deadline = time.monotonic() + 5
                            while not address.exists() and time.monotonic() < deadline:
                                self.assertIsNone(relay.poll())
                                time.sleep(.01)
                            url = (f"postgresql://fixture@{authority}/aiec_guard_tls"
                                   f"?sslmode=verify-full{query}")
                            result = subprocess.run(
                                ["bash", "-c",
                                 'source "$1"; acceptance_database_url_for_socket "$2" "$3"',
                                 "relay-tls", str(RELAY.parent / "acceptance-db.sh"),
                                 url, directory],
                                capture_output=True, text=True, timeout=10,
                            )
                            self.assertEqual(result.returncode, 0, result.stderr)
                            with socket.socket(socket.AF_UNIX) as client:
                                client.settimeout(5)
                                client.connect(str(address))
                                # SQLx uses the authority hostname for TLS even
                                # when the host query selects a Unix socket.
                                hostname = urlsplit(result.stdout).hostname
                                if trusted:
                                    with client_context.wrap_socket(
                                        client, server_hostname=hostname,
                                    ) as stream:
                                        self.assertEqual(
                                            stream.getpeercert()["subjectAltName"],
                                            (("IP Address", "127.0.0.1"),),
                                        )
                                        stream.sendall(b"x")
                                else:
                                    with self.assertRaises(ssl.SSLCertVerificationError):
                                        client_context.wrap_socket(
                                            client, server_hostname=hostname,
                                        )
                            thread.join(6)
                            self.assertFalse(thread.is_alive())
                            self.assertEqual(errors, [])
                        finally:
                            relay.terminate()
                            relay.communicate(timeout=5)
                            thread.join(6)
                            address.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
