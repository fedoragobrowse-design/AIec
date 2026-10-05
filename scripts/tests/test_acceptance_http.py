"""Real-socket checks for the acceptance client's credential boundary."""

import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from acceptance_http import urlopen


class AcceptanceHttpTest(unittest.TestCase):
    def setUp(self):
        self.target_requests = []
        self.origin_requests = []
        self.redirect_status = 302
        self.key = "synthetic-acceptance-bearer"
        fixture = self

        class Target(BaseHTTPRequestHandler):
            def do_GET(self):
                fixture.target_requests.append(True)
                body = b'{"origin":"target"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET

            def log_message(self, *args):
                pass

        class Origin(BaseHTTPRequestHandler):
            def do_GET(self):
                data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                fixture.origin_requests.append({
                    "method": self.command,
                    "path": self.path,
                    "body": data,
                    "authorized": self.headers.get("Authorization") == "Bearer " + fixture.key,
                })
                body = b'{"origin":"configured"}'
                self.send_response(fixture.redirect_status if self.path == "/redirect" else 200)
                if self.path == "/redirect":
                    self.send_header("Location", fixture.target_url)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_POST = do_GET

            def log_message(self, *args):
                pass

        for name, handler in (("target", Target), ("origin", Origin)):
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            setattr(self, name + "_url", f"http://127.0.0.1:{server.server_port}")

    def request(self, path, method):
        return urllib.request.Request(
            self.origin_url + path,
            data=b'{"fixture":true}' if method == "POST" else None,
            method=method,
            headers={"Authorization": "Bearer " + self.key},
        )

    def test_redirects_are_errors_and_never_contact_the_target(self):
        for method in ("GET", "POST"):
            for status in (301, 302, 303, 307, 308):
                with self.subTest(method=method, status=status):
                    self.redirect_status = status
                    self.target_requests.clear()
                    self.origin_requests.clear()
                    with self.assertRaises(urllib.error.HTTPError) as caught:
                        urlopen(self.request("/redirect", method), timeout=2)
                    with caught.exception as response:
                        self.assertEqual(response.code, status)
                        self.assertEqual(json.loads(response.read()), {"origin": "configured"})
                    self.assertEqual(self.target_requests, [])
                    self.assertEqual(self.origin_requests[-1]["method"], method)
                    self.assertTrue(self.origin_requests[-1]["authorized"])


if __name__ == "__main__":
    unittest.main()
