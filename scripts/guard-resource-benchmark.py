#!/usr/bin/env python3
"""Linux-only, process-isolated §51 gateway benchmark; no guest/image mutation.

Build first: cargo build --release -p aiec-guard --example guard_resource_gateway
Run: python3 scripts/guard-resource-benchmark.py --output benchmarks/guard-resource-benchmark.json
"""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import resource
import secrets
import selectors
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import uuid

CHUNK = bytes(range(256)) * 64
BODY = b'{"model":"benchmark","stream":true,"messages":[{"role":"user","content":"measure"}]}'
HZ = os.sysconf("SC_CLK_TCK")


def snapshot(pid):
    # comm may contain spaces and ')'; offsets are relative to the final ')'.
    fields = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines())
    return {"cpu_ticks": int(fields[11]) + int(fields[12]),
            "rss_kib": int(status["VmRSS"].split()[0]),
            "hwm_kib": int(status["VmHWM"].split()[0])}


def meter_control():
    print("ready", flush=True)
    sys.stdin.readline()
    memory = bytearray(32 * 1024 * 1024)
    memory[::4096] = b"x" * (len(memory) // 4096)
    until = time.monotonic() + 0.3
    while time.monotonic() < until:
        sum(range(10000))
    print(len(memory), flush=True)
    sys.stdin.readline()


def positive_control():
    child = subprocess.Popen([sys.executable, __file__, "--meter-control"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "ready"
        before = snapshot(child.pid)
        child.stdin.write("go\n")
        child.stdin.flush()
        assert child.stdout.readline().strip() == str(32 * 1024 * 1024)
        after = snapshot(child.pid)
        ticks = after["cpu_ticks"] - before["cpu_ticks"]
        growth = after["rss_kib"] - before["rss_kib"]
        assert ticks >= HZ * 0.2 and growth >= 24 * 1024, "resource meter control failed"
        return {"cpu_ticks_delta": ticks, "rss_growth_kib": growth,
                "allocated_bytes": 32 * 1024 * 1024, "minimum_burn_seconds": 0.3}
    finally:
        child.communicate("exit\n", timeout=5)
        assert child.returncode == 0


def client():
    config = json.load(sys.stdin)
    expected = hashlib.sha256(CHUNK * config["chunks"]).hexdigest()
    start_usage = resource.getrusage(resource.RUSAGE_SELF)
    started = time.monotonic()
    first_bytes = []
    for _ in range(config["requests"]):
        connection = http.client.HTTPConnection(config["address"], config["port"], timeout=30)
        try:
            start = time.monotonic()
            connection.request("POST", config["path"], BODY,
                               {"Authorization": config["authorization"], "Content-Type": "application/json"})
            response = connection.getresponse()
            if response.status != config.get("status", 200):
                reason = response.read(2048).decode(errors="replace").replace(config["authorization"], "[redacted]")
                raise RuntimeError(f"unexpected HTTP {response.status}: {reason}")
            if response.status != 200:
                response.read()
                continue
            digest = hashlib.sha256()
            total = 0
            while True:
                block = response.read(16384)
                if not block:
                    break
                if total == 0:
                    first_bytes.append((time.monotonic() - start) * 1000)
                total += len(block)
                digest.update(block)
            assert total == config["chunks"] * len(CHUNK) and digest.hexdigest() == expected, "response integrity failed"
        finally:
            connection.close()
    usage = resource.getrusage(resource.RUSAGE_SELF)
    print(json.dumps({"wall_seconds": time.monotonic() - started,
                      "cpu_seconds": usage.ru_utime + usage.ru_stime - start_usage.ru_utime - start_usage.ru_stime,
                      "peak_rss_kib": usage.ru_maxrss, "requests": config["requests"],
                      "response_bytes": config["requests"] * config["chunks"] * len(CHUNK),
                      "response_sha256": expected, "first_byte_median_ms": statistics.median(first_bytes) if first_bytes else None}))


class Fixture:
    def __init__(self, directory, chunks):
        self.directory, self.chunks = directory, chunks
        self.secret, self.worker = secrets.token_hex(32), secrets.token_hex(32)
        self.identity, self.fence = None, None
        self.lock = threading.Lock()
        self.hits = 0
        self.authority_refusals = 0
        self.refuse = False
        self.node = str(uuid.uuid4())
        self.db = sqlite3.connect(directory / "budget.sqlite", check_same_thread=False)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE ledger(requests INTEGER, bytes_in INTEGER, bytes_out INTEGER, reservations INTEGER)")
        self.db.execute("INSERT INTO ledger VALUES(0,0,0,0)")
        self.db.commit()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def empty(self, status):
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self):
                self.connection.settimeout(30)
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    decoded = bytearray()
                    while True:
                        size_line = self.rfile.readline(128)
                        assert size_line.endswith(b"\r\n")
                        size = int(size_line.split(b";", 1)[0], 16)
                        assert 0 <= size <= 65536 - len(decoded)
                        if size == 0:
                            assert self.rfile.readline(128) == b"\r\n"
                            break
                        block = self.rfile.read(size)
                        assert len(block) == size and self.rfile.read(2) == b"\r\n"
                        decoded.extend(block)
                    body = bytes(decoded)
                else:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 <= length <= 65536:
                        self.empty(413)
                        return
                    body = self.rfile.read(length)
                if self.server is fixture.provider:
                    if self.path != "/v1/chat/completions" or self.headers.get("Authorization") != "Bearer " + fixture.secret or body != BODY:
                        self.empty(403)
                        return
                    with fixture.lock:
                        fixture.hits += 1
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    for _ in range(fixture.chunks):
                        self.wfile.write(b"4000\r\n" + CHUNK + b"\r\n")
                        self.wfile.flush()
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
                else:
                    request = json.loads(body)
                    with fixture.lock:
                        if (fixture.refuse or self.path != f"/v1/workers/{fixture.node}/guard/reserve"
                                or self.headers.get("Authorization") != "Bearer " + fixture.worker
                                or request["identity"] != fixture.identity or request["fence"] != fixture.fence):
                            fixture.authority_refusals += 1
                            self.empty(403)
                            return
                        debit = request["debit"]
                        assert set(debit) == {"model_requests", "bytes_in", "bytes_out"}
                        assert all(isinstance(v, int) and v >= 0 for v in debit.values())
                        old = fixture.db.execute("SELECT * FROM ledger").fetchone()
                        values = tuple(old[i] + debit[k] for i, k in enumerate(("model_requests", "bytes_in", "bytes_out")))
                        if values[0] > 100000 or max(values[1:]) > 1 << 40:
                            self.empty(429)
                            return
                        fixture.db.execute("UPDATE ledger SET requests=?, bytes_in=?, bytes_out=?, reservations=?", (*values, old[3] + 1))
                        fixture.db.commit()  # Acknowledgment only after durable admission.
                    self.empty(204)

        self.provider = ThreadingHTTPServer(("198.18.0.10", 0), Handler)
        self.authority = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.threads = []
        for server in (self.provider, self.authority):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)

    def counts(self):
        with self.lock:
            return {"provider_requests": self.hits, "budget": list(self.db.execute("SELECT * FROM ledger").fetchone())}

    def close(self):
        for server in (self.provider, self.authority):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=5)
            assert not thread.is_alive()
        self.db.close()


def run_client(config, pid=None):
    readings = []
    sampling_errors = []
    stop = threading.Event()

    def sample():
        try:
            while not stop.is_set():
                readings.append(snapshot(pid))
                stop.wait(0.005)
        except Exception as error:
            sampling_errors.append(str(error))

    sampler = threading.Thread(target=sample) if pid else None
    if sampler:
        sampler.start()
    try:
        result = subprocess.run([sys.executable, __file__, "--client"], input=json.dumps(config),
                                text=True, capture_output=True, timeout=max(60, config["requests"] * 10), check=False)
        if result.returncode:
            diagnostic = result.stderr.replace(config["authorization"], "[redacted]")
            raise RuntimeError(f"client failed for {config['path']}: {diagnostic}")
        data = json.loads(result.stdout)
    finally:
        stop.set()
        if sampler:
            sampler.join()
    if pid:
        assert not sampling_errors, f"resource sampling failed: {sampling_errors}"
        assert readings, "missing RSS samples"
        data["gateway_sampled_peak_rss_kib"] = max(r["rss_kib"] for r in readings)
        data["gateway_rss_readings"] = len(readings)
    return data


def private_json(path, value):
    with path.open("x") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream)


def benchmark(args):
    result = {"schema_version": 1, "status": "PASS", "samples_per_side": args.samples,
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "namespace_isolation": "fresh user+network namespace; recorded host inode differs; no external interface",
              "hardware": {"kernel_arch": platform.platform(), "machine": platform.machine(),
                           "cpu_model": next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")),
                           "logical_cpus": os.cpu_count(), "gateway_cpu_affinity": sorted(os.sched_getaffinity(0))},
              "measurement": {"cpu": "/proc/PID/stat utime+stime; all gateway threads; ticks converted with sysconf",
                              "clock_ticks_per_second": HZ, "rss": "VmRSS sampled every 5 ms; VmHWM lifetime high-water also recorded",
                              "scope": "production GuardGateway library in a separate release acceptance process, including HTTP budget client, credential substitution, file-event sink and DNS listener",
                              "owner_heartbeat": "acceptance owner activates and heartbeats every 5 seconds; external watchdog excluded",
                              "excluded": "provider, client, SQLite authority, Firecracker, guest, nftables, watcher and control-plane server",
                              "baseline": "same warmed gateway process idle while identical direct client workload bypasses it; separate 1-second idle rate for time normalization",
                              "transport": "local HTTP in disposable network namespace; benchmark-only provider address; not WAN/TLS/guest overhead",
                              "ordering": "fresh gateway per pair; two warmup requests per side; alternating direct/guarded order",
                              "aggregation": "conventional median per side; paired differences separately named; no confidence interval or percentile claim"},
              "workload": {"requests_per_sample": args.requests, "concurrency": 1, "response_bytes_per_request": args.chunks * len(CHUNK),
                           "provider_chunk_bytes": len(CHUNK), "request_bytes": len(BODY), "warmup_requests_per_side": 2},
              "meter_positive_control": positive_control(), "samples": [], "cleanup_errors": []}
    binary = Path(args.gateway).resolve()
    result["gateway_binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="aiec-gr-") as scratch:
        directory = Path(scratch)
        fixture = Fixture(directory, args.chunks)
        try:
            port = fixture.provider.server_port
            host = "model.resource.test"
            policy = {"version": 1, "network": {"dns": {"allowed_zones": [host], "allowed_record_types": ["A"]},
                                              "egress": [{"host": host, "port": port, "protocol": "tcp",
                                                          "allowed_methods": ["POST"], "allowed_paths": ["/v1/"]}]},
                      "model": {"host": host, "port": port, "scheme": "http"},
                      "credentials": [{"name": "model-main", "host": host, "port": port, "header": "authorization"}],
                      "limits": {"requests_per_minute": 100000, "bytes_in": 1 << 40, "bytes_out": 1 << 40}}
            private_json(directory / "policy", policy)
            private_json(directory / "boundary", {"test_destinations": {f"{host}:{port}": ["198.18.0.10"]}})
            private_json(directory / "credentials", {"model-main": fixture.secret})
            token = directory / "worker"
            token.write_text(fixture.worker)
            token.chmod(0o600)
            for index in range(args.samples):
                fixture.fence = {"lease_id": str(uuid.uuid4()), "generation": 1}
                sandbox, tenant = str(uuid.uuid4()), str(uuid.uuid4())
                config_path = directory / f"config-{index}"
                private_json(config_path, {"policy": str(directory / "policy"), "boundary": str(directory / "boundary"),
                                          "credentials": str(directory / "credentials"), "worker_token": str(token),
                                          "events": str(directory / f"events-{index}"), "sandbox_id": sandbox, "tenant_id": tenant,
                                          "fence": fixture.fence, "worker_node_id": fixture.node,
                                          "budget_url": f"http://127.0.0.1:{fixture.authority.server_port}"})
                command = [str(binary), str(config_path)]
                env = {key: value for key, value in os.environ.items() if "proxy" not in key.lower()}
                # Fix the runtime worker count rather than silently inheriting machine-wide defaults.
                env["TOKIO_WORKER_THREADS"] = "2"
                with (directory / "gateway.stderr").open("w") as error:
                    gateway = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=error, text=True, env=env)
                    try:
                        with selectors.DefaultSelector() as selector:
                            selector.register(gateway.stdout, selectors.EVENT_READ)
                            assert selector.select(timeout=30), "gateway readiness timeout"
                            line = gateway.stdout.readline()
                            if not line:
                                error.flush()
                                diagnostic = (directory / "gateway.stderr").read_text()
                                diagnostic = diagnostic.replace(fixture.secret, "[redacted]").replace(fixture.worker, "[redacted]")
                                raise RuntimeError(f"gateway failed before readiness: {diagnostic}")
                            ready = json.loads(line)
                        fixture.identity = {"sandbox_id": sandbox, "tenant_id": tenant, "policy_hash": ready["policy_hash"]}
                        startup = snapshot(gateway.pid)
                        direct = {"address": "198.18.0.10", "port": port, "path": "/v1/chat/completions", "authorization": "Bearer " + fixture.secret,
                                  "chunks": args.chunks, "requests": args.requests}
                        guarded = {**direct, "address": "127.0.0.1", "port": int(ready["broker"].rsplit(":", 1)[1]),
                                   "path": "/model/model-main/v1/chat/completions", "authorization": "Bearer placeholder://model-main"}
                        if index == 0:
                            before = fixture.counts()
                            refusals_before = fixture.authority_refusals
                            fixture.refuse = True
                            run_client({**guarded, "requests": 1, "status": 503})
                            fixture.refuse = False
                            assert fixture.counts() == before, "denied budget reached provider or committed"
                            assert fixture.authority_refusals == refusals_before + 1, "refusal control did not reach budget authority"
                            result["budget_refusal_positive_control"] = "authority HTTP 403 observed; gateway HTTP 503; provider and durable ledger unchanged"
                        for config in (direct, guarded):
                            run_client({**config, "requests": 2})
                        idle_before = snapshot(gateway.pid)
                        idle_start = time.monotonic()
                        time.sleep(1)
                        idle_after = snapshot(gateway.pid)
                        idle_wall = time.monotonic() - idle_start
                        pair = {"index": index, "startup_before_any_request": startup,
                                "idle": {"before": idle_before, "after": idle_after, "wall_seconds": idle_wall},
                                "order": ["direct", "guarded"] if index % 2 == 0 else ["guarded", "direct"]}
                        for side in pair["order"]:
                            before = snapshot(gateway.pid)
                            window_start = time.monotonic()
                            counts_before = fixture.counts()
                            value = run_client(direct if side == "direct" else guarded, gateway.pid)
                            after = snapshot(gateway.pid)
                            gateway_window = time.monotonic() - window_start
                            counts_after = fixture.counts()
                            assert counts_after["provider_requests"] - counts_before["provider_requests"] == args.requests
                            debit = [a - b for a, b in zip(counts_after["budget"], counts_before["budget"])]
                            if side == "guarded":
                                assert debit[0] == args.requests and debit[1] == value["response_bytes"] and debit[2] == args.requests * len(BODY), "durable debit mismatch"
                            else:
                                assert debit == [0, 0, 0, 0], "direct workload touched authority"
                            value.update({"gateway_before": before, "gateway_after": after,
                                          "gateway_window_seconds": gateway_window,
                                          "gateway_cpu_seconds": (after["cpu_ticks"] - before["cpu_ticks"]) / HZ,
                                          "durable_debit_delta": debit, "provider_requests": args.requests})
                            pair[side] = value
                        pair["guarded_cpu_minus_normalized_idle_seconds"] = pair["guarded"]["gateway_cpu_seconds"] - (idle_after["cpu_ticks"] - idle_before["cpu_ticks"]) / HZ / idle_wall * pair["guarded"]["gateway_window_seconds"]
                        pair["sampled_peak_rss_minus_idle_kib"] = pair["guarded"]["gateway_sampled_peak_rss_kib"] - idle_after["rss_kib"]
                        pair["sampled_peak_rss_minus_startup_kib"] = pair["guarded"]["gateway_sampled_peak_rss_kib"] - startup["rss_kib"]
                        result["samples"].append(pair)
                        print(f"pair {index + 1}/{args.samples}: verified {args.requests} requests per side", file=sys.stderr)
                    finally:
                        if gateway.poll() is None:
                            gateway.send_signal(signal.SIGINT)
                        try:
                            gateway.wait(timeout=20)
                        except subprocess.TimeoutExpired:
                            if gateway.poll() is None:
                                gateway.kill()
                            gateway.wait(timeout=5)
                            raise RuntimeError("gateway required forced cleanup")
                        gateway.stdout.close()
                        if sys.exc_info()[0] is None:
                            assert gateway.returncode == 0, "unexpected gateway exit"
        finally:
            fixture.close()
    pairs = result["samples"]
    result["measurement"]["tokio_worker_threads"] = 2
    result["summary"] = {side: {key: statistics.median(p[side][key] for p in pairs) for key in
                                ("gateway_cpu_seconds", "gateway_sampled_peak_rss_kib", "cpu_seconds", "wall_seconds", "peak_rss_kib")}
                         for side in ("direct", "guarded")}
    result["summary"].update({key: statistics.median(p[key] for p in pairs) for key in
                              ("guarded_cpu_minus_normalized_idle_seconds", "sampled_peak_rss_minus_idle_kib",
                               "sampled_peak_rss_minus_startup_kib")})
    result["summary"]["idle_gateway_rss_kib"] = statistics.median(p["idle"]["after"]["rss_kib"] for p in pairs)
    result["summary"]["startup_gateway_rss_kib"] = statistics.median(p["startup_before_any_request"]["rss_kib"] for p in pairs)
    assert all(p["guarded"]["gateway_cpu_seconds"] >= 5 / HZ for p in pairs), "workload CPU below five meter ticks; increase requests"
    encoded = json.dumps(result, indent=2) + "\n"
    assert fixture.secret not in encoded and fixture.worker not in encoded, "credential leaked in artifact"
    output = Path(args.output)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(encoded)
    temporary.replace(output)  # Failed runs never replace valid evidence.
    print(json.dumps(result["summary"], indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--meter-control", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--gateway", default="target/release/examples/guard_resource_gateway")
    parser.add_argument("--samples", type=int, default=7)
    parser.add_argument("--requests", type=int, default=64)
    parser.add_argument("--chunks", type=int, default=64)
    parser.add_argument("--output", default="benchmarks/guard-resource-benchmark.json")
    arguments = parser.parse_args()
    if arguments.client:
        client()
    elif arguments.meter_control:
        meter_control()
    else:
        assert arguments.samples >= 3 and arguments.requests > 0 and 0 < arguments.chunks <= 4096
        host_namespace = os.readlink("/proc/self/ns/net")
        if not arguments.inside:
            environment = dict(os.environ)
            environment["AIEC_GUARD_ACCEPTANCE_HOST_NETNS"] = host_namespace
            os.execvpe("unshare", ["unshare", "--user", "--map-root-user", "--net", "--fork", "--kill-child=KILL",
                                 sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], "--inside"], environment)
        assert host_namespace != os.environ["AIEC_GUARD_ACCEPTANCE_HOST_NETNS"], "refusing host network namespace"
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
        subprocess.run(["ip", "addr", "add", "198.18.0.10/32", "dev", "lo"], check=True)
        benchmark(arguments)
