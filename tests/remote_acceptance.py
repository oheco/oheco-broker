#!/usr/bin/env python3
"""Isolated local acceptance: real control/SQLite/Pion TURN/C SDK/Go CLI."""
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request


def terminate(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--native", required=True)
    parser.add_argument("--api-test", required=True)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    for name in ("fixture", "native", "api_test", "binary"):
        setattr(args, name, str(Path(getattr(args, name)).resolve()))
    with tempfile.TemporaryDirectory(prefix="broker-remote-acceptance-", dir=os.environ["TMPDIR"]) as directory:
        root = Path(directory)
        temp = root / "temp"
        temp.mkdir(mode=0o700)
        config = root / "config"
        config.mkdir(mode=0o700)
        admin = secrets.token_hex(32)
        env = dict(os.environ, TMPDIR=str(temp), XDG_CONFIG_HOME=str(config),
                   OB_PEER_TEST_ADMIN_TOKEN=admin, OB_API_TEST_ADMIN_TOKEN=admin,
                   OHECO_BROKER_ADMIN_TOKEN=admin)
        processes, logs = [], []
        def start(command, label):
            output = (root / (label + ".log")).open("wb")
            logs.append(output)
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=output, env=env, cwd=root, start_new_session=True)
            processes.append(process)
            return process, root / (label + ".log")
        def stop(process):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    raise AssertionError("test-owned process failed graceful shutdown")
        def run(command, label, timeout=150, input_text=None):
            try:
                result = subprocess.run(command, env=env, cwd=root, capture_output=True,
                                        text=True, input=input_text, timeout=timeout)
            except subprocess.TimeoutExpired as error:
                def partial_text(value):
                    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
                details = (partial_text(error.stdout) + partial_text(error.stderr)).replace(admin, "[admin-redacted]")
                (root / (label + ".log")).write_text(details)
                raise AssertionError(f"{label} exceeded {timeout}s: " + details) from error
            (root / (label + ".log")).write_text(result.stdout + result.stderr)
            if result.returncode:
                # Redact test secrets in diagnostics; local artifacts are cleaned.
                raise AssertionError(f"{label} failed({result.returncode}): " +
                                     (result.stdout + result.stderr).replace(admin, "[admin-redacted]"))
            print(f"PASS {label}", flush=True)
            return result.stdout
        def event(process, path, event_name, timeout=40):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError(f"{event_name} exited{process.returncode}: {path.read_text()}")
                for line in path.read_text().splitlines():
                    try:
                        value = json.loads(line)
                    except ValueError:
                        continue
                    if value.get("event") == event_name:
                        return value
                time.sleep(.03)
            raise AssertionError(f"timeout waiting for {event_name}: {path.read_text()}")
        echo_stop = threading.Event()
        tcp = socket.socket()
        tcp.bind(("127.0.0.1", 0))
        tcp.listen()
        tcp.settimeout(.2)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(.2)
        workers = []
        def handle(connection):
            with connection:
                connection.settimeout(5)
                while True:
                    data = connection.recv(32768)
                    if not data:
                        break
                    connection.sendall(data)
        def tcp_echo():
            while not echo_stop.is_set():
                try:
                    connection, _ = tcp.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                worker = threading.Thread(target=handle, args=(connection,))
                worker.start()
                workers.append(worker)
        def udp_echo():
            while not echo_stop.is_set():
                try:
                    data, source = udp.recvfrom(65535)
                    udp.sendto(data, source)
                except socket.timeout:
                    continue
                except OSError:
                    break
        threads = [threading.Thread(target=tcp_echo), threading.Thread(target=udp_echo)]
        for thread in threads:
            thread.start()
        try:
            ready = root / "ready.json"
            fixture, fixture_log = start([args.fixture, "--db", str(root / "control.sqlite"),
                                          "--ready", str(ready)], "fixture")
            deadline = time.monotonic() + 20
            while not ready.exists():
                if fixture.poll() is not None:
                    raise AssertionError(fixture_log.read_text())
                if time.monotonic() >= deadline:
                    raise AssertionError("fixture startup timeout")
                time.sleep(.03)
            url = json.loads(ready.read_text())["api"]
            run([args.api_test, "--control", url], "C tenant API against real SQLite control")
            def signaling_counters():
                request = urllib.request.Request(url + "/__test/gates", headers={"Authorization": "Bearer " + admin})
                with urllib.request.urlopen(request, timeout=5) as response:
                    return json.load(response)
            before_ws = signaling_counters()
            run([args.native, url], "C authenticated direct TCP UDP mapping")
            # This case deliberately spends 100 seconds idle. A normal release
            # run took 141.744s, leaving only 8s under the generic 150s limit.
            # Keep socket/UDP deadlines and assertions; allow setup and teardown
            # their own bounded headroom outside that intentional idle period.
            run([args.native, url, "--force", "--idle"], "C authenticated actual Pion TURN idle and TCP UDP mapping", timeout=210)
            account_path = config / "oheco-broker" / "account.json"
            base = [args.binary, "--api", url]
            registered = json.loads(run(base + ["tenant", "register", "--email", "local@example.invalid"], "CLI account registration"))
            tenant_id = registered["tenant"]["id"]
            saved = json.loads(account_path.read_text())
            if len(saved["account"]["password"]) != 32 or account_path.stat().st_mode & 0o077:
                raise AssertionError("generated credentials or private storage invalid")
            if "token" in registered:
                raise AssertionError("CLI printed an account secret")
            run(base + ["admin", "tenant", "relay", "enable", tenant_id], "CLI administrator relay permission")
            peer_password = secrets.token_hex(16)
            broker, broker_log = start(base + ["tenant", "serve", "--name", "cli-test",
                       "--password", peer_password,
                       "--allow", f"tcp@127.0.0.1:{tcp.getsockname()[1]}",
                       "--allow", f"udp@127.0.0.1:{udp.getsockname()[1]}"], "broker")
            broker_ready = event(broker, broker_log, "broker_ready")
            for protocol, target_port in (("tcp", tcp.getsockname()[1]), ("udp", udp.getsockname()[1])):
                connector, mapping_log = start(base + ["tenant", "connect", "--name", "cli-test",
                        "--password", peer_password, "--protocol", protocol,
                        "--target", f"127.0.0.1:{target_port}", "--local", "0", "--relay", "force"], "mapping-" + protocol)
                mapping = event(connector, mapping_log, "mapping_ready")
                host, port = mapping["local"].rsplit(":", 1)
                if protocol == "tcp":
                    payload = bytes(range(256)) * 4096
                    with socket.create_connection((host, int(port)), timeout=10) as client:
                        client.settimeout(15)
                        received = bytearray()
                        def read_all():
                            while True:
                                data = client.recv(32768)
                                if not data:
                                    return
                                received.extend(data)
                        reader = threading.Thread(target=read_all)
                        reader.start()
                        client.sendall(payload)
                        client.shutdown(socket.SHUT_WR)
                        reader.join(timeout=20)
                        if reader.is_alive() or bytes(received) != payload:
                            raise AssertionError("Go/cgo TCP mapping corrupted bytes or FIN")
                else:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                        client.settimeout(10)
                        for payload in (b"", b"udp-echo", secrets.token_bytes(65507)):
                            client.sendto(payload, (host, int(port)))
                            response, _ = client.recvfrom(65535)
                            if response != payload:
                                raise AssertionError("Go/cgo UDP datagram mismatch")
                stop(connector)
                if connector.returncode != 0:
                    raise AssertionError(mapping_log.read_text())
                print("PASS Go/cgo CLI " + protocol + " actual relay", flush=True)
            usage = json.loads(run(base + ["tenant", "usage", "--broker", broker_ready["broker_id"]], "CLI real relay usage"))
            # Exact schema is documented by the control API; reject a zero lifetime.
            if not any(isinstance(v, (int, float)) and v > 0 for k, v in usage.items() if "lifetime" in k or "total" in k):
                # Some responses nest windows; inspect numbers within the lifetime entry.
                lifetime = usage.get("windows", {}).get("lifetime", usage.get("lifetime", 0))
                if isinstance(lifetime, dict):
                    lifetime = lifetime.get("bytes", 0)
                if not isinstance(lifetime, (int, float)) or lifetime <= 0:
                    raise AssertionError("broker usage omitted actual relay bytes: " + json.dumps(usage))
            stop(broker)
            after_ws = signaling_counters()
            for name in ("http_signal_polls", "http_broker_polls", "http_heartbeats"):
                if after_ws[name] != before_ws[name]:
                    raise AssertionError("native signaling still used continuous REST: " + name)
            for name in ("ws_broker_upgrades", "ws_session_upgrades", "ws_requests"):
                if after_ws[name] <= before_ws[name]:
                    raise AssertionError("no actual WebSocket signaling observed: " + name)
            print("PASS actual WS broker/session push and lease RPCs; zero continuous REST polls/heartbeats", flush=True)
            stop(fixture)
            print("PASS local end-to-end acceptance; no Cloudflare or external network required", flush=True)
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            echo_stop.set()
            tcp.close()
            udp.close()
            for thread in threads + workers:
                thread.join(timeout=10)
            for output in logs:
                output.close()

if __name__ == "__main__":
    main()
