#!/usr/bin/env python3
"""Real WS reconnect/lease/close/outage tests with isolated fault injection."""
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
    parser.add_argument("--fixture", required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument("--binary", required=True, type=lambda p: str(Path(p).resolve()))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="broker-peer-lifecycle-", dir=os.environ["TMPDIR"]) as directory:
        root = Path(directory)
        (root / "temp").mkdir(mode=0o700)
        admin = secrets.token_hex(32)
        env = dict(os.environ, TMPDIR=str(root / "temp"), XDG_CONFIG_HOME=str(root / "config"),
                   OB_PEER_TEST_ADMIN_TOKEN=admin, OHECO_BROKER_ADMIN_TOKEN=admin)
        processes, outputs = [], []
        ready_file = root / "ready.json"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        echo = socket.socket()
        echo.bind(("127.0.0.1", 0))
        echo.listen()
        echo.settimeout(.2)
        halted = threading.Event()
        closed_events, echo_workers = [], []
        def echo_connection(connection, done):
            try:
                with connection:
                    connection.settimeout(180)
                    while True:
                        data = connection.recv(65536)
                        if not data:
                            return
                        connection.sendall(data)
            finally:
                done.set()
        def echo_loop():
            while not halted.is_set():
                try:
                    connection, _ = echo.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                done = threading.Event()
                closed_events.append(done)
                worker = threading.Thread(target=echo_connection, args=(connection, done))
                worker.start()
                echo_workers.append(worker)
        echo_thread = threading.Thread(target=echo_loop)
        echo_thread.start()
        def start(command, label):
            path = root / (label + ".log")
            output = path.open("wb")
            outputs.append(output)
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                       env=env, cwd=root, start_new_session=True)
            processes.append(process)
            return process, path
        def stop(process, timeout=20):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    raise AssertionError("test-owned process did not finish close")
        def wait_event(process, path, name, timeout=35):
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                if process.poll() is not None:
                    raise AssertionError(path.read_text())
                for line in path.read_text().splitlines():
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue
                    if item.get("event") == name:
                        return item
                time.sleep(.02)
            raise AssertionError("event timeout: " + path.read_text())
        def wait_state(process, path, state, timeout=80):
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                if process.poll() is not None:
                    raise AssertionError("CLI terminated before recovery state: " + path.read_text())
                for line in path.read_text().splitlines():
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if item.get("event") == "connection_state" and item.get("state") == state:
                        return item
                time.sleep(.05)
            raise AssertionError("CLI recovery state timeout: " + path.read_text())
        def boot(listen=None, turn=None):
            ready_file.unlink(missing_ok=True)
            command = [args.fixture, "--db", str(root / "control.sqlite"), "--ready", str(ready_file),
                       "--broker-lease", "5s"]
            if listen:
                command += ["--listen", listen, "--turn-listen", turn]
            process, log = start(command, "fixture-" + str(len(processes)))
            end = time.monotonic() + 10
            while not ready_file.exists():
                if process.poll() is not None:
                    raise AssertionError(log.read_text())
                if time.monotonic() > end:
                    raise AssertionError("fixture readiness timeout")
                time.sleep(.02)
            return process, json.loads(ready_file.read_text())
        def cli(parts, success=True):
            result = subprocess.run([args.binary, "--api", url] + parts, env=env, cwd=root,
                                    capture_output=True, text=True, timeout=20)
            if success != (result.returncode == 0):
                raise AssertionError("CLI lifecycle control failed: " + result.stderr.replace(admin, "[redacted]"))
            return json.loads(result.stdout) if success and result.stdout.strip() else None
        def gate(body=None):
            raw = None if body is None else json.dumps(body).encode()
            request = urllib.request.Request(url + "/__test/gates", data=raw,
                       headers={"Authorization": "Bearer " + admin, "Content-Type": "application/json"},
                       method="GET" if body is None else "POST")
            with opener.open(request, timeout=3) as response:
                return json.load(response)
        def wait_gate(key):
            end = time.monotonic() + 5
            while time.monotonic() < end:
                if gate()[key] > 0:
                    return
                time.sleep(.03)
            raise AssertionError("native WS heartbeat RPC did not enter the stall gate")
        def connect(label):
            before = len(closed_events)
            process, log = start([args.binary, "--api", url, "tenant", "connect", "--name", "lifecycle",
                        "--password", password, "--protocol", "tcp", "--target", target,
                        "--local", "0", "--relay", "never", "--state-events"], label)
            mapping = wait_event(process, log, "mapping_ready")
            host, port = mapping["local"].rsplit(":", 1)
            connection = socket.create_connection((host, int(port)), timeout=8)
            connection.settimeout(8)
            connection.sendall(b"live")
            if connection.recv(4) != b"live":
                raise AssertionError("mapping did not echo before fault injection")
            if len(closed_events) != before + 1:
                raise AssertionError("unexpected target socket count")
            return process, connection, closed_events[-1]
        def eof(connection, deadline):
            connection.settimeout(deadline)
            try:
                if connection.recv(1) != b"":
                    raise AssertionError("unexpected bytes instead of close")
            except (ConnectionResetError, BrokenPipeError):
                pass
        try:
            fixture, information = boot()
            url = information["api"]
            cli(["tenant", "register"])
            password = secrets.token_hex(16)
            target = "127.0.0.1:" + str(echo.getsockname()[1])
            broker, broker_log = start([args.binary, "--api", url, "tenant", "serve", "--name", "lifecycle",
                         "--password", password, "--allow", "tcp@" + target, "--state-events"], "broker")
            broker_id = wait_event(broker, broker_log, "broker_ready")["broker_id"]
            mapping_process, connection, target_closed = connect("lease-mapping")
            before_reconnect = gate()
            dropped = gate({"drop_ws": True})
            if dropped["ws_disconnects"] < before_reconnect["ws_disconnects"] + 3:
                raise AssertionError("fault gate did not drop watcher and both session WebSockets")
            end = time.monotonic() + 4
            while time.monotonic() < end:
                counters = gate()
                if target_closed.is_set():
                    raise AssertionError("transient WS loss closed existing target before lease expiry")
                if counters["ws_broker_upgrades"] > before_reconnect["ws_broker_upgrades"] and counters["ws_session_upgrades"] >= before_reconnect["ws_session_upgrades"] + 2:
                    break
                time.sleep(.03)
            else:
                raise AssertionError("native watcher/session WS reconnects were not observed")
            connection.sendall(b"after-ws-reconnect")
            answer = bytearray()
            while len(answer) < len(b"after-ws-reconnect"):
                block = connection.recv(64)
                if not block: break
                answer.extend(block)
            if bytes(answer) != b"after-ws-reconnect":
                raise AssertionError("existing QUIC TCP flow failed after WS cursor reconnect")
            if any(counters[name] for name in ("http_signal_polls", "http_broker_polls", "http_heartbeats")):
                raise AssertionError("WS reconnect silently used continuous REST fallback")
            print("PASS native watcher/session WS reconnect with live QUIC flow; zero REST fallback", flush=True)
            gate({"sessions": True})
            wait_gate("sessions_waiting")
            # Let the old lease expire. Fresh managed grants may authorize new
            # transports; an authorized logical TCP flow keeps its target fd.
            time.sleep(7)
            if target_closed.is_set() or mapping_process.poll() is not None:
                raise AssertionError("managed recovery closed an established TCP flow during a heartbeat stall")
            gate({"sessions": False})
            connection.settimeout(30)
            connection.sendall(b"after-heartbeat-stall")
            answer = bytearray()
            while len(answer) < len(b"after-heartbeat-stall"):
                block = connection.recv(64)
                if not block:
                    raise AssertionError("retained TCP closed after heartbeat recovery")
                answer.extend(block)
            if bytes(answer) != b"after-heartbeat-stall" or target_closed.is_set():
                raise AssertionError("heartbeat recovery lost TCP data or replaced target socket")
            connection.close()
            stop(mapping_process)
            if broker.poll() is not None:
                raise AssertionError("broker stopped instead of remaining available after peer lease loss")
            print("PASS stalled WS heartbeat recovers authorized transport and preserves existing TCP socket", flush=True)

            mapping_process, connection, target_closed = connect("close-mapping")
            gate({"broker": True})
            wait_gate("broker_waiting")
            started = time.monotonic()
            broker.send_signal(signal.SIGTERM)
            if not target_closed.wait(timeout=2) or time.monotonic() - started > 2:
                raise AssertionError("explicit broker close waited for stalled control before stopping target I/O")
            eof(connection, 7)
            connection.close()
            gate({"broker": False})
            stop(broker)
            stop(mapping_process)
            print("PASS explicit broker close stops target I/O during blocked WS heartbeat and bounded close", flush=True)

            broker, broker_log = start([args.binary, "--api", url, "tenant", "serve", "--name", "lifecycle",
                         "--password", password, "--allow", "tcp@" + target, "--state-events"], "recovering-broker")
            if wait_event(broker, broker_log, "broker_ready")["broker_id"] != broker_id:
                raise AssertionError("broker UUID changed on restore")
            mapping_process, connection, target_closed = connect("outage-mapping")
            mapping_log = root / "outage-mapping.log"
            target_count = len(closed_events)
            stop(fixture)
            # Both real CLI processes exhaust the automatic recovery budget.
            wait_state(mapping_process, mapping_log, "paused")
            wait_state(broker, broker_log, "paused")
            if target_closed.is_set() or len(closed_events) != target_count:
                raise AssertionError("control outage closed or reopened the retained target socket")
            if broker.poll() is not None or mapping_process.poll() is not None:
                raise AssertionError("CLI exited during an automatically paused connection")
            listen = information["api"].removeprefix("http://")
            fixture, restarted = boot(listen, information["turn"])
            if restarted["api"] != url:
                raise AssertionError("restart endpoint changed")
            broker.send_signal(signal.SIGUSR1)
            mapping_process.send_signal(signal.SIGUSR1)
            if not wait_event(broker, broker_log, "reconnect_requested")["accepted"]:
                raise AssertionError("broker SIGUSR1 manual request rejected")
            if not wait_event(mapping_process, mapping_log, "reconnect_requested")["accepted"]:
                raise AssertionError("peer SIGUSR1 manual request rejected")
            end = time.monotonic() + 25
            while time.monotonic() < end:
                status = cli(["tenant", "broker", "show", broker_id])["broker"]
                if status["online"]:
                    break
                time.sleep(.2)
            else:
                raise AssertionError("broker did not recover the same device identity after control restart")
            connection.settimeout(30)
            connection.sendall(b"same-socket-after-sigusr1")
            answer = bytearray()
            while len(answer) < len(b"same-socket-after-sigusr1"):
                block = connection.recv(64)
                if not block:
                    raise AssertionError("SIGUSR1 manual recovery closed the old application TCP fd")
                answer.extend(block)
            if bytes(answer) != b"same-socket-after-sigusr1" or len(closed_events) != target_count or target_closed.is_set():
                raise AssertionError("SIGUSR1 did not recover the same application/target sockets")
            connection.close()
            stop(mapping_process)
            stop(broker)
            stop(fixture)
            print("PASS real CLI exhausted budgets, then SIGUSR1 restores same UUID/handles/TCP sockets after SQLite restart", flush=True)
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            halted.set()
            echo.close()
            echo_thread.join(timeout=5)
            for worker in echo_workers:
                worker.join(timeout=25)
            for output in outputs:
                output.close()
    print("PASS isolated native peer lifecycle acceptance; test-owned resources cleaned", flush=True)

if __name__ == "__main__":
    main()
