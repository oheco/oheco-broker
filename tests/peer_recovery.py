#!/usr/bin/env python3
"""Disposable native recovery acceptance; real UDP faults and public C API only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request

CONNECTED, RECONNECTING, RETRY_WAIT, PAUSED, FAILED = 1, 2, 3, 4, 5
HEADER = struct.Struct("!II")
FIN_ID = 0xFFFFFFFE
INTRO_ID = 0xFFFF0000
INTRO = bytes(range(256)) * 512


def exact(connection, size):
    data = bytearray()
    while len(data) < size:
        block = connection.recv(size - len(data))
        if not block:
            raise AssertionError(f"unexpected EOF at {len(data)}/{size} bytes")
        data.extend(block)
    return bytes(data)


def frame(connection):
    number, size = HEADER.unpack(exact(connection, HEADER.size))
    if size > 1024 * 1024:
        raise AssertionError(f"corrupt frame length {size}")
    return number, exact(connection, size)


def packet(number, payload):
    return HEADER.pack(number, len(payload)) + payload


class Driver:
    def __init__(self, command, env, root, label, redact):
        self.condition = threading.Condition()
        self.events = []
        self.event_times = []
        self.lines = []
        self.redact = redact
        self.stderr = (root / (label + ".stderr")).open("w+")
        self.process = subprocess.Popen(command, env=env, cwd=root, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=self.stderr,
                                        text=True, bufsize=1, start_new_session=True)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.process.stdout:
            with self.condition:
                self.lines.append(line.strip())
                try:
                    event = json.loads(line)
                except ValueError:
                    event = None
                if isinstance(event, dict):
                    self.events.append(event)
                    self.event_times.append(time.monotonic())
                self.condition.notify_all()
        with self.condition:
            self.condition.notify_all()

    def mark(self):
        with self.condition:
            return len(self.events)

    def observed_at(self, event):
        with self.condition:
            for index, item in enumerate(self.events):
                if item is event:
                    return self.event_times[index]
        raise AssertionError("event has no reader timestamp")

    def command(self, text):
        self.process.stdin.write(text + "\n")
        self.process.stdin.flush()

    def diagnostic(self):
        self.stderr.flush()
        self.stderr.seek(0)
        waits = {}
        try:
            for task in Path(f"/proc/{self.process.pid}/task").iterdir():
                try:
                    waits[task.name] = (task / "wchan").read_text().strip()
                except OSError:
                    pass
        except OSError:
            pass
        result = f"driver_pid={self.process.pid} thread_wchan={waits}\n" + "\n".join(self.lines[-40:]) + "\n" + self.stderr.read()
        for secret in self.redact:
            result = result.replace(secret, "[redacted]")
        return result

    def wait(self, predicate, after=0, timeout=45):
        end = time.monotonic() + timeout
        with self.condition:
            while True:
                for event in self.events[after:]:
                    if predicate(event):
                        return event
                if self.process.poll() is not None:
                    raise AssertionError("driver exited: " + self.diagnostic())
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise AssertionError("driver event timeout: " + self.diagnostic())
                self.condition.wait(min(remaining, .1))

    def state(self):
        mark = self.mark()
        self.command("state")
        return self.wait(lambda item: item.get("event") == "snapshot", mark, 3)

    def close(self, prompt=False):
        if self.process.poll() is None:
            mark = self.mark()
            self.command("close")
            closed = self.wait(lambda item: item.get("event") == "closed", mark, 6)
            if closed["result"] != 0 or prompt and closed["elapsed_ms"] > 2000:
                raise AssertionError("close was not prompt: " + str(closed))
            if self.process.wait(timeout=3) != 0:
                raise AssertionError(self.diagnostic())
        self.reader.join(timeout=2)

    def dispose(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.reader.join(timeout=2)
        self.process.stdin.close()
        self.process.stdout.close()
        self.stderr.close()


class TargetFlow:
    def __init__(self, connection):
        self.connection = connection
        self.lock = threading.Lock()
        self.half_closed = threading.Event()
        self.half_closed_at = None
        self.closed_at = None
        self.closed = threading.Event()
        self.received = []
        self.received_bytes = 0
        self.error = None

    def send(self, number, payload):
        with self.lock:
            self.connection.sendall(packet(number, payload))

    def work(self):
        try:
            self.send(INTRO_ID, INTRO)
            while True:
                header = self.connection.recv(HEADER.size)
                if not header:
                    self.half_closed_at = time.monotonic()
                    self.half_closed.set()
                    self.send(FIN_ID, b"target-fin")
                    self.connection.shutdown(socket.SHUT_WR)
                    break
                header += exact(self.connection, HEADER.size - len(header))
                number, size = HEADER.unpack(header)
                if size > 1024 * 1024:
                    raise AssertionError("target received corrupt frame size")
                payload = exact(self.connection, size)
                self.received.append((number, hashlib.sha256(payload).hexdigest()))
                self.received_bytes += len(payload)
                self.send(number, payload)
        except (OSError, AssertionError) as error:
            self.error = error
        finally:
            self.closed_at = time.monotonic()
            self.closed.set()
            self.connection.close()


class Targets:
    def __init__(self):
        self.halted = threading.Event()
        self.flows = []
        self.udp_received = []
        self.workers = []
        self.tcp = socket.socket()
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen(16)
        self.tcp.settimeout(.1)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.settimeout(.1)
        self.acceptor = threading.Thread(target=self._accept, daemon=True)
        self.datagrams = threading.Thread(target=self._udp, daemon=True)
        self.acceptor.start()
        self.datagrams.start()

    def _accept(self):
        while not self.halted.is_set():
            try:
                connection, _ = self.tcp.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            connection.settimeout(100)
            flow = TargetFlow(connection)
            self.flows.append(flow)
            worker = threading.Thread(target=flow.work, daemon=True)
            self.workers.append(worker)
            worker.start()

    def _udp(self):
        while not self.halted.is_set():
            try:
                payload, address = self.udp.recvfrom(65535)
                self.udp_received.append(payload)
                self.udp.sendto(payload, address)
            except TimeoutError:
                continue
            except OSError:
                return

    def ports(self):
        return [str(self.tcp.getsockname()[1]), str(self.udp.getsockname()[1])]

    def close(self):
        self.halted.set()
        self.tcp.close()
        self.udp.close()
        for flow in self.flows:
            try:
                flow.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.acceptor.join(timeout=2)
        self.datagrams.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--native", required=True)
    parser.add_argument("--preload", required=True)
    parser.add_argument("--case", choices=("all", "transfer", "quota", "grace", "idle", "revoke", "initial", "initial-udp", "close"), default="all")
    parser.add_argument("--relay", choices=("never", "force", "auto"), default="never")
    parser.add_argument("--debug-hold-seconds", type=int, default=0, choices=range(0, 61), help="Keep failed test processes alive briefly for local debugging")
    args = parser.parse_args()
    for key in ("fixture", "native", "preload"):
        setattr(args, key, str(Path(getattr(args, key)).resolve()))
    def terminated(signum, _frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminated)
    signal.signal(signal.SIGINT, terminated)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with tempfile.TemporaryDirectory(prefix="broker-peer-recovery-", dir=os.environ["TMPDIR"]) as directory:
        root = Path(directory)
        admin = secrets.token_hex(32)
        password = secrets.token_hex(32)
        redact = [admin, password]
        env = dict(os.environ, TMPDIR=str(root), OB_PEER_TEST_ADMIN_TOKEN=admin,
                   OB_RECOVERY_PEER_PASSWORD=password)
        flag = root / "udp-fault"
        client_env = dict(env, LD_PRELOAD=args.preload, OB_TEST_UDP_FAULT_FILE=str(flag))
        drivers, fixtures, fixture_outputs = [], [], []
        targets = Targets()
        ready = root / "ready.json"
        information = None
        fixture = None
        url = None

        def boot(previous=None):
            ready.unlink(missing_ok=True)
            command = [args.fixture, "--db", str(root / "control.sqlite"), "--ready", str(ready), "--broker-lease", "15s"]
            if previous:
                command += ["--listen", previous["api"].removeprefix("http://"), "--turn-listen", previous["turn"]]
            output = (root / ("fixture-" + str(len(fixtures)) + ".log")).open("w+")
            fixture_outputs.append(output)
            process = subprocess.Popen(command, env=env, cwd=root, stdout=output, stderr=output)
            fixtures.append(process)
            end = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    output.seek(0)
                    raise AssertionError("fixture exited: " + output.read())
                if ready.exists():
                    try:
                        info = json.loads(ready.read_text())
                    except (ValueError, OSError):
                        pass
                    else:
                        return process, info
                if time.monotonic() > end:
                    raise AssertionError("fixture readiness timeout")
                time.sleep(.02)

        def stop_fixture(process):
            process.terminate()
            try:
                process.wait(timeout=7)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
                raise AssertionError("fixture failed bounded shutdown")

        def api(method, path, body=None, token=None):
            raw = None if body is None else json.dumps(body).encode()
            request = urllib.request.Request(url + path, data=raw, method=method,
                headers={"Authorization": "Bearer " + (token or env["OB_RECOVERY_ACCOUNT_TOKEN"]),
                         "Content-Type": "application/json"})
            with opener.open(request, timeout=8) as response:
                return json.load(response)

        def new_driver(role, identity, label, special=None, relay=None):
            selected = dict(client_env if role == "connect" else env)
            if special:
                selected.update(special)
            driver = Driver([args.native, role, url, identity] + targets.ports() + [relay or args.relay], selected, root, label, redact)
            drivers.append(driver)
            return driver

        def peer(label, special=None, identity=None, relay=None):
            driver = new_driver("connect", identity or broker_id, label, special, relay)
            driver.wait(lambda item: item.get("event") == "peer_created", timeout=3)
            mapping = driver.wait(lambda item: item.get("event") == "maps", timeout=25)
            driver.wait(lambda item: item.get("event") in ("state", "snapshot") and item.get("state") == CONNECTED)
            return driver, mapping

        def same_maps(driver, original):
            mark = driver.mark()
            driver.command("state")
            mapping = driver.wait(lambda item: item.get("event") == "maps", mark, 3)
            if mapping != original:
                raise AssertionError("mapping handles/ports changed: " + str((original, mapping)))
            stats = driver.wait(lambda item: item.get("event") == "fault_stats", mark, 3)
            if not stats["active"]:
                raise AssertionError("native UDP fault interposition was absent")
            return stats

        def tcp_open(mapping):
            before = len(targets.flows)
            connection = socket.create_connection(("127.0.0.1", mapping["tcp_port"]), timeout=8)
            connection.settimeout(90)
            if frame(connection) != (INTRO_ID, INTRO):
                raise AssertionError("initial target frame corrupt")
            if len(targets.flows) != before + 1:
                raise AssertionError("unexpected accepted target count")
            return connection, targets.flows[-1], before

        def blackhole(mapping):
            flag.write_text("drop " + str(mapping["udp_port"]))

        def restore():
            flag.unlink(missing_ok=True)

        try:
            # The probe makes a platform unable to preload fail explicitly.
            probe = subprocess.run([args.native, "--fault-probe"], env=client_env,
                                   cwd=root, capture_output=True, text=True, timeout=5)
            if probe.returncode or not any(json.loads(line).get("active") for line in probe.stdout.splitlines() if line.startswith("{")):
                raise AssertionError("preload probe failed: " + probe.stdout + probe.stderr)
            fixture, information = boot()
            url = information["api"]
            api("PATCH", "/v1/admin/settings", {"registration_relay_enabled":True}, admin)
            registration = api("POST", "/v1/tenants/register", {"name":"recovery-fixture", "password":secrets.token_hex(32), "email":"recovery@example.invalid"}, admin)
            token = registration["token"]
            redact.append(token)
            env["OB_RECOVERY_ACCOUNT_TOKEN"] = token
            client_env["OB_RECOVERY_ACCOUNT_TOKEN"] = token
            server = new_driver("serve", "recovery-fixture", "server")
            broker_id = server.wait(lambda item: item.get("event") == "server_ready", timeout=10)["broker_id"]
            if server.state()["state"] != CONNECTED:
                server.wait(lambda item: item.get("event") in ("state", "snapshot") and item.get("state") == CONNECTED, timeout=15)

            def transfer(relay_mode):
                client, mapping = peer("transfer-" + relay_mode, relay=relay_mode)
                connection, flow, accepted_before = tcp_open(mapping)
                original_fd = connection.fileno()
                connection.sendall(packet(0, b"before-fault"))
                if frame(connection) != (0, b"before-fault"):
                    raise AssertionError("initial echo failed")
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp.connect(("127.0.0.1", mapping["udp_port"]))
                udp.settimeout(8)
                udp.send(b"udp-before")
                if udp.recv(65535) != b"udp-before":
                    raise AssertionError("initial UDP failed")
                before_state = client.state()
                # No application traffic for longer than the selected 3s idle
                # deadline: healthy QUIC PING must prevent false recovery.
                time.sleep(5)
                healthy = client.state()
                if healthy["state"] != CONNECTED or healthy["generation"] != before_state["generation"]:
                    raise AssertionError("healthy idle connection spuriously reconnected")
                mark = client.mark()
                transfer_started = time.monotonic()
                blackhole(mapping)
                expected = {}
                uploads, downloads = [], []
                for number in range(1, 65):
                    up = hashlib.sha256(b"up" + number.to_bytes(4, "big")).digest() * 2048
                    down = hashlib.sha256(b"down" + number.to_bytes(4, "big")).digest() * 2048
                    uploads.append((number, up)); downloads.append((1000 + number, down))
                    expected[number] = up; expected[1000 + number] = down
                failures = []
                progress = {"uploaded":0, "downloaded":0, "received":0}
                def send_uploads():
                    try:
                        for number, payload in uploads:
                            connection.sendall(packet(number, payload))
                            progress["uploaded"] += 1
                    except BaseException as error:
                        failures.append(error)
                def send_downloads():
                    try:
                        for number, payload in downloads:
                            flow.send(number, payload)
                            progress["downloaded"] += 1
                    except BaseException as error:
                        failures.append(error)
                def receive_frames():
                    try:
                        pending = dict(expected)
                        for _ in range(len(pending)):
                            number, payload = frame(connection)
                            if number not in pending or payload != pending.pop(number):
                                raise AssertionError(f"missing, duplicated or corrupt frame {number}")
                            progress["received"] += 1
                        if pending:
                            raise AssertionError("missing frames")
                    except BaseException as error:
                        failures.append(error)
                workers = [threading.Thread(target=action, daemon=True) for action in (send_uploads, send_downloads, receive_frames)]
                for worker in workers:
                    worker.start()
                first_disconnect = client.wait(lambda item: item.get("event") == "state" and item.get("state") in (RECONNECTING, RETRY_WAIT), mark, 45)
                restore()
                recovered = client.wait(lambda item: item.get("event") == "state" and item.get("state") == CONNECTED and item.get("generation", 0) > before_state["generation"], mark, 30)
                # TURN carries both the 4MiB independent download and the 4MiB
                # echo; observed relay windows advance about 100KiB/s. Bound the
                # entire transfer, rather than granting each worker a full budget.
                transfer_deadline = time.monotonic() + (150 if relay_mode == "force" else 70)
                for worker in workers:
                    worker.join(timeout=max(0, transfer_deadline - time.monotonic()))
                if any(worker.is_alive() for worker in workers) or failures:
                    print(json.dumps({"event":"transfer_incomplete", "relay":relay_mode, "elapsed_seconds":round(time.monotonic()-transfer_started,3), "progress":progress,
                        "workers":{worker.name:worker.is_alive() for worker in workers},
                        "client":client.state(), "server":server.state(), "target_received_bytes":flow.received_bytes}), flush=True)
                    raise AssertionError("bidirectional stream recovery failed: " + repr(failures))
                if connection.fileno() != original_fd or len(targets.flows) != accepted_before + 1:
                    raise AssertionError("recovery reopened an application/target TCP socket")
                stats = same_maps(client, mapping)
                if stats["sent"] == 0:
                    raise AssertionError("blackhole dropped no native UDP traffic")
                print(json.dumps({"event":"transfer_complete", "relay":relay_mode, "elapsed_seconds":round(time.monotonic()-transfer_started,3), "progress":progress}), flush=True)
                print(f"PASS relay={relay_mode} automatic UDP-blackhole recovery on SAME TCP fd/target socket; 4MiB each direction exact once; stable maps/ports", flush=True)

                before_second_fault = client.state()
                mark = client.mark()
                blackhole(mapping)
                second_disconnect = client.wait(lambda item: item.get("event") == "state" and item.get("state") in (RECONNECTING, RETRY_WAIT, PAUSED), mark, 45)
                paused = second_disconnect if second_disconnect["state"] == PAUSED else client.wait(lambda item: item.get("event") == "state" and item.get("state") == PAUSED, mark, 50)
                print(json.dumps({"event":"flow_stage", "phase":"paused_after_retry_exhaustion", "observed_at":time.monotonic(),
                    "target_closed_at":flow.closed_at, "target_half_closed_at":flow.half_closed_at,
                    "target_closed":flow.closed.is_set(), "target_half_closed":flow.half_closed.is_set()}), flush=True)
                # The driver configures max_attempts=2 and retry_budget_ms=12000;
                # setup_timeout_ms=8000 bounds each attempt. A flicker before the
                # 30s stable reset retains the original outage clock and attempts.
                budget_origin = first_disconnect if before_second_fault["attempts"] else second_disconnect
                budget_elapsed = client.observed_at(paused) - client.observed_at(budget_origin)
                if not 1 <= paused["attempts"] <= 2:
                    raise AssertionError("automatic retry attempt bound was not respected")
                if paused["attempts"] < 2 and budget_elapsed < 11.5:
                    raise AssertionError("automatic retries paused before both attempt and 12s budget limits")
                print(json.dumps({"event":"retry_exhaustion", "relay":relay_mode,
                    "attempts":paused["attempts"], "retained_attempts":before_second_fault["attempts"],
                    "budget_ms":12000, "budget_elapsed_seconds":round(budget_elapsed,3),
                    "reason":"attempt_limit" if paused["attempts"] == 2 else "time_budget"}), flush=True)
                stale = b"stale-" + secrets.token_bytes(32)
                for _ in range(20):
                    udp.send(stale)
                    time.sleep(.02)
                restore()
                mark = client.mark()
                client.command("burst 16")
                burst = client.wait(lambda item: item.get("event") == "burst", mark, 3)
                if burst["launched"] != 16 or burst["accepted"] != 16:
                    raise AssertionError("concurrent manual calls were rejected: " + str(burst))
                manual = client.wait(lambda item: item.get("event") == "state" and item.get("state") == CONNECTED, mark, 30)
                if manual["generation"] != paused["generation"] + 1:
                    raise AssertionError("manual calls created multiple transport generations")
                print(json.dumps({"event":"flow_stage", "phase":"manual_connected", "observed_at":time.monotonic(),
                    "target_closed_at":flow.closed_at, "target_half_closed_at":flow.half_closed_at,
                    "target_closed":flow.closed.is_set(), "target_half_closed":flow.half_closed.is_set()}), flush=True)
                for second in range(1, 6):
                    time.sleep(1)
                    print(json.dumps({"event":"manual_ready_baseline", "second":second,
                        "client":client.state(), "server":server.state(),
                        "target_closed":flow.closed.is_set(), "target_half_closed":flow.half_closed.is_set(),
                        "target_received_bytes":flow.received_bytes}), flush=True)
                same_maps(client, mapping)
                connection.sendall(packet(65, b"after-manual"))
                if frame(connection) != (65, b"after-manual") or len(targets.flows) != accepted_before + 1:
                    raise AssertionError("manual retry did not retain existing TCP flow")
                fresh = b"fresh-" + secrets.token_bytes(64000)
                udp.send(fresh)
                if udp.recv(65535) != fresh:
                    raise AssertionError("post-recovery UDP payload failed or stale datagram replayed")
                time.sleep(.25)
                if stale in targets.udp_received:
                    raise AssertionError("UDP datagram queued during outage replayed to target")
                connection.shutdown(socket.SHUT_WR)
                if frame(connection) != (FIN_ID, b"target-fin") or connection.recv(1) != b"":
                    raise AssertionError("TCP half-close/remote FIN was lost")
                if not flow.half_closed.wait(2):
                    raise AssertionError("target never received retained-flow FIN")
                expected_uploads = [(0, hashlib.sha256(b"before-fault").hexdigest())] + [(number, hashlib.sha256(payload).hexdigest()) for number, payload in uploads] + [(65, hashlib.sha256(b"after-manual").hexdigest())]
                if flow.received != expected_uploads:
                    raise AssertionError("target upload sequence/hash contained loss or duplication")
                connection.close(); udp.close(); client.close()
                print(f"PASS relay={relay_mode} exhausted auto retries +16 coalesced manual calls on SAME TCP fd; UDP stale drop/fresh64KiB; retained half-close", flush=True)

            if args.case in ("all", "transfer"):
                transfer(args.relay)
                if args.case == "all" and args.relay != "force":
                    transfer("force")

            if args.case in ("all", "quota"):
                loaded, mapping = peer("stream-quota")
                admitted = []
                first_target = len(targets.flows)
                for number in range(125):
                    connection = None
                    try:
                        connection, flow, _ = tcp_open(mapping)
                        local_fd = connection.fileno()
                        payload = (f"quota-{number:03d}:".encode() * 128)
                        connection.sendall(packet(1, payload))
                        if frame(connection) != (1, payload):
                            raise AssertionError("stream quota initial bytes mismatch")
                        admitted.append((connection, flow, local_fd, payload))
                    except (OSError, AssertionError):
                        if connection is not None:
                            connection.close()
                        if len(admitted) < 120:
                            raise
                        break
                if len(admitted) < 120:
                    raise AssertionError("default stream quota admitted fewer than 120 flows")
                accepted = len(targets.flows)
                prior = loaded.state();mark = loaded.mark();blackhole(mapping)
                loaded.wait(lambda item: item.get("event") == "state" and item.get("state") in (RECONNECTING, RETRY_WAIT), mark, 20)
                restore()
                loaded.wait(lambda item: item.get("event") == "state" and item.get("state") == CONNECTED and item["generation"] > prior["generation"], mark, 25)
                same_maps(loaded, mapping)
                for connection, flow, local_fd, payload in admitted:
                    if connection.fileno() != local_fd or flow.closed.is_set():
                        raise AssertionError("admitted quota flow closed during recovery")
                    connection.sendall(packet(2, payload))
                    if frame(connection) != (2, payload):
                        raise AssertionError("admitted quota flow failed exact byte recovery")
                if len(targets.flows) != accepted or accepted < first_target + len(admitted):
                    raise AssertionError("quota recovery accepted replacement target sockets")
                for connection, _, _, _ in admitted:
                    connection.close()
                loaded.close()
                print(f"PASS stream quota stress: {len(admitted)} admitted flows retain SAME TCP fds/target sockets and exact bytes; stable maps/ports", flush=True)

            if args.case in ("all", "grace"):
                short = {"OB_RECOVERY_FLOW_GRACE_MS":"5000", "OB_RECOVERY_TRANSPORT_TIMEOUT_MS":"1000"}
                grace_server = new_driver("serve", "grace-fixture", "grace-server", short)
                grace_id = grace_server.wait(lambda item: item.get("event") == "server_ready", timeout=10)["broker_id"]
                limited, mapping = peer("grace-peer", short, grace_id)
                old, flow, accepted_before = tcp_open(mapping)
                old_fd = old.fileno();old.sendall(packet(1, b"before-grace"))
                if frame(old) != (1, b"before-grace"):
                    raise AssertionError("grace initial echo failed")
                mark = limited.mark();blackhole(mapping)
                limited.wait(lambda item: item.get("event") == "state" and item.get("state") in (RECONNECTING, RETRY_WAIT), mark, 15)
                suspended_at = time.monotonic()
                for request in range(3):
                    if request:
                        time.sleep(1.3)
                    if flow.closed.is_set():
                        raise AssertionError("grace closed target before its original deadline")
                    manual_mark = limited.mark();limited.command("reconnect")
                    limited.wait(lambda item: item.get("event") == "manual" and item.get("result") == 0, manual_mark, 2)
                original_limit = suspended_at + 6.0  # 5s policy plus scheduler/notification tolerance.
                old.settimeout(max(.1, original_limit - time.monotonic()))
                try:
                    if old.recv(1) != b"":
                        raise AssertionError("grace-expired TCP continued forwarding")
                except (ConnectionResetError, BrokenPipeError):
                    pass
                if not flow.closed.wait(max(0, original_limit - time.monotonic())):
                    raise AssertionError("manual calls extended the original target flow grace deadline")
                if not suspended_at + 4.0 <= flow.closed_at <= original_limit:
                    raise AssertionError("target closed outside the original 5s grace deadline tolerance")
                paused = limited.wait(lambda item: item.get("event") == "state" and item.get("state") == PAUSED, mark, 40)
                same_maps(limited, mapping)
                restore();manual_mark = limited.mark();limited.command("reconnect")
                limited.wait(lambda item: item.get("event") == "manual" and item.get("result") == 0, manual_mark, 3)
                limited.wait(lambda item: item.get("event") == "state" and item.get("state") == CONNECTED and item["generation"] > paused["generation"], manual_mark, 25)
                same_maps(limited, mapping)
                if len(targets.flows) != accepted_before + 1 or not flow.closed.is_set() or old.fileno() != old_fd:
                    raise AssertionError("manual recovery resurrected an expired TCP flow")
                if old.recv(1) != b"":
                    raise AssertionError("old application socket revived after grace expiry")
                new, fresh_flow, _ = tcp_open(mapping)
                new.sendall(packet(1, b"new-after-grace"))
                if frame(new) != (1, b"new-after-grace") or len(targets.flows) != accepted_before + 2 or fresh_flow is flow:
                    raise AssertionError("explicit new TCP connection did not recover after grace expiry")
                old.close();new.close();limited.close();grace_server.close()
                print("PASS 5s flow grace expires both old sockets without extension by manual calls; stable maps manually recover only explicit new TCP", flush=True)

            if args.case in ("all", "idle"):
                default = {"OB_RECOVERY_TRANSPORT_TIMEOUT_MS":"0"}
                idle_server = new_driver("serve", "default-idle-fixture", "default-idle-server", default)
                idle_id = idle_server.wait(lambda item: item.get("event") == "server_ready", timeout=10)["broker_id"]
                idle_peer, mapping = peer("default-idle-peer", default, idle_id)
                connection, flow, accepted_before = tcp_open(mapping)
                descriptor = connection.fileno();before = idle_peer.state()
                time.sleep(19)
                after = idle_peer.state()
                if after["state"] != CONNECTED or after["generation"] != before["generation"] or flow.closed.is_set():
                    raise AssertionError("default 15s transport deadline spuriously recovered during 19s healthy idle")
                connection.sendall(packet(1, b"default-idle"))
                if frame(connection) != (1, b"default-idle") or connection.fileno() != descriptor or len(targets.flows) != accepted_before + 1:
                    raise AssertionError("default idle check replaced the original TCP socket")
                same_maps(idle_peer, mapping)
                connection.close();idle_peer.close();idle_server.close()
                print("PASS default 15s transport timeout stays healthy for 19s idle on same TCP fd/target and generation", flush=True)

            if args.case in ("all", "revoke"):
                client, mapping = peer("revoked")
                connection, flow, _ = tcp_open(mapping)
                records = api("GET", "/__test/connections?broker_id=" + broker_id, token=admin)["connections"]
                managed = [item for item in records if not item["revoked"]]
                if len(managed) != 1:
                    raise AssertionError("ambiguous managed test connection")
                api("DELETE", "/v1/connections/" + managed[0]["connection_id"])
                client.wait(lambda item: item.get("event") == "state" and item.get("state") == FAILED, timeout=8)
                connection.settimeout(3)
                try:
                    if connection.recv(1) != b"":
                        raise AssertionError("revoked forwarding remained active")
                except (ConnectionResetError, BrokenPipeError):
                    pass
                if not flow.closed.wait(3):
                    raise AssertionError("revocation retained the target socket")
                mark = client.mark();client.command("reconnect")
                client.wait(lambda item: item.get("event") == "manual", mark, 3)
                time.sleep(.5)
                records = api("GET", "/__test/connections?broker_id=" + broker_id, token=admin)["connections"]
                if client.state()["state"] != FAILED or any(not item["revoked"] for item in records):
                    raise AssertionError("manual retry resurrected an explicit revocation")
                connection.close();client.close()
                print("PASS explicit connection revocation closes both sockets and manual retry cannot resurrect forwarding", flush=True)

            if args.case in ("all", "initial"):
                stop_fixture(fixture)
                offline = new_driver("connect", broker_id, "initial-offline")
                created = offline.wait(lambda item: item.get("event") == "peer_created", timeout=3)
                if not created["handle"]:
                    raise AssertionError("initial async failure returned no live handle")
                offline.wait(lambda item: item.get("event") == "state" and item.get("state") == PAUSED, timeout=30)
                fixture, restarted = boot(information)
                if restarted != information:
                    raise AssertionError("control restart changed public endpoints")
                mark = server.mark();server.command("reconnect")
                server.wait(lambda item: item.get("event") == "manual", mark, 3)
                if server.state()["state"] != CONNECTED:
                    server.wait(lambda item: item.get("event") in ("state", "snapshot") and item.get("state") == CONNECTED, mark, 20)
                mark = offline.mark();offline.command("reconnect")
                offline.wait(lambda item: item.get("event") == "manual" and item.get("result") == 0, mark, 3)
                mapping = offline.wait(lambda item: item.get("event") == "maps", mark, 25)
                connection, _, _ = tcp_open(mapping)
                connection.sendall(packet(1, b"initial-manual"))
                if frame(connection) != (1, b"initial-manual"):
                    raise AssertionError("initial-offline manual retry did not forward")
                connection.close();offline.close()
                print("PASS initial asynchronous offline handle retries manually after same-UUID/backend restart", flush=True)

            if args.case in ("all", "initial-udp"):
                flag.write_text("drop")
                initial_udp = new_driver("connect", broker_id, "initial-udp-offline")
                initial_udp.wait(lambda item: item.get("event") == "peer_created", timeout=3)
                initial_udp.wait(lambda item: item.get("event") == "state" and item.get("state") == PAUSED, timeout=35)
                restore()
                mark = initial_udp.mark();initial_udp.command("reconnect")
                initial_udp.wait(lambda item: item.get("event") == "manual" and item.get("result") == 0, mark, 3)
                mapping = initial_udp.wait(lambda item: item.get("event") == "maps", mark, 25)
                connection, _, _ = tcp_open(mapping)
                connection.sendall(packet(1, b"initial-udp-manual"))
                if frame(connection) != (1, b"initial-udp-manual"):
                    raise AssertionError("initial UDP failure did not recover manually")
                connection.close();initial_udp.close()
                print("PASS initial asynchronous UDP blackhole exhausts cleanly and same handle manually recovers", flush=True)

            if args.case in ("all", "close"):
                closing, mapping = peer("close-backoff", {"OB_RECOVERY_RETRY_DELAY_MS":"5000"})
                mark = closing.mark()
                blackhole(mapping)
                closing.wait(lambda item: item.get("event") == "state" and item.get("state") == RETRY_WAIT, mark, 30)
                closing.close(prompt=True)
                restore()
                print("PASS explicit close interrupts retry backoff within 2 seconds", flush=True)
            server.close()
        except BaseException:
            for driver in drivers:
                print(driver.diagnostic(), flush=True)
            for number, flow in enumerate(targets.flows):
                print(f"target_flow={number} closed={flow.closed.is_set()} half_closed={flow.half_closed.is_set()} received_frames={len(flow.received)} received_bytes={flow.received_bytes} error={flow.error!r}", flush=True)
            if args.debug_hold_seconds:
                print(f"DEBUG holding test-owned processes for {args.debug_hold_seconds}s before cleanup", flush=True)
                time.sleep(args.debug_hold_seconds)
            raise
        finally:
            restore()
            for driver in reversed(drivers):
                driver.dispose()
            for process in reversed(fixtures):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=7)
                    except subprocess.TimeoutExpired:
                        process.kill();process.wait(timeout=3)
            targets.close()
            for output in fixture_outputs:
                output.close()
    print("PASS isolated native recovery acceptance; all test-owned processes, sockets and private artifacts cleaned", flush=True)


if __name__ == "__main__":
    main()
