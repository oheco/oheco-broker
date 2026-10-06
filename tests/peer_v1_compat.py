#!/usr/bin/env python3
"""Real native 0.3/v1 <-> 0.4/v2 CLI acceptance, using only private fixtures.

Run with --fixture, --new-binary and --old-binary. Both CLI versions must use
native SDKs; a Linux CI runner can supply an old build from the 0.3.0 checkout.
No production endpoint, user profile, external proxy, or transport shim is used.
The fixture must be the current tests/control-server (schema 2). Each direction
gets a fresh database/account. Failure logs are emitted with credentials removed;
all child processes, sockets and private temporary directories are cleaned.
"""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request


FRAME_SIZES = (0, 32769, 2 * 1024 * 1024)
UDP_SIZES = (0, 8, 1200, 1201, 8192, 65507)  # IPv4 maximum: fragmented QUIC DATAGRAMs.
BANNER = bytes(range(256)) * 16
TRAILER_PREFIX = b"peer-v1-compatible FIN "


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def receive_exact(connection, size):
    data = bytearray()
    while len(data) < size:
        block = connection.recv(min(65536, size - len(data)))
        require(block, f"TCP EOF after {len(data)}/{size} bytes")
        data.extend(block)
    return bytes(data)


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def native_artifact(path):
    """Recognize an installed package launcher without changing its environment."""
    path = Path(path).resolve()
    with path.open("rb") as source:
        header = source.read(64)
    if header.startswith(b"#!"):
        candidate = path.parent.parent / "libexec" / "oheco-broker"
        require(candidate.is_file(), "old CLI launcher lacks its native libexec executable")
        path = candidate
        with path.open("rb") as source:
            header = source.read(64)
    require(header[:4] == b"\x7fELF", f"{path.name} is not a native ELF executable")
    require(header[4] == 2 and header[5] == 1, "expected little-endian ELF64")
    machine = struct.unpack_from("<H", header, 18)[0]
    signed_ohos = False
    if platform.system() == "HarmonyOS":
        require(machine == 183, "HarmonyOS compatibility requires native aarch64 executables")
        section_offset = struct.unpack_from("<Q", header, 40)[0]
        section_size, section_count, names_index = struct.unpack_from("<HHH", header, 58)
        require(section_size >= 64 and names_index < section_count, "invalid native ELF section table")
        with path.open("rb") as source:
            source.seek(section_offset)
            sections = source.read(section_size * section_count)
            require(len(sections) == section_size * section_count, "truncated ELF section table")
            names_header = sections[names_index * section_size:(names_index + 1) * section_size]
            names_offset, names_size = struct.unpack_from("<QQ", names_header, 24)
            source.seek(names_offset)
            names = source.read(names_size)
        named_sections = {}
        for index in range(section_count):
            section = sections[index * section_size:(index + 1) * section_size]
            name_offset = struct.unpack_from("<I", section)[0]
            name = names[name_offset:].split(b"\0", 1)[0]
            named_sections[name] = struct.unpack_from("<Q", section, 32)[0]
        require(named_sections.get(b".codesign", 0) > 0 and named_sections.get(b".note.ohos.ident", 0) > 0,
                "HarmonyOS native CLI/fixture must contain code signature and OHOS identity sections")
        signed_ohos = True
    return {"path": str(path), "sha256": digest(path), "elf_machine": machine,
            "signed_ohos_elf": signed_ohos, "size": path.stat().st_size}


class Targets:
    """Count actual target accepts and bytes, including replies after caller FIN."""
    def __init__(self, timeout):
        self.timeout = timeout
        self.halt = threading.Event()
        self.lock = threading.Lock()
        self.connections = set()
        self.workers = []
        self.errors = []
        self.accepts = self.half_closes = self.tcp_rx = self.tcp_tx = 0
        self.udp_seen = []
        self.tcp = socket.socket()
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen()
        self.tcp.settimeout(.1)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.settimeout(.1)
        self.threads = [threading.Thread(target=self.tcp_loop, name="compat-tcp-target"),
                        threading.Thread(target=self.udp_loop, name="compat-udp-target")]
        for thread in self.threads:
            thread.start()

    def target(self, protocol):
        sock = self.tcp if protocol == "tcp" else self.udp
        return "127.0.0.1:" + str(sock.getsockname()[1])

    def tcp_loop(self):
        while not self.halt.is_set():
            try:
                connection, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.accepts += 1
                self.connections.add(connection)
            worker = threading.Thread(target=self.echo_frames, args=(connection,),
                                      name="compat-target-flow")
            self.workers.append(worker)
            worker.start()

    def echo_frames(self, connection):
        rx, tx = 0, 0
        try:
            with connection:
                connection.settimeout(self.timeout)
                connection.sendall(BANNER)
                tx += len(BANNER)
                checksum = hashlib.sha256()
                for expected_size in FRAME_SIZES:
                    header = receive_exact(connection, 4)
                    size = struct.unpack("!I", header)[0]
                    require(size == expected_size, f"target frame size {size} != {expected_size}")
                    payload = receive_exact(connection, size)
                    checksum.update(payload)
                    rx += 4 + len(payload)
                    connection.sendall(header + payload)
                    tx += 4 + len(payload)
                require(connection.recv(1) == b"", "target received unexpected bytes after frames")
                with self.lock:
                    self.half_closes += 1
                trailer = TRAILER_PREFIX + checksum.digest()
                connection.sendall(trailer)  # Only produced after the incoming FIN.
                tx += len(trailer)
                connection.shutdown(socket.SHUT_WR)
        except Exception as error:
            if not self.halt.is_set():
                with self.lock:
                    self.errors.append(str(error))
        finally:
            with self.lock:
                self.tcp_rx += rx
                self.tcp_tx += tx
                self.connections.discard(connection)

    def udp_loop(self):
        while not self.halt.is_set():
            try:
                payload, source = self.udp.recvfrom(65535)
                self.udp.sendto(payload, source)
                with self.lock:
                    self.udp_seen.append((len(payload), hashlib.sha256(payload).hexdigest()))
            except socket.timeout:
                continue
            except OSError:
                return

    def snapshot(self):
        with self.lock:
            return {"target_accepts": self.accepts, "target_half_closes": self.half_closes,
                    "tcp_target_rx": self.tcp_rx, "tcp_target_tx": self.tcp_tx,
                    "udp_target_datagrams": len(self.udp_seen),
                    "udp_target_bytes_each_direction": sum(size for size, _ in self.udp_seen),
                    "errors": list(self.errors)}

    def close(self):
        self.halt.set()
        self.tcp.close()
        self.udp.close()
        with self.lock:
            connections = list(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for thread in self.threads:
            thread.join(timeout=3)
        # The accept loop has stopped, so it cannot append a new worker here.
        for thread in self.workers:
            thread.join(timeout=3)
        require(not any(thread.is_alive() for thread in self.threads + self.workers),
                "target worker survived cleanup")


class Fixture:
    def __init__(self, root, args):
        self.root, self.args = root, args
        self.processes, self.outputs, self.logs = [], [], []
        self.observations = []
        self.secrets = [secrets.token_hex(32)]
        for name in ("temp", "config"):
            (root / name).mkdir(mode=0o700)
        self.env = dict(os.environ, TMPDIR=str(root / "temp"),
                        XDG_CONFIG_HOME=str(root / "config"),
                        OB_PEER_TEST_ADMIN_TOKEN=self.secrets[0],
                        OHECO_BROKER_ADMIN_TOKEN=self.secrets[0],
                        NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
        # Fixtures and native peers must not inherit fault injection or TLS key logs.
        for key in ("LD_PRELOAD", "SSLKEYLOGFILE", "QLOGDIR", "OB_UDP_FAULT_FILE",
                    "OB_API_TEST_ADMIN_TOKEN"):
            self.env.pop(key, None)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.db = root / "control.sqlite"
        self.account = root / "config" / "account.json"

    def redact(self, text):
        for secret in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(secret, "[credential-redacted]")
        # Also cover session/device tokens and PAKE/ICE proofs in diagnostics.
        text = re.sub(r'(?i)("(?:password|token|device_token|session_token|mac|resume_proof)"\s*:\s*)"[^"\n]*"',
                      r'\1"[credential-redacted]"', text)
        return re.sub(r"\b[0-9a-fA-F]{64,}\b", "[credential-redacted]", text)

    def start(self, command, label):
        path = self.root / (label + ".log")
        output = path.open("wb")
        self.outputs.append(output)
        self.logs.append(path)
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                   env=self.env, cwd=self.root, start_new_session=True)
        self.processes.append(process)
        return process, path

    def stop(self, process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                raise AssertionError("test process needed SIGKILL during graceful shutdown")
        require(process.returncode == 0, f"test child exited with {process.returncode}")

    def event(self, process, path, name):
        deadline = time.monotonic() + self.args.ready_timeout
        observe_at = time.monotonic() + 2
        while time.monotonic() < deadline:
            if time.monotonic() >= observe_at:
                self.observe(path.stem)
                observe_at = time.monotonic() + 2
            require(process.poll() is None, f"{path.stem} exited with {process.returncode} before {name}")
            for line in path.read_text(errors="replace").splitlines():
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if isinstance(value, dict) and value.get("event") == name:
                    return value
            time.sleep(.03)
        raise AssertionError(f"{path.stem}: timed out waiting for {name}")

    def boot(self):
        ready = self.root / "ready.json"
        process, _ = self.start([self.args.fixture, "--db", str(self.db), "--ready", str(ready)], "fixture")
        deadline = time.monotonic() + self.args.ready_timeout
        while not ready.exists():
            require(process.poll() is None, "fixture exited before readiness")
            require(time.monotonic() < deadline, "fixture readiness timeout")
            time.sleep(.03)
        information = json.loads(ready.read_text())
        self.url = information["api"]
        require(self.url.startswith("http://127.0.0.1:"), "fixture is not private loopback")
        with self.database() as database:
            require(database.execute("SELECT version FROM schema_version").fetchall() == [(2,)],
                    "compatibility fixture must run backend schema 2")
        return process

    def database(self):
        return closing(sqlite3.connect(self.db.as_uri() + "?mode=ro", uri=True, timeout=3))

    def cli(self, binary, parts):
        return [binary, "--api", self.url, "--config", str(self.account)] + parts

    def run(self, command, label):
        result = subprocess.run(command, stdin=subprocess.DEVNULL, env=self.env, cwd=self.root,
                                capture_output=True, text=True, timeout=self.args.ready_timeout)
        path = self.root / (label + ".log")
        path.write_text(result.stdout + result.stderr)
        self.logs.append(path)
        require(result.returncode == 0, f"{label} exited with {result.returncode}")
        return result.stdout

    def registration(self, binary):
        parts = ["tenant", "register"]
        if binary == self.args.new_binary:
            parts.append("--legacy-auth")
        result = json.loads(self.run(self.cli(binary, parts), "register"))
        stored = json.loads(self.account.read_text())
        require("token" not in result, "registration printed an account token")
        for field in ("password", "token"):
            self.secrets.append(stored["account"][field])
        require(not self.account.stat().st_mode & 0o077, "account profile is not private")
        require(not Path(str(self.account) + ".pending").exists(), "pending profile survived registration")

    def gates(self):
        request = urllib.request.Request(self.url + "/__test/gates",
                                         headers={"Authorization": "Bearer " + self.secrets[0]})
        with self.opener.open(request, timeout=3) as response:
            return json.load(response)

    def inspect_session(self, broker_id, new_is_broker):
        # Read only the test-owned SQLite state: no proxy or altered signaling.
        with self.database() as database:
            rows = database.execute("SELECT s.id,s.peer_authenticated,s.relay_approved,"
                                    "COALESCE(c.connection_id,''),COALESCE(c.generation,0) "
                                    "FROM sessions s LEFT JOIN connection_sessions c ON c.session_id=s.id "
                                    "WHERE s.broker_id=?", (broker_id,)).fetchall()
            require(len(rows) == 1, "expected exactly one live native session per mapping")
            sid, authenticated, relay, connection, generation = rows[0]
            require(authenticated == 1 and relay == 0, "native session lacks PAKE approval or used relay")
            require(bool(connection) == (not new_is_broker), "incorrect legacy/managed session metadata")
            require(generation == (0 if new_is_broker else 1), "unexpected transport generation")
            signals = database.execute("SELECT side,sequence,data FROM messages WHERE session_id=? "
                                       "ORDER BY side,sequence", (sid,)).fetchall()
        messages = {"broker": [], "client": []}
        ice = {}
        for side, sequence, raw in signals:
            envelope = json.loads(raw)
            require(envelope["v"] == 1 and envelope["sid"] == sid and envelope["seq"] == sequence,
                    "signal envelope binding/version mismatch")
            messages[side].append(envelope["t"])
            if envelope["t"] in ("confirm", "ice"):
                require(re.fullmatch("[0-9a-f]{64}", envelope.get("mac", "")),
                        "key confirmation or ICE envelope omitted its MAC")
            if envelope["t"] == "ice":
                ice[side] = json.loads(envelope["payload"])
        for side in messages:
            require(messages[side] == ["pake", "confirm", "ice"], "incomplete native PAKE/ICE transcript")
            require("a=candidate:" in ice[side].get("sdp", ""), "ICE omitted actual candidates")
        new_side = "broker" if new_is_broker else "client"
        old_side = "client" if new_is_broker else "broker"
        require(ice[new_side].get("mapping_version") == 2, "new peer did not advertise mapping v2")
        # Recovery proofs are bound to managed connection IDs. A 0.3 caller
        # creates a legacy session; the new broker must not invent a proof for it.
        if connection:
            require(re.fullmatch("[0-9a-f]{64}", ice[new_side].get("resume_proof", "")),
                    "new managed authenticated ICE omitted resume_proof")
        else:
            require("resume_proof" not in ice[new_side],
                    "new broker advertised a recovery proof for a legacy session")
        require("mapping_version" not in ice[old_side] and "resume_proof" not in ice[old_side],
                "old binary is not the baseline v1 peer")
        require(re.fullmatch("[0-9a-f]{64}", ice["broker"].get("cert_sha256", "")),
                "broker ICE omitted the pinned QUIC certificate fingerprint")
        return {"backend_schema": 2, "managed_metadata": bool(connection), "generation": generation,
                "native_pake_confirm_ice": True, "new_authenticated_ice_mapping_version": 2,
                "new_authenticated_ice_resume_proof": bool(connection), "old_ice_version_absent": True,
                "negotiated_mapping_version": 1, "pinned_quic_application_bytes": True}

    def observe(self, label):
        # A timed-out old CLI deletes its session. Preserve nonsecret setup
        # progress before that cleanup so missing broker/ICE messages are visible.
        try:
            with self.database() as database:
                sessions = database.execute("SELECT peer_authenticated,relay_approved FROM sessions").fetchall()
                signals = [(side, sequence, json.loads(raw).get("t")) for side, sequence, raw in
                           database.execute("SELECT side,sequence,data FROM messages ORDER BY side,sequence")]
                leases = database.execute("SELECT lease_expires_at FROM brokers").fetchall()
            self.observations.append({"waiting": label, "sessions": sessions, "signals": signals,
                                      "broker_leases": leases, "gates": self.gates()})
        except (sqlite3.Error, OSError, ValueError) as error:
            self.observations.append({"waiting": label, "inspection_error": self.redact(str(error))})
        self.observations = self.observations[-60:]

    def diagnostics(self, error):
        print("FAIL " + self.redact(str(error)), file=sys.stderr, flush=True)
        for path in self.logs:
            text = self.redact(path.read_text(errors="replace"))
            print(f"--- {path.name} (redacted, last 16000 characters) ---\n" + text[-16000:],
                  file=sys.stderr, flush=True)
        if self.observations:
            print("setup observations " + json.dumps(self.observations), file=sys.stderr, flush=True)
        if self.db.exists():
            try:
                with self.database() as database:
                    sessions = database.execute("SELECT peer_authenticated,relay_approved FROM sessions").fetchall()
                    signals = []
                    for side, sequence, raw in database.execute("SELECT side,sequence,data FROM messages ORDER BY side,sequence"):
                        envelope = json.loads(raw)
                        item = {"side": side, "sequence": sequence, "type": envelope.get("t"),
                                "mac_present": bool(envelope.get("mac"))}
                        if envelope.get("t") == "ice":
                            payload = json.loads(envelope["payload"])
                            item.update(ice_fields=sorted(payload), mapping_version=payload.get("mapping_version", 1))
                        signals.append(item)
                    print("fixture diagnostic " + json.dumps({"sessions": sessions, "signals": signals}),
                          file=sys.stderr, flush=True)
            except (sqlite3.Error, ValueError) as inspection_error:
                print("fixture inspection failed: " + self.redact(str(inspection_error)), file=sys.stderr)

    def close(self):
        failures = []
        for process in reversed(self.processes):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                    failures.append("cleanup needed SIGKILL")
                except ProcessLookupError:
                    process.wait(timeout=5)
            require(process.poll() is not None, "test-owned child survived cleanup")
        for output in self.outputs:
            output.close()
        require(not failures, "; ".join(failures))


def tcp_roundtrip(address, timeout):
    payloads = [secrets.token_bytes(size) for size in FRAME_SIZES]
    checksum = hashlib.sha256(b"".join(payloads)).digest()
    errors = []
    with socket.create_connection(address, timeout=timeout) as connection:
        connection.settimeout(timeout)
        require(receive_exact(connection, len(BANNER)) == BANNER, "unsolicited target banner corrupted")
        def reader():
            try:
                for payload in payloads:
                    require(receive_exact(connection, 4) == struct.pack("!I", len(payload)), "echo frame header corrupted")
                    require(receive_exact(connection, len(payload)) == payload, "TCP echo payload corrupted")
                expected = TRAILER_PREFIX + checksum
                require(receive_exact(connection, len(expected)) == expected, "post-FIN target reply corrupted")
                require(connection.recv(1) == b"", "target FIN missing or extra echo bytes received")
            except Exception as error:
                errors.append(str(error))
        thread = threading.Thread(target=reader, name="compat-caller-reader")
        thread.start()
        try:
            for payload in payloads:
                connection.sendall(struct.pack("!I", len(payload)) + payload)
            connection.shutdown(socket.SHUT_WR)
            thread.join(timeout=timeout)
            require(not thread.is_alive(), "framed TCP echo/half-close timed out")
            require(not errors, "; ".join(errors))
        finally:
            if thread.is_alive():
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                thread.join(timeout=3)
            require(not thread.is_alive(), "caller reader survived cleanup")
    tx = sum(4 + len(payload) for payload in payloads)
    return tx, tx + len(BANNER) + len(TRAILER_PREFIX) + len(checksum)


def scenario(args, directory, label, broker_binary, caller_binary, new_is_broker):
    root = Path(directory)
    fixture = Fixture(root, args)
    targets = Targets(args.io_timeout)
    started = time.monotonic()
    try:
        service = fixture.boot()
        fixture.registration(broker_binary)
        password = secrets.token_hex(16)
        fixture.secrets.append(password)
        name = "compat-" + secrets.token_hex(6)
        broker, broker_log = fixture.start(fixture.cli(broker_binary, ["tenant", "serve", "--name", name,
                           "--password", password, "--allow", "tcp@" + targets.target("tcp"),
                           "--allow", "udp@" + targets.target("udp")]), "broker")
        broker_id = fixture.event(broker, broker_log, "broker_ready")["broker_id"]
        transcripts = []
        expected_tx = expected_rx = 0
        for protocol in ("tcp", "udp"):
            caller, caller_log = fixture.start(fixture.cli(caller_binary, ["tenant", "connect", "--name", name,
                                "--password", password, "--protocol", protocol, "--target", targets.target(protocol),
                                "--local", "0", "--relay", "never"]), "caller-" + protocol)
            mapping = fixture.event(caller, caller_log, "mapping_ready")
            require(mapping["protocol"] == protocol and mapping["broker_id"] == broker_id,
                    "mapping readiness identified the wrong peer/protocol")
            require(mapping["target"] == targets.target(protocol) and mapping["relay_mode"] == "never",
                    "mapping readiness changed the target or relay policy")
            host, port = mapping["local"].rsplit(":", 1)
            require(host == "127.0.0.1" and int(port) > 0, "mapping did not bind private ephemeral loopback")
            address = (host, int(port))
            transcript = fixture.inspect_session(broker_id, new_is_broker)
            transcript["protocol"] = protocol
            transcripts.append(transcript)
            if protocol == "tcp":
                for _ in range(2):
                    tx, rx = tcp_roundtrip(address, args.io_timeout)
                    expected_tx += tx
                    expected_rx += rx
                deadline = time.monotonic() + args.io_timeout
                while targets.snapshot()["tcp_target_tx"] != expected_rx:
                    require(time.monotonic() < deadline, "target FIN/byte accounting timeout")
                    time.sleep(.02)
                snapshot = targets.snapshot()
                require(snapshot["target_accepts"] == 2 and snapshot["target_half_closes"] == 2,
                        "TCP mapping reopened/duplicated a target socket or lost a half-close")
                require(snapshot["tcp_target_rx"] == expected_tx and snapshot["tcp_target_tx"] == expected_rx,
                        "TCP target byte accounting mismatch")
            else:
                wanted = []
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                    connection.settimeout(args.io_timeout)
                    connection.connect(address)
                    for size in UDP_SIZES:
                        payload = secrets.token_bytes(size)
                        wanted.append((size, hashlib.sha256(payload).hexdigest()))
                        require(connection.send(payload) == size, "UDP send truncated")
                        require(connection.recv(65535) == payload, f"UDP {size}-byte datagram changed")
                    connection.settimeout(.2)
                    try:
                        connection.recv(65535)
                    except socket.timeout:
                        pass
                    else:
                        raise AssertionError("UDP mapping duplicated an application datagram")
                with targets.lock:
                    require(targets.udp_seen == wanted, "UDP target datagram count/content/order mismatch")
            require(broker.poll() is None and caller.poll() is None, "native peer exited during healthy forwarding")
            require(not targets.snapshot()["errors"], "target errors: " + repr(targets.snapshot()["errors"]))
            fixture.stop(caller)
        final_targets = targets.snapshot()
        require(final_targets["target_accepts"] == 2 and final_targets["target_half_closes"] == 2,
                "unexpected late target accept or missing half-close")
        require(final_targets["udp_target_datagrams"] == len(UDP_SIZES), "unexpected late UDP datagram")
        counters = fixture.gates()
        require(counters["ws_broker_upgrades"] >= 1 and counters["ws_session_upgrades"] >= 4
                and counters["ws_requests"] > 0, "actual native WebSocket signaling not observed")
        for key in ("http_signal_polls", "http_broker_polls", "http_heartbeats"):
            require(counters[key] == 0, "interop used REST signaling fallback: " + key)
        fixture.stop(broker)
        fixture.stop(service)
        result = {"direction": label, "elapsed_seconds": round(time.monotonic() - started, 3),
                  **targets.snapshot(), "tcp_caller_tx": expected_tx, "tcp_caller_rx": expected_rx,
                  "udp_max_datagram": max(UDP_SIZES), "transcripts": transcripts, "signaling": counters}
        print("PASS " + json.dumps(result, sort_keys=True), flush=True)
        return result
    except BaseException as error:
        fixture.diagnostics(error)
        raise
    finally:
        try:
            fixture.close()
        finally:
            targets.close()


def terminate(signum, _frame):
    raise SystemExit(128 + signum)


def bounded_timeout(value):
    number = float(value)
    if not 0 < number <= 120:
        raise argparse.ArgumentTypeError("timeout must be between 0 and 120 seconds")
    return number


def main():
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fixture", "new-binary", "old-binary"):
        parser.add_argument("--" + name, required=True, type=lambda value: str(Path(value).resolve()))
    parser.add_argument("--ready-timeout", default=40, type=bounded_timeout)
    parser.add_argument("--io-timeout", default=30, type=bounded_timeout)
    args = parser.parse_args()
    artifacts = {name: native_artifact(getattr(args, name)) for name in ("fixture", "new_binary", "old_binary")}
    invocations = {name: digest(getattr(args, name)) for name in artifacts}
    test_source_sha256 = digest(__file__)
    temp_base = os.environ.get("TMPDIR")
    require(temp_base or platform.system() != "HarmonyOS", "HarmonyOS requires private TMPDIR")
    with tempfile.TemporaryDirectory(prefix="broker-peer-v1-compat-", dir=temp_base) as directory:
        root = Path(directory)
        version_env = dict(os.environ, TMPDIR=str(root), XDG_CONFIG_HOME=str(root / "version-config"))
        version_env.pop("LD_PRELOAD", None)
        for binary, expected in ((args.old_binary, "0.3.0"), (args.new_binary, "0.5.0")):
            result = subprocess.run([binary, "--version"], env=version_env, cwd=root, stdin=subprocess.DEVNULL,
                                    capture_output=True, text=True, timeout=args.ready_timeout)
            require(result.returncode == 0 and result.stdout.strip() == "oheco-broker " + expected,
                    f"expected CLI version {expected}, got {result.returncode}: {result.stdout.strip()}")
        results = []
        for label, broker, caller, new_is_broker in (
                ("old-0.3-broker_new-0.5-caller", args.old_binary, args.new_binary, False),
                ("new-0.5-broker_old-0.3-caller", args.new_binary, args.old_binary, True)):
            scenario_root = root / label
            scenario_root.mkdir(mode=0o700)
            results.append(scenario(args, str(scenario_root), label, broker, caller, new_is_broker))
    for name, artifact in artifacts.items():
        require(digest(artifact["path"]) == artifact["sha256"] and
                digest(getattr(args, name)) == invocations[name], "native artifact or launcher changed during acceptance")
    require(digest(__file__) == test_source_sha256, "test source changed during acceptance")
    print("PASS " + json.dumps({"event": "peer_v1_compat_complete", "platform": platform.platform(),
          "native_signed_execution_on_harmonyos": platform.system() == "HarmonyOS",
          "old_version": "0.3.0", "new_version": "0.5.0", "artifacts": artifacts,
          "directions": len(results), "resources_cleaned": True,
          "test_source_sha256": test_source_sha256, "artifacts_unchanged": True,
          "scope": "healthy native v1 fallback; transport outage is a separate acceptance gate"},
          sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
