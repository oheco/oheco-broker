#!/usr/bin/env python3
"""Native CLI refresh acceptance against a disposable local SQLite/Pion fixture.

Requires signed native --cli and --fixture binaries. No production endpoints,
existing account profiles, external proxy configuration, or installed credentials
are used. All account/peer secrets are freshly generated inside one private temp
root, checked for output leakage, and removed with the test's own processes.

Fixture gate contract: POST /__test/gates accepts drop_refresh_replies (count)
and hold_refresh_replies (bool, AFTER commit); GET exposes refresh_dropped,
refresh_waiting, refresh_requests, http_account_requests and auth login/register
counters. Neither gate belongs in a production server.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
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
import urllib.error
import urllib.parse
import urllib.request


ACCESS_TTL = 3.0
REFRESH_TTL = 20.0
SECRET_KEYS = {"token", "access_token", "refresh_token", "next_token", "next_access_token",
               "next_refresh_token", "device_token", "session_token", "password", "credential"}
CASES = ("transport", "idle", "offline", "concurrent", "lost-response", "restart",
         "predecessor-expiry", "persistence", "revocation")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def until(predicate, message, timeout=15):
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(message)
        time.sleep(.025)


def epoch(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def secret_field(value):
    if isinstance(value, dict):
        return any((key in SECRET_KEYS and isinstance(item, str) and bool(item)) or secret_field(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(secret_field(item) for item in value)
    return False


def exact(connection, length):
    data = bytearray()
    while len(data) < length:
        part = connection.recv(length - len(data))
        if not part:
            raise AssertionError("mapped TCP socket reached unexpected EOF")
        data.extend(part)
    return bytes(data)


class Secrets:
    def __init__(self):
        self.values = set()
        self.lock = threading.Lock()

    def new(self):
        value = secrets.token_hex(32)
        with self.lock:
            self.values.add(value)
        return value

    def learn(self, value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in SECRET_KEYS and isinstance(item, str) and item:
                    with self.lock:
                        self.values.add(item)
                else:
                    self.learn(item)
        elif isinstance(value, list):
            for item in value:
                self.learn(item)

    def safe(self, message):
        with self.lock:
            for value in self.values:
                message = message.replace(value, "[redacted]")
        # Unknown candidate/device/session secrets from a failing new binary
        # must not leak through diagnostics before a profile taught us the value.
        return re.sub(r"(?i)\b[0-9a-f]{64}\b", "[redacted-hex]", message)

    def check(self, output):
        with self.lock:
            require(not any(value in output for value in self.values), "a generated test secret appeared in process output")


class Process:
    """Own exactly one subprocess group; retain private output until cleanup."""
    def __init__(self, command, env, root, label, vault, stdin=None):
        self.label, self.vault = label, vault
        self.condition = threading.Condition()
        self.events, self.output = [], []
        self.exposed_secret_field = False
        self.process = subprocess.Popen(command, env=env, cwd=root, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, bufsize=1, start_new_session=True)
        self.readers = [threading.Thread(target=self._read, args=(stream,), daemon=True)
                        for stream in (self.process.stdout, self.process.stderr)]
        for reader in self.readers:
            reader.start()
        try:
            if stdin is not None:
                self.process.stdin.write(stdin)
                self.process.stdin.flush()
        finally:
            self.process.stdin.close()

    def _read(self, stream):
        for line in stream:
            with self.condition:
                self.output.append(line)
                try:
                    event = json.loads(line)
                except ValueError:
                    event = None
                if isinstance(event, dict):
                    if secret_field(event):
                        self.exposed_secret_field = True
                        self.vault.learn(event)
                    self.events.append(event)
                self.condition.notify_all()
        with self.condition:
            self.condition.notify_all()

    def text(self):
        with self.condition:
            return "".join(self.output)

    def alive(self):
        require(self.process.poll() is None, self.label + " exited during a live peer test: " + self.vault.safe(self.text()))

    def event(self, name, timeout=35):
        def observed():
            with self.condition:
                for event in self.events:
                    if event.get("event") == name:
                        return event
            self.alive()
            return None
        return until(observed, self.label + " readiness timeout", timeout)

    def finish(self, success=True, timeout=20):
        try:
            status = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.close(kill=True)
            raise AssertionError(self.label + " exceeded its bounded command timeout")
        for reader in self.readers:
            reader.join(timeout=2)
        require(not self.exposed_secret_field, "native output included a secret JSON field")
        self.vault.check(self.text())
        if success is not None:
            require((status == 0) == success, self.label + " unexpected exit " + str(status) + ": " + self.vault.safe(self.text()))
        return status

    def close(self, kill=False):
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL if kill else signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=7)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
        for reader in self.readers:
            reader.join(timeout=2)
        for stream in (self.process.stdout, self.process.stderr):
            stream.close()


class EchoTargets:
    def __init__(self):
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.accepted = 0
        self.connections, self.workers = [], []
        self.tcp = socket.socket()
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen(16)
        self.tcp.settimeout(.1)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.settimeout(.1)
        self.workers = [threading.Thread(target=self._accept, daemon=True), threading.Thread(target=self._datagrams, daemon=True)]
        for worker in self.workers:
            worker.start()

    def _accept(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            connection.settimeout(.1)
            with self.lock:
                self.accepted += 1
                self.connections.append(connection)
                worker = threading.Thread(target=self._echo, args=(connection,), daemon=True)
                self.workers.append(worker)
            worker.start()

    def _echo(self, connection):
        try:
            while not self.stop.is_set():
                try:
                    block = connection.recv(65536)
                except socket.timeout:
                    continue
                if not block:
                    return
                connection.sendall(block)
        except OSError:
            pass
        finally:
            connection.close()

    def _datagrams(self):
        while not self.stop.is_set():
            try:
                block, address = self.udp.recvfrom(65536)
                self.udp.sendto(block, address)
            except socket.timeout:
                continue
            except OSError:
                return

    def port(self, protocol):
        return (self.tcp if protocol == "tcp" else self.udp).getsockname()[1]

    def close(self):
        self.stop.set()
        self.tcp.close()
        self.udp.close()
        with self.lock:
            connections, workers = list(self.connections), list(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for worker in workers:
            worker.join(timeout=2)


def owned_socket_fds(process):
    """Observe only test-owned descriptors; HarmonyOS denies global proc tables."""
    owned = {}
    directory = Path("/proc") / str(process.process.pid) / "fd"
    require(directory.is_dir(), "native acceptance needs owned proc descriptor inspection")
    for descriptor in directory.iterdir():
        try:
            target = os.readlink(descriptor)
        except OSError:
            continue
        if target.startswith("socket:["):
            owned[descriptor.name] = target[8:-1]
    return owned


def stable_socket_fds(processes, profile):
    # Briefly acquire the ORIGINAL profile lock after readiness/real echo. Every
    # refresh RPC owns that same lock from prepare through completion, so this
    # snapshot includes ALL map/control/transport sockets and excludes transient
    # account curl sockets. Never discard a listener because it changed during a
    # warmup interval: such a change must be caught by subsequent comparisons.
    path = Path(str(profile) + ".lock")
    require(path.is_file() and not path.is_symlink() and path.stat().st_mode & 0o077 == 0,
            "test profile lock must be a private ordinary file")
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    def locked():
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            return False
    try:
        until(locked, "test could not coordinate a native socket snapshot", 5)
        for process in processes:
            process.alive()
        stable = [owned_socket_fds(process) for process in processes]
        require(all(len(group) >= 2 for group in stable), "native map/control sockets were not observed")
        return stable
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def same_socket_fds(processes, originals):
    for process, original in zip(processes, originals):
        current = owned_socket_fds(process)
        require(all(current.get(fd) == inode for fd, inode in original.items()),
                "credential refresh closed/replaced a stable native socket or map listener")


class Acceptance:
    def __init__(self, cli, fixture, root, vault):
        self.cli, self.root, self.vault = cli, root, vault
        self.fixture_binary = fixture
        self.children, self.report = [], {}
        self.admin = vault.new()
        self.env = dict(os.environ, TMPDIR=str(root), XDG_CONFIG_HOME=str(root / "xdg"),
                        OB_PEER_TEST_ADMIN_TOKEN=self.admin, OHECO_BROKER_ADMIN_TOKEN=self.admin)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.db = root / "database" / "control.sqlite"
        self.db.parent.mkdir(mode=0o700)
        self.ready = root / "ready.json"
        self.fixture = self.start([fixture, "--db", str(self.db), "--ready", str(self.ready),
                                   "--broker-lease", "15s", "--account-token-ttl", "3s",
                                   "--auth-refresh-ttl", "20s", "--auth-access-overlap", "1s"], "fixture")
        def ready():
            self.fixture.alive()
            if not self.ready.exists():
                return None
            try:
                return json.loads(self.ready.read_text())
            except ValueError:
                return None
        information = until(ready, "fixture readiness timeout")
        self.api = information["api"]
        parsed = urllib.parse.urlsplit(self.api)
        require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port and
                not parsed.username and not parsed.password and parsed.path in ("", "/"),
                "acceptance refuses every endpoint except its own HTTP IPv4 loopback fixture")
        require(information["turn"].startswith("127.0.0.1:"), "acceptance TURN must be loopback")
        require(self.http("GET", "/v1/status")[1].get("account_refresh_protocol") == "refresh-v1", "fixture does not advertise refresh-v1")
        self.http("PATCH", "/v1/admin/settings", {"registration_relay_enabled": True}, self.admin)

    def start(self, command, label, stdin=None, env=None):
        child = Process(command, self.env if env is None else env, self.root, label, self.vault, stdin)
        self.children.append(child)
        return child

    def command(self, profile, parts, label, stdin=None, success=True):
        child = self.start([self.cli, "--api", self.api, "--config", str(profile)] + parts, label, stdin)
        child.finish(success=success)
        return child

    def http(self, method, path, body=None, token=None, expected=200):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.api + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=5) as response:
                status, raw = response.status, response.read()
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read()
        require(status == expected, "fixture " + method + " " + path + " returned HTTP " + str(status))
        return status, json.loads(raw) if raw else {}

    def gates(self, body=None):
        return self.http("POST" if body is not None else "GET", "/__test/gates", body, self.admin)[1]

    def register(self, label):
        directory = self.root / label
        directory.mkdir(mode=0o700)
        profile = directory / "account.json"
        password = self.vault.new()
        self.command(profile, ["tenant", "register", "--name", "refresh-" + label,
                               "--email", label + "@example.invalid", "--password-stdin"], label + "-register", password + "\n")
        saved = self.profile(profile)
        require(saved["auth"]["generation"] == 1, "a fresh login session must start at generation1")
        return profile

    def profile(self, profile):
        require(not profile.is_symlink() and profile.is_file() and profile.stat().st_mode & 0o077 == 0,
                "test account profile must be a private ordinary file")
        saved = json.loads(profile.read_text())
        self.vault.learn(saved)
        require(saved.get("version") == 2 and isinstance(saved.get("auth"), dict), "CLI must persist a version2 refresh profile")
        require(not saved["account"].get("password"), "version2 profile must not persist the account password")
        require(len(saved["account"]["token"]) == 64 and len(saved["auth"]["refresh_token"]) == 64,
                "profile access/refresh secret length is invalid")
        require(saved["account"]["token"] != saved["auth"]["refresh_token"], "access and refresh proofs must be distinct")
        return saved

    def query(self, statement, values=()):
        with sqlite3.connect("file:" + str(self.db) + "?mode=ro", uri=True, timeout=2) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(statement, values)]

    def authority(self, saved):
        rows = self.query("SELECT id,tenant_id,generation,token_expires_at,refresh_expires_at,revoked_reason,request_id,next_token_hash,next_refresh_hash FROM auth_sessions WHERE id=?", (saved["auth"]["auth_session_id"],))
        require(len(rows) == 1, "expected exactly one stable login authority")
        return rows[0]

    def connections(self, broker):
        return self.query("SELECT id,generation,current_session_id,revoked_reason,auth_session_id FROM connections WHERE broker_id=? ORDER BY id", (broker,))

    def wait_access_expiry(self, saved):
        expiry = epoch(saved["auth"]["token_expires_at"])
        until(lambda: time.time() > expiry + .15, "test access deadline did not expire", ACCESS_TTL + 3)
        require(time.time() < epoch(saved["auth"]["refresh_expires_at"]), "refresh proof expired before offline recovery")

    def serve(self, profile, targets, label):
        password = self.vault.new()
        parts = ["tenant", "serve", "--name", label, "--password-stdin", "--state-events",
                 "--allow", "tcp@127.0.0.1:" + str(targets.port("tcp")),
                 "--allow", "udp@127.0.0.1:" + str(targets.port("udp"))]
        child = self.start([self.cli, "--api", self.api, "--config", str(profile)] + parts, label + "-broker", password + "\n")
        broker = child.event("broker_ready")["broker_id"]
        return child, broker, password

    def connect(self, profile, broker, password, targets, protocol, label):
        parts = ["tenant", "connect", "--broker-id", broker, "--password-stdin", "--state-events",
                 "--protocol", protocol, "--target", "127.0.0.1:" + str(targets.port(protocol)),
                 "--local", "127.0.0.1:0", "--relay", "force"]
        child = self.start([self.cli, "--api", self.api, "--config", str(profile)] + parts, label, password + "\n")
        event = child.event("mapping_ready")
        require(event["relay_mode"] == "force" and event["protocol"] == protocol, "CLI mapping did not honor forced relay/protocol")
        host, port = event["local"].rsplit(":", 1)
        require(host == "127.0.0.1" and 0 < int(port) < 65536, "mapping must expose an assigned IPv4 loopback port")
        return child, int(port)

    def transport(self, duration):
        profile = self.register("transport")
        targets = EchoTargets()
        tcp = udp = None
        peers = []
        try:
            server, broker, password = self.serve(profile, targets, "refresh-transport")
            peers.append(server)
            tcp_peer, tcp_port = self.connect(profile, broker, password, targets, "tcp", "refresh-tcp")
            peers.append(tcp_peer)
            udp_peer, udp_port = self.connect(profile, broker, password, targets, "udp", "refresh-udp")
            peers.append(udp_peer)
            tcp = socket.create_connection(("127.0.0.1", tcp_port), timeout=8)
            tcp.settimeout(5)
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.connect(("127.0.0.1", udp_port))
            udp.settimeout(5)
            tcp.sendall(b"warmup")
            require(exact(tcp, 6) == b"warmup", "initial mapped TCP echo failed")
            until(lambda: targets.accepted == 1, "target TCP accept was not observed")
            original = self.profile(profile)
            rows = self.connections(broker)
            require(len(rows) == 2 and all(not row["revoked_reason"] for row in rows), "TCP+UDP peers need two live logical connections")
            sid = original["auth"]["auth_session_id"]
            require(all(row["auth_session_id"] == sid for row in rows), "connections were not bound to the shared stable authority")
            originals = {row["id"]: (row["generation"], row["current_session_id"]) for row in rows}
            inodes = stable_socket_fds((tcp_peer, udp_peer), profile)
            descriptors = (tcp.fileno(), udp.fileno())
            started, sequence = time.monotonic(), 0
            while time.monotonic() - started < duration:
                for peer in peers:
                    peer.alive()
                same_socket_fds((tcp_peer, udp_peer), inodes)
                payload = struct.pack("!I", sequence) + bytes(range(256))
                tcp.sendall(payload)
                require(exact(tcp, len(payload)) == payload, "same TCP socket payload changed across refresh")
                udp.send(payload)
                require(udp.recv(65536) == payload, "UDP payload changed across refresh")
                saved = self.profile(profile)
                require(saved["auth"]["auth_session_id"] == sid, "refresh changed stable login authority")
                require(not saved["account"].get("password"), "refresh restored a stored password")
                sequence += 1
                time.sleep(.15)
            final = self.profile(profile)
            authority = self.authority(final)
            require(final["auth"]["generation"] >= original["auth"]["generation"] + 3, "live native processes did not perform at least three automatic refreshes")
            require(authority["generation"] == final["auth"]["generation"], "shared profile and server authority generations disagree")
            require((tcp.fileno(), udp.fileno()) == descriptors and targets.accepted == 1, "refresh replaced a persistent mapped or target TCP socket")
            same_socket_fds((tcp_peer, udp_peer), inodes)
            current = self.connections(broker)
            require({row["id"]: (row["generation"], row["current_session_id"]) for row in current} == originals,
                    "credential refresh recreated a peer transport/logical generation")
            require(all(not row["revoked_reason"] for row in current), "routine refresh revoked a connection")
            relayed = self.query("SELECT COALESCE(SUM(bytes),0) AS bytes FROM usage_daily WHERE tenant_id=?", (final["account"]["id"],))[0]["bytes"]
            require(relayed > 0, "forced-relay native transfer produced no real TURN usage")
            for child in (tcp_peer, udp_peer):
                require(sum(event.get("event") == "mapping_ready" for event in child.events) == 1, "refresh recreated a CLI mapping")
            self.report["transport"] = {"passed": True, "seconds": round(time.monotonic() - started, 3),
                "credential_rotations": final["auth"]["generation"] - original["auth"]["generation"],
                "tcp_frames": sequence, "udp_frames": sequence, "target_tcp_accepts": targets.accepted,
                "same_source_socket": True, "same_target_socket": True, "same_listener_inodes": True,
                "same_logical_ids_and_generations": True, "relay": "force", "actual_turn_bytes": relayed}
        finally:
            for connection in (tcp, udp):
                if connection is not None:
                    connection.close()
            for child in reversed(peers):
                child.close()
            targets.close()

    def idle(self, duration):
        profile = self.register("idle")
        targets = EchoTargets()
        server = None
        try:
            server, broker, _ = self.serve(profile, targets, "refresh-idle")
            def connected():
                server.alive()
                with server.condition:
                    return any(event.get("event") == "connection_state" and event.get("state") == "connected"
                               for event in server.events)
            until(connected, "idle broker did not establish its control connection", 20)
            initial = self.profile(profile)
            gates_before = self.gates()
            require("http_account_requests" in gates_before,
                    "fixture must expose http_account_requests to prove independent proactive refresh")
            started = time.monotonic()
            while time.monotonic() - started < duration:
                server.alive()
                self.profile(profile)
                time.sleep(.1)
            final = self.profile(profile)
            require(targets.accepted == 0, "idle test accidentally opened a target TCP flow")
            require(final["auth"]["auth_session_id"] == initial["auth"]["auth_session_id"], "idle refresh changed login session")
            require(final["auth"]["generation"] >= initial["auth"]["generation"] + 3, "device-only idle runtime did not proactively refresh account authority")
            authority = self.authority(final)
            require(authority["refresh_expires_at"] > time.time() * 1000 and not authority["revoked_reason"], "healthy idle authority expired or was revoked")
            require(self.query("SELECT COUNT(*) AS count FROM brokers WHERE id=?", (broker,))[0]["count"] == 1, "idle refresh recreated broker")
            gates_after = self.gates()
            require(gates_after["http_account_requests"] == gates_before["http_account_requests"],
                    "idle runtime performed account RPCs instead of proving the independent refresh timer")
            require(gates_after["refresh_requests"] >= gates_before["refresh_requests"] + 3,
                    "idle credential generation advanced without three real refresh RPCs")
            self.report["idle"] = {"passed": True, "seconds": round(time.monotonic() - started, 3),
                "credential_rotations": final["auth"]["generation"] - initial["auth"]["generation"],
                "account_api_calls_during_idle": 0, "target_tcp_accepts": 0}
        finally:
            if server is not None:
                server.close()
            targets.close()

    def offline(self):
        profile = self.register("offline")
        before = self.profile(profile)
        self.wait_access_expiry(before)
        require(self.profile(profile)["auth"]["generation"] == before["auth"]["generation"], "offline phase had an unexpected active auth manager")
        self.command(profile, ["tenant", "account", "show"], "offline-recovery")
        after = self.profile(profile)
        require(after["auth"]["auth_session_id"] == before["auth"]["auth_session_id"] and
                after["auth"]["generation"] == before["auth"]["generation"] + 1,
                "new CLI could not recover expired access with the live refresh proof")
        require(epoch(after["auth"]["token_expires_at"]) > time.time(), "offline recovery returned expired access")
        self.report["offline"] = {"passed": True, "same_authority": True, "rotations": 1}

    def concurrent(self):
        profile = self.register("concurrent")
        before = self.profile(profile)
        self.wait_access_expiry(before)
        children = []
        started = time.monotonic()
        try:
            for index in range(6):
                children.append(self.start([self.cli, "--api", self.api, "--config", str(profile),
                                           "tenant", "account", "show"], "concurrent-" + str(index)))
            for child in children:
                child.finish()
            final = self.profile(profile)
            require(final["auth"]["auth_session_id"] == before["auth"]["auth_session_id"], "simultaneous CLI operations changed login authority")
            require(final["auth"]["generation"] == before["auth"]["generation"] + 1,
                    "simultaneous readers did not coordinate one expired-access refresh")
            count = self.query("SELECT COUNT(*) AS count FROM auth_sessions WHERE tenant_id=?", (before["account"]["id"],))[0]["count"]
            require(count == 1, "shared profile concurrency minted additional login sessions")
            self.report["concurrent"] = {"passed": True, "processes": len(children), "rotations": 1,
                                          "seconds": round(time.monotonic() - started, 3)}
        finally:
            for child in children:
                child.close()

    def lost_response(self):
        profile = self.register("lost-response")
        before = self.profile(profile)
        gates = self.gates()
        require("refresh_dropped" in gates, "fixture must expose refresh_dropped for deterministic loss acceptance")
        self.gates({"drop_refresh_replies": 1})
        first = self.command(profile, ["tenant", "refresh"], "lost-response-attempt", success=None)
        if Path(str(profile) + ".refresh-pending").exists():
            pending = json.loads(Path(str(profile) + ".refresh-pending").read_text())
            self.vault.learn(pending)
        self.command(profile, ["tenant", "account", "show"], "lost-response-recovery")
        after = self.profile(profile)
        require(self.gates()["refresh_dropped"] == gates["refresh_dropped"] + 1, "no post-commit refresh response was actually dropped")
        require(after["auth"]["auth_session_id"] == before["auth"]["auth_session_id"] and
                after["auth"]["generation"] == before["auth"]["generation"] + 1,
                "lost-reply recovery was not exactly one credential commit")
        require(not Path(str(profile) + ".refresh-pending").exists(), "confirmed refresh did not remove its pending journal")
        self.report["lost-response"] = {"passed": True, "first_exit": first.process.returncode,
                                        "dropped_committed_replies": 1, "rotations": 1}

    def restart(self):
        profile = self.register("restart")
        before = self.profile(profile)
        gates = self.gates()
        require("refresh_waiting" in gates, "fixture must expose post-commit refresh_waiting")
        self.gates({"hold_refresh_replies": True})
        child = self.start([self.cli, "--api", self.api, "--config", str(profile), "tenant", "refresh"], "restart-interrupted")
        pending_path = Path(str(profile) + ".refresh-pending")
        try:
            until(lambda: self.gates()["refresh_waiting"] > 0 and
                  self.authority(before)["generation"] == before["auth"]["generation"] + 1 and pending_path.exists(),
                  "fixture did not stall after a journaled credential commit", 10)
            pending = json.loads(pending_path.read_text())
            self.vault.learn(pending)
            candidate = pending["pending"]
            committed = self.authority(before)
            require(committed["request_id"] == candidate["request_id"] and
                    committed["next_token_hash"] == hashlib.sha256(candidate["next_token"].encode()).hexdigest() and
                    committed["next_refresh_hash"] == hashlib.sha256(candidate["next_refresh_token"].encode()).hexdigest(),
                    "pending candidate does not prove the real committed request")
            require(self.profile(profile)["auth"]["generation"] == before["auth"]["generation"], "held reply was already committed to profile")
            child.close(kill=True)
        finally:
            self.gates({"hold_refresh_replies": False})
            child.close()
        # Make the acknowledged candidate access expire while its exact pending
        # refresh and predecessor receipt remain alive. Restart must confirm it,
        # then perform one fresh rotation, never silently password-login.
        until(lambda: time.time() * 1000 > committed["token_expires_at"] + 150,
              "candidate access did not expire before journal restart", ACCESS_TTL + 3)
        self.command(profile, ["tenant", "account", "show"], "restart-recovery")
        after = self.profile(profile)
        require(after["auth"]["auth_session_id"] == before["auth"]["auth_session_id"] and
                after["auth"]["generation"] == before["auth"]["generation"] + 2,
                "restart did not confirm the expired pending commit then obtain fresh access")
        require(not pending_path.exists(), "restart recovery left a confirmed pending journal")
        self.report["restart"] = {"passed": True, "killed_after_server_commit": True,
                                  "candidate_access_expired_before_restart": True, "rotations": 2}

    def predecessor_expiry(self):
        """A committed receipt outlives the predecessor's local refresh deadline."""
        profile = self.register("predecessor-expiry")
        before = self.profile(profile)
        original_deadline = epoch(before["auth"]["refresh_expires_at"])
        original_generation = before["auth"]["generation"]
        original_session = before["auth"]["auth_session_id"]
        # No SDK process is alive during this gap. Refresh at about t0+8s so its
        # committed family remains alive until about t0+28s, while the unchanged
        # local profile still records t0+20s. Access at t0+3s is already expired.
        until(lambda: time.time() >= original_deadline - REFRESH_TTL + 8,
              "predecessor test did not reach its delayed initial commit", 12)
        require(epoch(before["auth"]["token_expires_at"]) < time.time() < original_deadline,
                "initial delayed refresh requires expired access and a live original refresh proof")
        gate_before = self.gates()
        require("refresh_waiting" in gate_before, "fixture must expose post-commit refresh_waiting")
        self.gates({"hold_refresh_replies": True})
        pending_path = Path(str(profile) + ".refresh-pending")
        child = self.start([self.cli, "--api", self.api, "--config", str(profile), "tenant", "refresh"],
                           "predecessor-expiry-interrupted")
        try:
            until(lambda: self.gates()["refresh_waiting"] > 0 and
                  self.authority(before)["generation"] == original_generation + 1 and pending_path.exists(),
                  "predecessor refresh did not reach a journaled server commit", 10)
            pending = json.loads(pending_path.read_text())
            self.vault.learn(pending)
            candidate = pending["pending"]
            committed = self.authority(before)
            require(candidate["auth_session_id"] == original_session and
                    candidate["expected_generation"] == original_generation and
                    committed["request_id"] == candidate["request_id"] and
                    committed["next_token_hash"] == hashlib.sha256(candidate["next_token"].encode()).hexdigest() and
                    committed["next_refresh_hash"] == hashlib.sha256(candidate["next_refresh_token"].encode()).hexdigest(),
                    "predecessor journal does not identify the real committed credential candidates")
            stored = self.profile(profile)
            require(stored["auth"]["generation"] == original_generation and
                    epoch(stored["auth"]["refresh_expires_at"]) == original_deadline,
                    "held predecessor reply changed the old local credential snapshot")
            require(committed["refresh_expires_at"] > (original_deadline + 5) * 1000,
                    "delayed commit did not leave enough live server authority beyond predecessor expiry")
            child.close(kill=True)
        finally:
            self.gates({"hold_refresh_replies": False})
            child.close()
        until(lambda: time.time() > original_deadline + .2,
              "old local refresh deadline did not expire before predecessor recovery", REFRESH_TTL + 2)
        require(pending_path.is_file(), "interrupted predecessor journal was lost before restart")
        require(epoch(self.profile(profile)["auth"]["refresh_expires_at"]) < time.time(),
                "restart did not actually begin with an expired local refresh deadline")
        live = self.authority(before)
        require(live["generation"] == original_generation + 1 and not live["revoked_reason"] and
                live["refresh_expires_at"] > (time.time() + 3) * 1000 and
                live["token_expires_at"] < time.time() * 1000,
                "receipt recovery needs expired candidate access but a still-live committed server family")
        self.command(profile, ["tenant", "account", "show"], "predecessor-expiry-recovery")
        after = self.profile(profile)
        require(after["auth"]["auth_session_id"] == original_session and
                after["auth"]["generation"] == original_generation + 2 and
                epoch(after["auth"]["token_expires_at"]) > time.time(),
                "expired predecessor did not confirm its pending receipt then perform one fresh rotation")
        require(self.authority(after)["generation"] == original_generation + 2,
                "predecessor recovery created an extra credential commit")
        require(not pending_path.exists(), "confirmed predecessor recovery did not remove its journal")
        gate_after = self.gates()
        require(gate_after["auth_register_calls"] == gate_before["auth_register_calls"] and
                gate_after["auth_login_calls"] == gate_before["auth_login_calls"],
                "expired predecessor recovery silently registered or password-logged-in")
        self.report["predecessor-expiry"] = {"passed": True, "rotations": 2,
            "original_refresh_expired_before_restart": True,
            "candidate_access_expired_before_restart": True,
            "committed_server_authority_still_live": True, "same_authority": True,
            "exact_pending_receipt_recovered": True, "no_automatic_login": True}

    def persistence(self):
        profile = self.register("persistence")
        before = self.profile(profile)
        initial = profile.read_bytes()
        sentinel = profile.parent / "sentinel"
        sentinel.write_text("do not follow credential journal symlinks\n")
        pending_path = Path(str(profile) + ".refresh-pending")
        pending_path.symlink_to(sentinel)
        try:
            self.command(profile, ["tenant", "refresh"], "persistence-rejection", success=False)
            require(profile.read_bytes() == initial and self.authority(before)["generation"] == before["auth"]["generation"],
                    "unsafe pending persistence allowed a server-side rotation")
            require(sentinel.read_text() == "do not follow credential journal symlinks\n", "refresh followed its pending symlink")
        finally:
            pending_path.unlink(missing_ok=True)
        self.report["persistence"] = {"passed": True, "unsafe_journal_rejected_before_rpc": True}

    def revocation(self):
        profile = self.register("revocation")
        targets = EchoTargets()
        peers, connection = [], None
        try:
            server, broker, password = self.serve(profile, targets, "refresh-revocation")
            peers.append(server)
            peer, port = self.connect(profile, broker, password, targets, "tcp", "revocation-tcp")
            peers.append(peer)
            connection = socket.create_connection(("127.0.0.1", port), timeout=8)
            connection.settimeout(2)
            connection.sendall(b"authorized-before-revoke")
            require(exact(connection, 24) == b"authorized-before-revoke", "pre-revocation echo failed")
            before = self.profile(profile)
            gate_counts = self.gates()
            self.http("POST", "/v1/auth/logout", {}, before["auth"]["refresh_token"])
            revoked_rows = self.query("SELECT generation,revoked_reason FROM auth_sessions WHERE id=?", (before["auth"]["auth_session_id"],))
            require(not revoked_rows or revoked_rows[0]["revoked_reason"], "logout did not revoke stable login authority")
            revoked_generation = revoked_rows[0]["generation"] if revoked_rows else None
            stopped = False
            end = time.monotonic() + 12
            while time.monotonic() < end:
                try:
                    connection.sendall(b"revoked-flow")
                    if exact(connection, 12) != b"revoked-flow":
                        stopped = True
                        break
                except (OSError, AssertionError):
                    stopped = True
                    break
                time.sleep(.1)
            require(stopped, "revoked stable authority continued forwarding TCP")
            self.command(profile, ["tenant", "refresh"], "revoked-refresh", success=False)
            self.command(profile, ["tenant", "account", "show"], "revoked-account", success=False)
            final = self.profile(profile)
            remaining = self.query("SELECT id,generation,revoked_reason FROM auth_sessions WHERE tenant_id=?", (before["account"]["id"],))
            require(not remaining or (len(remaining) == 1 and remaining[0]["id"] == before["auth"]["auth_session_id"] and
                    remaining[0]["revoked_reason"] and (revoked_generation is None or remaining[0]["generation"] == revoked_generation)),
                    "refresh revived, advanced or replaced revoked authority")
            require(final["auth"]["auth_session_id"] == before["auth"]["auth_session_id"] and
                    not final["account"].get("password"), "revocation silently adopted a fresh password login")
            gate_after = self.gates()
            require(gate_after["auth_login_calls"] == gate_counts["auth_login_calls"] and
                    gate_after["auth_register_calls"] == gate_counts["auth_register_calls"],
                    "revocation triggered an automatic password login/register attempt")
            self.report["revocation"] = {"passed": True, "forwarding_stopped": True, "no_automatic_login": True}
        finally:
            if connection is not None:
                connection.close()
            for child in reversed(peers):
                child.close()
            targets.close()

    def native_sdk(self, binary):
        """Run the standalone native C client against its own one-second fixture."""
        directory = self.root / "native-sdk"
        directory.mkdir(mode=0o700)
        database = directory / "database" / "control.sqlite"
        database.parent.mkdir(mode=0o700)
        ready_path = directory / "ready.json"
        fixture_admin = self.vault.new()
        env = dict(self.env, OB_PEER_TEST_ADMIN_TOKEN=fixture_admin,
                   OHECO_BROKER_ADMIN_TOKEN=fixture_admin)
        fixture = self.start([self.fixture_binary, "--db", str(database), "--ready", str(ready_path),
                              "--account-token-ttl", "1s", "--auth-refresh-ttl", "20s",
                              "--auth-access-overlap", "1s"], "native-sdk-fixture", env=env)
        try:
            def ready():
                fixture.alive()
                if not ready_path.exists():
                    return None
                try:
                    return json.loads(ready_path.read_text())
                except ValueError:
                    return None
            information = until(ready, "standalone C fixture readiness timeout")
            api = information["api"]
            parsed = urllib.parse.urlsplit(api)
            require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port and
                    not parsed.username and not parsed.password and parsed.path in ("", "/"),
                    "standalone C acceptance refuses non-loopback endpoints")
            client = self.start([binary, api], "native-sdk-client", env=env)
            client.finish(timeout=20)
            metadata = [event for event in client.events if event.get("standalone_c") is True]
            require(len(metadata) == 1 and metadata[0].get("generation", 0) >= 3 and
                    metadata[0].get("proactive_idle") is True and metadata[0].get("concurrent_requests") == 80,
                    "standalone C SDK did not confirm proactive idle/concurrent refresh")
            with sqlite3.connect("file:" + str(database) + "?mode=ro", uri=True, timeout=2) as db:
                rows = db.execute("SELECT generation,revoked_reason FROM auth_sessions").fetchall()
            require(len(rows) == 1 and rows[0][0] >= 3 and not rows[0][1],
                    "standalone C did not preserve one stable real SQLite login authority")
            self.report["native-sdk"] = {"passed": True, "standalone_c": True,
                "client_go_runtime": False, "own_fixture": True, "access_ttl_seconds": 1,
                "generation": metadata[0]["generation"], "proactive_idle": True,
                "concurrent_requests": 80}
        finally:
            fixture.close()

    def check_secret_storage(self):
        with self.vault.lock:
            values = [value.encode() for value in self.vault.values]
        for path in self.db.parent.iterdir():
            if path.is_file():
                stored = path.read_bytes()
                require(not any(value in stored for value in values), "test database stored raw token/password material")
        for child in self.children:
            require(not child.exposed_secret_field, "native output included a secret JSON field")
            self.vault.check(child.text())

    def close(self):
        if hasattr(self, "api") and self.fixture.process.poll() is None:
            try:
                self.gates({"hold_refresh_replies": False})
            except Exception:
                pass
        for child in reversed(self.children):
            child.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=lambda value: str(Path(value).resolve()))
    parser.add_argument("--fixture", required=True, type=lambda value: str(Path(value).resolve()))
    parser.add_argument("--native-auth", type=lambda value: str(Path(value).resolve()),
                        help="optional signed standalone C SDK auth acceptance binary")
    parser.add_argument("--case", choices=("all", "native-sdk") + CASES, default="all")
    parser.add_argument("--duration", type=float, default=32, help="transport/idle duration; at least30s to exceed refresh idle TTL")
    args = parser.parse_args()
    require(args.duration >= 30, "long-running acceptance needs at least30 seconds")
    require(Path(args.cli).is_file() and Path(args.fixture).is_file(), "provide the built signed native CLI and fixture binaries")
    require(args.case != "native-sdk" or args.native_auth, "native-sdk case requires --native-auth")
    require(not args.native_auth or Path(args.native_auth).is_file(), "provide the built signed standalone C SDK test binary")
    require(os.environ.get("TMPDIR") and Path(os.environ["TMPDIR"]).is_dir(), "a permissions-capable TMPDIR is required")
    def terminated(signum, _frame):
        raise SystemExit(128 + signum)
    signal.signal(signal.SIGTERM, terminated)
    signal.signal(signal.SIGINT, terminated)
    vault = Secrets()
    acceptance = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="broker-auth-refresh-", dir=os.environ["TMPDIR"]) as directory:
            root = Path(directory)
            require(root.stat().st_mode & 0o077 == 0, "temporary filesystem cannot protect test credentials")
            try:
                # Set the owner before startup so even failed fixture readiness is
                # covered by the exact process-group cleanup below.
                acceptance = Acceptance.__new__(Acceptance)
                acceptance.children = []
                Acceptance.__init__(acceptance, args.cli, args.fixture, root, vault)
                selected = CASES + (("native-sdk",) if args.native_auth else ()) if args.case == "all" else (args.case,)
                for case in selected:
                    if case == "native-sdk":
                        acceptance.native_sdk(args.native_auth)
                    elif case in ("transport", "idle"):
                        getattr(acceptance, case)(args.duration)
                    else:
                        getattr(acceptance, case.replace("-", "_"))()
                    print(json.dumps({"event": "case_passed", "case": case}), flush=True)
                acceptance.check_secret_storage()
                result = {"passed": True, "native_cli": any(case != "native-sdk" for case in selected), "local_real_sqlite_and_pion": True,
                          "access_ttl_seconds": ACCESS_TTL, "refresh_idle_seconds": REFRESH_TTL,
                          "cases": acceptance.report, "seconds": round(time.monotonic() - started, 3)}
            finally:
                if acceptance is not None:
                    acceptance.close()
                    for child in acceptance.children:
                        vault.check(child.text())
        result["test_temp_removed"] = True
        result["test_processes_stopped"] = all(child.process.poll() is not None for child in acceptance.children)
        require(result["test_processes_stopped"], "test-owned processes survived cleanup")
        print(json.dumps(result, sort_keys=True, indent=2), flush=True)
        return 0
    except Exception as error:
        print(json.dumps({"passed": False, "error": vault.safe(type(error).__name__ + ": " + str(error))}), file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
