#!/usr/bin/env python3
"""Native CLI recovery after its real 60-second retry budget is exhausted.

Own local fixtures, profiles, TCP gate and echo sockets only. Keep the same serve
process and device credential; never send SIGUSR1 or restart to obtain recovery.
"""
import argparse
import json
import os
from pathlib import Path
import select
import socket
import sqlite3
import tempfile
import threading
import time
import urllib.request

from auth_refresh import EchoTargets, Process, Secrets, exact, require, secret_field, until


class RecordedProcess(Process):
    def __init__(self, *args, **kwargs):
        self.stdout_lines, self.stderr_lines = [], []
        super().__init__(*args, **kwargs)

    def _read(self, stream):
        for line in stream:
            with self.condition:
                self.output.append(line)
                (self.stdout_lines if stream is self.process.stdout else self.stderr_lines).append(line)
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

    def state(self, state, after=0, timeout=85):
        def observed():
            with self.condition:
                found = next((e for e in self.events[after:] if e.get("event") == "connection_state" and e.get("state") == state), None)
            self.alive()
            return found
        return until(observed, self.label + " state timeout: " + state, timeout)

    def notice(self, text, timeout=10):
        return until(lambda: any(text in line for line in self.stderr_lines), self.label + " missing stderr notice", timeout)


class ControlGate:
    def __init__(self, upstream):
        self.upstream = upstream
        self.enabled, self.halted = True, False
        self.lock = threading.Lock()
        self.connections, self.workers = [], []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.listener.settimeout(.1)
        self.thread = threading.Thread(target=self._accept)
        self.thread.start()

    def _accept(self):
        while not self.halted:
            try:
                client, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            if not self.enabled:
                client.close()
                continue
            try:
                server = socket.create_connection(self.upstream, timeout=2)
            except OSError:
                client.close()
                continue
            with self.lock:
                self.connections.extend((client, server))
            worker = threading.Thread(target=self._forward, args=(client, server), daemon=True)
            self.workers.append(worker)
            worker.start()

    def _forward(self, client, server):
        try:
            while self.enabled and not self.halted:
                ready, _, _ = select.select([client, server], [], [], .1)
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    (server if source is client else client).sendall(data)
        except (OSError, ValueError):
            pass
        finally:
            with self.lock:
                for connection in (client, server):
                    if connection in self.connections:
                        self.connections.remove(connection)
                    connection.close()

    def cut(self):
        self.enabled = False
        with self.lock:
            for connection in self.connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()

    def close(self):
        self.halted = True
        self.cut()
        self.listener.close()
        self.thread.join(timeout=3)
        for worker in self.workers:
            worker.join(timeout=3)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=lambda p: str(Path(p).resolve()))
    args = parser.parse_args()
    vault = Secrets()
    processes, gate, targets = [], None, None
    with tempfile.TemporaryDirectory(prefix="broker-cli-serve-recovery-", dir=os.environ["TMPDIR"]) as directory:
        root = Path(directory)
        env = dict(os.environ, XDG_CONFIG_HOME=str(root), OHECO_BROKER_ADMIN_TOKEN=vault.new())
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "OHECO_BROKER_API"):
            env.pop(key, None)
        env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def start(parts, label, stdin=None):
            process = RecordedProcess([args.binary] + parts, env, root, label, vault, stdin=stdin)
            processes.append(process)
            return process
        profile = root / "oheco-broker/account.json"
        db_path = root / "control.sqlite"
        def credentials():
            value = json.loads(profile.read_text())
            vault.learn(value)
            return value
        def devices():
            with sqlite3.connect("file:" + str(db_path) + "?mode=ro", uri=True) as db:
                return db.execute("SELECT broker_id,hash,auth_session_id FROM tokens WHERE kind='device' ORDER BY broker_id").fetchall()
        def api(method, path):
            token = credentials()["account"]["token"]
            request = urllib.request.Request(origin + path, method=method, headers={"Authorization": "Bearer " + token})
            with opener.open(request, timeout=5) as response:
                return json.load(response)
        try:
            fixture = start(["server", "serve", "--listen", "127.0.0.1:0", "--db", str(db_path), "--registration", "open",
                             "--turn-listen", "127.0.0.1:0", "--broker-lease", "5s", "--account-token-ttl", "6s",
                             "--auth-refresh-ttl", "10m", "--auth-access-overlap", "1s"], "control")
            origin = fixture.event("server_ready")["api"]
            gate = ControlGate(("127.0.0.1", int(origin.rsplit(":", 1)[1])))
            url = "http://127.0.0.1:" + str(gate.listener.getsockname()[1])
            registration = start(["--api", url, "tenant", "register", "--name", "serve-recovery", "--password-stdin"], "registration", vault.new() + "\n")
            registration.finish()
            targets = EchoTargets()
            target = "127.0.0.1:" + str(targets.tcp.getsockname()[1])
            password = vault.new()
            common = ["--api", url, "tenant", "serve", "--password-stdin", "--allow", "tcp@" + target]
            broker = start(common + ["--name", "desktop", "--state-events"], "broker", password + "\n")
            broker_id = broker.event("broker_ready")["broker_id"]
            broker.state("connected")
            quiet = start(common + ["--name", "quiet-desktop"], "quiet-broker", password + "\n")
            quiet.event("broker_ready")
            original_devices = devices()
            initial = credentials()
            original_pid = broker.process.pid
            gate.cut()
            broker.state("paused")
            paused_at = time.monotonic()
            quiet.notice("automatic retries exhausted", timeout=5)
            # The six-second account bearer has expired while the gate is down.
            # Inspect only this fixture's lease rows without refreshing or logging in.
            with sqlite3.connect("file:" + str(db_path) + "?mode=ro", uri=True) as db:
                online = db.execute("SELECT COUNT(*) FROM brokers WHERE lease_expires_at>?", (int(time.time() * 1000),)).fetchone()[0]
            require(online == 0, "lease remained online during the outage")
            with broker.condition:
                mark = len(broker.events)
            gate.enabled = True
            broker.state("connected", after=mark, timeout=40)
            elapsed = time.monotonic() - paused_at
            require(28 <= elapsed <= 38, "paused recovery did not wait one 30-second interval: " + str(elapsed))
            broker.notice("connection restored")
            quiet.notice("connection restored", timeout=6)
            until(lambda: credentials()["auth"]["generation"] > initial["auth"]["generation"], "account refresh did not recover", 25)
            final = credentials()
            require(final["auth"]["auth_session_id"] == initial["auth"]["auth_session_id"], "recovery replaced the login session")
            require(devices() == original_devices, "recovery rotated/replaced device credentials")
            require(broker.process.pid == original_pid, "serve process was replaced")
            require(all(b["online"] for b in api("GET", "/v1/brokers")["brokers"]), "one broker did not restore its heartbeat")
            require(any(e.get("event") == "reconnect_requested" and e.get("automatic") is True for e in broker.events[mark:]), "missing automatic recovery event")
            require(len(quiet.stdout_lines) == 1 and json.loads(quiet.stdout_lines[0])["event"] == "broker_ready", "default stdout readiness contract changed")
            client = start(["--api", url, "tenant", "connect", "--name", "desktop", "--password-stdin", "--protocol", "tcp",
                            "--target", target, "--local", "0", "--relay", "never"], "new-client", password + "\n")
            mapping = client.event("mapping_ready")
            host, port = mapping["local"].rsplit(":", 1)
            with socket.create_connection((host, int(port)), timeout=5) as connection:
                connection.settimeout(5)
                payload = b"new mapping after automatic broker recovery"
                connection.sendall(payload)
                require(exact(connection, len(payload)) == payload, "new mapped TCP connection did not carry data")
            client.close()
            api("DELETE", "/v1/brokers/" + broker_id)
            broker.finish(success=False, timeout=12)
            # A healthy or waiting service must also honor cancellation promptly.
            quiet.process.terminate()
            quiet.finish(timeout=7)
            for process in processes:
                vault.check(process.text())
                require(not process.exposed_secret_field, "secret field in native output")
            print(json.dumps({"result": "PASS", "paused_retry_seconds": round(elapsed, 2), "same_process": True,
                              "same_device_credentials": True, "same_login_session": True, "automatic_account_refresh": True,
                              "default_stderr_notices": True, "default_stdout_compatible": True, "new_tcp_mapping": True,
                              "revocation_exits": True, "cancellation_exits": True}), flush=True)
        finally:
            for process in reversed(processes):
                process.close()
            if gate:
                gate.close()
            if targets:
                targets.close()


if __name__ == "__main__":
    main()
