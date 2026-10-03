#!/usr/bin/env python3
"""Exercise CLI control operations and receipt-loss recovery in private fixtures."""
import argparse
import http.server
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
import urllib.error
import urllib.request


def terminate(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=lambda p: str(Path(p).resolve()))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="broker-cli-control-", dir=os.environ["TMPDIR"]) as directory:
        root = Path(directory)
        admin = secrets.token_hex(32)
        env = dict(os.environ, TMPDIR=str(root), XDG_CONFIG_HOME=str(root / "xdg"),
                   OHECO_BROKER_ADMIN_TOKEN=admin)
        output = (root / "server.log").open("wb")
        process = subprocess.Popen([args.binary, "server", "serve", "--listen", "127.0.0.1:0",
                         "--db", str(root / "database" / "control.sqlite"), "--registration", "open",
                         "--turn-listen", "127.0.0.1:0", "--turn-allow-loopback"],
                         env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=output)
        def command(parts, profile="account.json", success=True, stdin=None, api=None):
            result = subprocess.run([args.binary, "--api", api or url, "--config", str(root / profile)] + parts,
                                    env=env, capture_output=True, text=True, input=stdin, timeout=30)
            if success != (result.returncode == 0):
                raise AssertionError(f"CLI {parts[:3]} unexpected status {result.returncode}: " +
                                     (result.stdout + result.stderr).replace(admin, "[redacted]"))
            if admin in result.stdout or admin in result.stderr:
                raise AssertionError("administrator secret printed")
            if not success:
                return result
            return json.loads(result.stdout) if result.stdout.strip() else {}
        proxy = None
        proxy_thread = None
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise AssertionError((root / "server.log").read_text())
                ready = None
                for line in (root / "server.log").read_text().splitlines():
                    try:
                        candidate = json.loads(line)
                    except ValueError:
                        continue
                    if candidate.get("event") == "server_ready":
                        ready = candidate
                if ready:
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError("CLI server startup timeout")
                time.sleep(.03)
            url = ready["api"]
            registered = command(["tenant", "register", "--email", "cli@example.invalid"])
            tenant_id = registered["tenant"]["id"]
            path = root / "account.json"
            stored = json.loads(path.read_text())
            if len(stored["account"]["password"]) != 32 or path.stat().st_mode & 0o077:
                raise AssertionError("credential generation/storage invalid")
            if (root / "account.json.pending").exists() or "token" in registered:
                raise AssertionError("registration cleanup/redaction failed")
            assert command(["tenant", "capabilities"])["relay_enabled"] is False
            command(["admin", "tenant", "relay", "enable", tenant_id])
            assert command(["tenant", "capabilities"])["relay_enabled"] is True
            command(["admin", "tenant", "relay", "disable", tenant_id])
            broker = command(["tenant", "broker", "register", "metadata-test"])["broker"]
            command(["tenant", "broker", "rename", broker["id"], "--name", "renamed"])
            assert command(["tenant", "broker", "show", broker["id"]])["broker"]["name"] == "renamed"
            assert command(["admin", "broker", "show", broker["id"]])["broker"]["tenant_id"] == tenant_id
            command(["tenant", "usage", "--broker", broker["id"]])
            command(["tenant", "broker", "delete", broker["id"]])
            command(["tenant", "account", "update", "--name", "cli-renamed-" + secrets.token_hex(4),
                     "--email", "changed@example.invalid"])
            changed = json.loads(path.read_text())
            assert changed["account"]["token"] != stored["account"]["token"]
            (root / "stale.json").write_text(json.dumps(stored))
            (root / "stale.json").chmod(0o600)
            command(["tenant", "account", "show"], profile="stale.json", success=False)
            replacement = secrets.token_hex(16)
            command(["tenant", "account", "password", "--password-stdin"], stdin=replacement + "\n")
            assert json.loads(path.read_text())["account"]["password"] == replacement
            command(["tenant", "logout"])
            command(["tenant", "account", "show"], success=False)
            command(["tenant", "login"])
            command(["admin", "tenant", "disable", tenant_id])
            command(["tenant", "login"], success=False)
            command(["admin", "tenant", "enable", tenant_id])
            command(["tenant", "login"])
            reset = secrets.token_hex(16)
            command(["admin", "tenant", "reset-password", tenant_id, "--password-stdin"], stdin=reset + "\n")
            command(["tenant", "login"], success=False)
            command(["tenant", "login", "--password-stdin"], stdin=reset + "\n")
            print("PASS CLI account/admin/broker operations, token revocation and private credentials", flush=True)
            command(["admin", "registration", "set", "approval"])
            pending = command(["tenant", "register"], profile="pending.json")["tenant"]
            assert pending["status"] == "pending"
            command(["tenant", "broker", "list"], profile="pending.json", success=False)
            command(["admin", "tenant", "approve", pending["id"]])
            command(["tenant", "login"], profile="pending.json")
            command(["admin", "registration", "set", "closed"])
            command(["tenant", "register"], profile="closed.json", success=False)
            assert not (root / "closed.json").exists()
            assert (root / "closed.json.pending").exists()
            command(["admin", "registration", "set", "open"])
            print("PASS CLI registration policies and approval", flush=True)

            state = {"registrations": 0, "tenant_id": None}
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            class LostReceipt(http.server.BaseHTTPRequestHandler):
                def log_message(self, *unused):
                    pass
                def do_POST(self):
                    length = int(self.headers.get("Content-Length", "0"))
                    if length > 65536:
                        self.send_error(413)
                        return
                    body = self.rfile.read(length)
                    request = urllib.request.Request(url + self.path, data=body,
                                                      headers={"Content-Type": "application/json"}, method="POST")
                    try:
                        with opener.open(request, timeout=10) as response:
                            raw = response.read()
                            status = response.status
                    except urllib.error.HTTPError as error:
                        raw, status = error.read(), error.code
                    if self.path == "/v1/tenants/register":
                        state["registrations"] += 1
                        if status == 201:
                            state["tenant_id"] = json.loads(raw)["tenant"]["id"]
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        self.close_connection = True
                        return
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
            proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LostReceipt)
            proxy_thread = threading.Thread(target=proxy.serve_forever)
            proxy_thread.start()
            proxy_url = "http://127.0.0.1:" + str(proxy.server_port)
            failed = command(["tenant", "register"], profile="receipt.json", success=False, api=proxy_url)
            recovery = root / "receipt.json.pending"
            draft = json.loads(recovery.read_text())
            if draft["account"]["password"] in failed.stderr or state["registrations"] != 1:
                raise AssertionError("receipt loss leaked credentials or retried registration")
            recovered = command(["tenant", "login"], profile="receipt.json.pending", api=proxy_url)
            assert recovered["tenant"]["id"] == state["tenant_id"]
            print("PASS CLI committed registration/lost receipt recovery without secret output or retry", flush=True)
        finally:
            if proxy is not None:
                proxy.shutdown()
                proxy.server_close()
                proxy_thread.join(timeout=5)
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            output.close()
        assert process.returncode == 0, "CLI server did not shut down gracefully"
    print("PASS isolated CLI control acceptance; test-owned resources cleaned", flush=True)

if __name__ == "__main__":
    main()
