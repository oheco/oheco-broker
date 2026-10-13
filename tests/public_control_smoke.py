#!/usr/bin/env python3
"""Opt-in trusted public HTTPS/WSS recovery smoke with an approved account.

Read an existing profile's access bearer into an isolated legacy profile, without
logging in, refreshing that authority or changing the original profile. Create
one uniquely named broker with an empty target allowlist, recover its control
connection, and delete only that broker. Every public connection uses SOCKS5;
TLS terminates in the CLI/curl with normal certificate and hostname checks.
This covers the public control plane, not public direct/TURN data traffic.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse

from auth_refresh import Secrets, exact, require, until
from cli_serve_recovery import ControlGate, RecordedProcess


class SocksTunnelGate(ControlGate):
    """A transparent loopback TLS gate forwarding the selected API via SOCKS."""
    def __init__(self, destination, proxy):
        self.destination, self.proxy = destination, proxy
        super().__init__(proxy)

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
            worker = threading.Thread(target=self._tunnel, args=(client,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def _tunnel(self, client):
        server = None
        try:
            server = socket.create_connection(self.proxy, timeout=8)
            server.sendall(b"\x05\x01\x00")
            require(exact(server, 2) == b"\x05\x00", "SOCKS authentication negotiation failed")
            host = self.destination[0].encode("idna")
            server.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", self.destination[1]))
            reply = exact(server, 4)
            require(reply[:2] == b"\x05\x00", "SOCKS refused the trusted API destination")
            length = {1: 4, 4: 16}.get(reply[3])
            if reply[3] == 3:
                length = exact(server, 1)[0]
            require(length is not None, "invalid SOCKS reply")
            exact(server, length + 2)
            with self.lock:
                if not self.enabled or self.halted:
                    return
                self.connections.extend((client, server))
            client.settimeout(None)
            server.settimeout(None)
            self._forward(client, server)
        except (OSError, ValueError, AssertionError):
            pass
        finally:
            with self.lock:
                for connection in (client, server):
                    if connection is not None:
                        if connection in self.connections:
                            self.connections.remove(connection)
                        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--api", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--proxy", default="socks5h://127.0.0.1:10808")
    args = parser.parse_args()
    url, proxy = urllib.parse.urlsplit(args.api), urllib.parse.urlsplit(args.proxy)
    require(url.scheme == "https" and url.hostname and not url.username and not url.query, "supply a trusted HTTPS API")
    require(proxy.scheme == "socks5h" and proxy.hostname in ("127.0.0.1", "localhost") and proxy.port, "supply the local SOCKS5 proxy")
    socket.inet_aton(url.hostname)  # The test shim deliberately targets an IPv4 literal.
    source = Path(args.profile).read_bytes()
    source_hash = hashlib.sha256(source).hexdigest()
    original = json.loads(source)
    require(original["api"].rstrip("/") == args.api.rstrip("/"), "profile belongs to a different API")
    vault = Secrets()
    vault.learn(original)
    account = {key: original["account"][key] for key in ("id", "name", "token")}
    token = account["token"]
    require(token and not any(c.isspace() for c in token), "invalid account access bearer")
    name = "recovery-smoke-" + secrets.token_hex(6)
    process, gate = None, None
    own_id = None

    def request(method, path):
        # Keep the bearer off argv and out of diagnostics.
        config = "header = " + json.dumps("Authorization: Bearer " + token) + "\n"
        result = subprocess.run(["curl", "--disable", "--noproxy", "", "--proxy", args.proxy, "--cacert", args.ca_file,
                                 "--silent", "--show-error", "--fail-with-body", "--max-time", "15",
                                 "--request", method, "--config", "-", args.api.rstrip("/") + path],
                                input=config, capture_output=True, text=True, timeout=20)
        require(result.returncode == 0, "trusted management request failed: " + str(result.returncode))
        value = json.loads(result.stdout)
        vault.learn(value)
        return value

    def brokers():
        return request("GET", "/v1/brokers")["brokers"]

    with tempfile.TemporaryDirectory(prefix="broker-public-control-smoke-", dir=os.environ["TMPDIR"]) as directory:
        root = Path(directory)
        require(root.resolve().parent == Path(os.environ["TMPDIR"]).resolve(), "invalid private test root")
        cfg = root / "account.json"
        cfg.write_text(json.dumps({"version": 1, "api": args.api, "ca_file": args.ca_file, "account": account}))
        cfg.chmod(0o600)
        try:
            require(not any(b["name"] == name for b in brokers()), "test broker name already exists")
            gate = SocksTunnelGate((url.hostname, url.port or 443), (proxy.hostname, proxy.port))
            # The SDK disables environment proxies; a signed test-only socket
            # shim changes the TCP destination while keeping the real TLS URL.
            shim, signed = root / "control-proxy.so", root / "control-proxy.signed.so"
            subprocess.run(["clang", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                            str(Path(__file__).parent / "c/control_proxy_preload.c"), "-ldl", "-o", str(shim)],
                           check=True, capture_output=True, text=True, timeout=45)
            subprocess.run(["binary-sign-tool", "sign", "-inFile", str(shim), "-outFile", str(signed), "-selfSign", "1"],
                           check=True, capture_output=True, text=True, timeout=30)
            signed.chmod(0o700)
            env = dict(os.environ, XDG_CONFIG_HOME=str(root), OHECO_BROKER_API=args.api,
                       LD_PRELOAD=str(signed), OHECO_SMOKE_API_IP=url.hostname,
                       OHECO_SMOKE_API_PORT=str(url.port or 443),
                       OHECO_SMOKE_GATE_PORT=str(gate.listener.getsockname()[1]))
            for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
                env[key] = args.proxy
            env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
            process = RecordedProcess([args.binary, "--config", str(cfg), "tenant", "serve", "--name", name,
                                       "--password-stdin", "--state-events"], env, root, "public-control", vault,
                                      stdin=vault.new() + "\n")
            own_id = process.event("broker_ready")["broker_id"]
            process.state("connected")
            with gate.lock:
                require(len(gate.connections) >= 2, "native WSS bypassed the isolated proxy gate")
            require(any(b["id"] == own_id and b["name"] == name and b["online"] for b in brokers()), "test broker is not online")
            gate.cut()
            process.state("paused")
            paused_at = time.monotonic()
            with process.condition:
                mark = len(process.events)
            gate.enabled = True
            process.state("connected", after=mark, timeout=45)
            elapsed = time.monotonic() - paused_at
            require(28 <= elapsed <= 43, "public control recovery did not use the scheduled interval")
            require(any(e.get("event") == "reconnect_requested" and e.get("automatic") is True for e in process.events[mark:]), "missing public automatic recovery")
            until(lambda: any(b["id"] == own_id and b["online"] for b in brokers()), "test broker heartbeat did not recover", 10)
            process.notice("connection restored")
            vault.check(process.text())
            require(not process.exposed_secret_field, "public native output exposed a secret")
        finally:
            if process:
                process.close()
            if gate:
                gate.close()
            # A partial startup may have registered before broker_ready. Match
            # the unique own name and verify the ID before deleting anything.
            matches = [b for b in brokers() if b["name"] == name]
            require(len(matches) <= 1, "ambiguous test broker cleanup")
            for broker in matches:
                require(own_id is None or broker["id"] == own_id, "test broker cleanup ID changed")
                request("DELETE", "/v1/brokers/" + broker["id"])
            require(not any(b["name"] == name for b in brokers()), "test broker cleanup failed")
    require(hashlib.sha256(Path(args.profile).read_bytes()).hexdigest() == source_hash, "original account profile changed during smoke")
    print(json.dumps({"result": "PASS", "scope": "public HTTPS/WSS control recovery",
                      "verified_tls": True, "all_public_connections_via_socks5": True,
                      "automatic_recovery_seconds": round(elapsed, 2), "same_process": True,
                      "original_profile_unchanged": True, "own_broker_deleted": True,
                      "public_peer_tcp_udp": "outside this control-plane smoke"}, sort_keys=True))


if __name__ == "__main__":
    main()
