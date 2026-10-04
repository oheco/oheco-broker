#!/usr/bin/env python3
"""Native Linux Docker acceptance with only local TLS, SQLite and TURN traffic.

Requires Docker, Python 3, OpenSSL, and root or passwordless sudo for test-owned
UID/GID 10001 bind mounts. Run separately on native amd64 and arm64 runners.
The Docker recipe and this driver can live outside the immutable app context.
No pip packages, production endpoints, or emulation are used.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import signal
import socket
import sqlite3
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


STATE = "/var/lib/oheco-broker"
DB = STATE + "/db/control.sqlite"
SECRETS = "/run/oheco-broker/secrets"
TLS = "/run/oheco-broker/tls"
UID = GID = 10001


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def architecture(value):
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64/v8": "arm64"}.get(value, value)


class Smoke:
    def __init__(self, args, root):
        self.args, self.root = args, root
        self.names = []
        self.secrets = []
        self.root_command = [] if os.geteuid() == 0 else ["sudo", "-n"]

    def redact(self, text):
        for secret in self.secrets:
            text = text.replace(secret, "[redacted]")
        return text

    def run(self, command, *, check=True, timeout=30, input_text=None):
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, input=input_text)
        if check and result.returncode:
            raise AssertionError(self.redact("command failed: " + " ".join(command) + "\n" + result.stdout + result.stderr))
        return result

    def docker(self, *args, **kwargs):
        return self.run(["docker", *map(str, args)], **kwargs)

    def privileged(self, *args):
        return self.run([*self.root_command, *map(str, args)])

    def inventory(self):
        info = json.loads(self.docker("info", "--format", "{{json .}}").stdout)
        require(info["OSType"] == "linux" and architecture(info["Architecture"]) == self.args.expected_arch,
                "Docker daemon must run the expected native Linux architecture")
        image = json.loads(self.docker("image", "inspect", self.args.image).stdout)[0]
        require(image["Os"] == "linux" and image["Architecture"] == self.args.expected_arch, "wrong image architecture")
        config = image["Config"]
        require(config["User"] == "10001:10001", "image must default to UID:GID 10001:10001")
        require(config["Entrypoint"] == ["/usr/local/bin/oheco-broker-server"], "server must be the direct entrypoint")
        require(config["Cmd"] == ["--db", DB], "default CMD must use the persisted absolute SQLite path")
        require(config.get("StopSignal") == "SIGTERM", "image must use SIGTERM")
        require(STATE in config.get("Volumes", {}), "state volume is missing")
        require(config["Labels"]["org.opencontainers.image.version"] == self.args.expected_version, "version label mismatch")
        require(config["Labels"]["org.opencontainers.image.revision"] == self.args.expected_revision, "source label mismatch")
        for binary in ("oheco-broker-server", "oheco-broker"):
            options = [] if binary.endswith("-server") else ["--entrypoint", "/usr/local/bin/" + binary]
            result = self.docker("run", "--rm", "--network", "none", *options, self.args.image, "--version")
            require(result.stdout.strip() == binary + " " + self.args.expected_version, "binary version mismatch")
            help_output = self.docker("run", "--rm", "--network", "none", *options, self.args.image, "--help")
            require("Usage:" in help_output.stdout + help_output.stderr, "help requires service configuration")
        probe = self.docker("run", "--rm", "--network", "none", "--entrypoint", "/bin/sh", self.args.image, "-ec", """
            test "$(id -u)" = 10001; test "$(id -g)" = 10001
            test "$XDG_CONFIG_HOME" = /var/lib/oheco-broker/config
            test "$SSL_CERT_FILE" = /etc/ssl/certs/ca-certificates.crt
            for path in /var/lib/oheco-broker /var/lib/oheco-broker/db /var/lib/oheco-broker/config /var/lib/oheco-broker/acme; do
                test "$(stat -c '%u:%g:%a' "$path")" = 10001:10001:700
            done
            test -s /etc/ssl/certs/ca-certificates.crt; test -r /etc/ssl/cert.pem
            test -s /usr/share/licenses/oheco-broker/LICENSE
            test -s /usr/share/licenses/oheco-broker/Go-LICENSE
            test -s /usr/share/licenses/oheco-broker/sdk/c/tpr/curl/COPYING
            test -s /usr/share/licenses/oheco-broker/vendor/github.com/mattn/go-sqlite3/LICENSE
            test -s /usr/share/doc/libstdc++6/copyright
            test -s /usr/share/doc/libgcc-s1/copyright
            test -s /usr/share/doc/libc6/copyright
            test -s /usr/share/doc/ca-certificates/copyright
            ldd /usr/local/bin/oheco-broker
            ldd /usr/local/bin/oheco-broker-server
            uname -m
        """)
        require("not found" not in probe.stdout, "missing dynamic runtime dependency")
        # Query each closure separately: ldd's headings vary between releases.
        cli = self.docker("run", "--rm", "--network", "none", "--entrypoint", "ldd", self.args.image,
                          "/usr/local/bin/oheco-broker").stdout
        server = self.docker("run", "--rm", "--network", "none", "--entrypoint", "ldd", self.args.image,
                             "/usr/local/bin/oheco-broker-server").stdout
        for library in ("libstdc++.so.6", "libgcc_s.so.1", "libc.so.6"):
            require(library in cli, "CLI runtime closure is missing " + library)
        require("libc.so.6" in server and "libstdc++" not in server, "independent server has incorrect runtime closure")
        require(architecture(probe.stdout.strip().splitlines()[-1]) == self.args.expected_arch, "container kernel architecture mismatch")
        bundle = self.docker("run", "--rm", "--network", "none", "--entrypoint", "/bin/cat", self.args.image,
                             "/etc/ssl/certs/ca-certificates.crt").stdout
        require(bundle.count("-----BEGIN CERTIFICATE-----") > 50, "runtime public CA trust store is incomplete")
        print("PASS native architecture, two versions/help, nonroot state, licenses and runtime/CA closure", flush=True)
        return bundle

    def prepare(self, public_bundle):
        os.umask(0o077)
        self.state = self.root / "state"
        self.tls = self.root / "tls"
        self.secret_dir = self.root / "secrets"
        for path in (self.state, self.state / "db", self.state / "config", self.state / "acme", self.tls, self.secret_dir):
            path.mkdir(mode=0o700)
        cert, key = self.tls / "cert.pem", self.tls / "key.pem"
        self.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
                  "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                  "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(key), "-out", str(cert)])
        self.ca = self.root / "ca.pem"
        self.ca.write_bytes(cert.read_bytes())
        self.trust = self.root / "trusted-bundle.pem"
        self.trust.write_text(public_bundle + self.ca.read_text())
        self.trust.chmod(0o444)
        self.admin = secrets.token_hex(32)
        self.secrets.append(self.admin)
        token = self.secret_dir / "admin.token"
        token.write_text(self.admin + "\n")
        key.chmod(0o400)
        token.chmod(0o400)
        cert.chmod(0o444)
        # Docker daemon binds these paths as root; ancestor remains private to the
        # host test user. Only test-owned assets are chowned with passwordless sudo.
        for path in (self.state, self.tls, self.secret_dir):
            self.privileged("chown", "-R", "10001:10001", path)
            self.privileged("chmod", "0700", path)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                         urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(self.ca))))

    def options(self, *, cap=False, trust=False, bridge=False):
        result = ["--network", "bridge" if bridge else "host", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                  "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777",
                  "--mount", f"type=bind,src={self.state},dst={STATE}",
                  "--mount", f"type=bind,src={self.tls},dst={TLS},readonly",
                  "--mount", f"type=bind,src={self.secret_dir},dst={SECRETS},readonly"]
        if cap:
            result += ["--cap-add", "NET_BIND_SERVICE"]
        if bridge:
            result += ["--sysctl", "net.ipv4.ip_unprivileged_port_start=1024", "--publish", "127.0.0.1::443"]
        if trust:
            result += ["--mount", f"type=bind,src={self.trust},dst=/etc/ssl/certs/ca-certificates.crt,readonly"]
        return result

    def start(self, command, *, entrypoint=None, cap=False, bridge=False):
        name = "oheco-docker-smoke-" + secrets.token_hex(8)
        self.names.append(name)
        options = self.options(cap=cap, bridge=bridge)
        if entrypoint:
            options += ["--entrypoint", entrypoint]
        self.docker("run", "--detach", "--name", name, *options, self.args.image, *command)
        return name

    def inspect(self, name):
        return json.loads(self.docker("inspect", name).stdout)[0]

    def logs(self, name):
        result = self.docker("logs", name)
        return result.stdout + result.stderr

    def event(self, name, kind, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for line in self.logs(name).splitlines():
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if value.get("event") == kind:
                    return value
            require(self.inspect(name)["State"]["Running"], self.redact("container exited before " + kind + ": " + self.logs(name)))
            time.sleep(0.1)
        raise AssertionError(self.redact("readiness timeout for " + kind + ": " + self.logs(name)))

    def stop(self, name):
        start = time.monotonic()
        self.docker("kill", "--signal", "TERM", name)
        result = self.docker("wait", name, timeout=15)
        elapsed = time.monotonic() - start
        require(result.stdout.strip() == "0", self.redact("SIGTERM exit failed: " + self.logs(name)))
        require(elapsed < 15 and not self.inspect(name)["State"]["OOMKilled"], "TERM did not shut down within 15 seconds")
        return elapsed

    def cli(self, name, *args, check=True):
        return self.docker("exec", name, "/usr/local/bin/oheco-broker", "--api", self.api_url,
                           "--ca-file", TLS + "/cert.pem", *args, check=check, timeout=45)

    def cli_json(self, name, *args):
        return json.loads(self.cli(name, *args).stdout)

    def api(self, method, path, *, token="", body=None, expected=200):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(self.api_url + path, method=method, headers=headers,
                         data=None if body is None else json.dumps(body).encode())
        try:
            response = self.opener.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            require(response.code == expected, f"unexpected HTTP {response.code} for {method} {path}; expected {expected}")
        return json.loads(raw) if raw else None

    def server_flags(self, listen="127.0.0.1:0", *, turn=True):
        result = ["--db", DB, "--listen", listen, "--admin-token-file", SECRETS + "/admin.token",
                  "--tls-cert", TLS + "/cert.pem", "--tls-key", TLS + "/key.pem"]
        if turn:
            result += ["--turn-listen", "127.0.0.1:0", "--turn-public-ip", "127.0.0.1", "--turn-allow-loopback"]
        return result

    def check_process(self, name, *, cap=False):
        proc = self.docker("exec", name, "/bin/sh", "-ec", "readlink /proc/1/exe; cat /proc/1/status").stdout
        require(proc.splitlines()[0] == "/usr/local/bin/oheco-broker-server", "server is not PID 1")
        fields = dict(line.split(":", 1) for line in proc.splitlines()[1:] if ":" in line)
        require(fields["Uid"].split() == ["10001"] * 4 and fields["Gid"].split() == ["10001"] * 4, "server is not UID/GID 10001")
        require(fields["NoNewPrivs"].strip() == "1", "no-new-privileges is missing")
        capabilities = int(fields["CapEff"].strip(), 16)
        require(capabilities == (1 << 10 if cap else 0), "unexpected effective capabilities")

    def control(self):
        server = self.start(self.server_flags())
        ready = self.event(server, "server_ready")
        require(ready["version"] == self.args.expected_version and ready["api"].startswith("https://127.0.0.1:"), "incorrect TLS readiness")
        self.api_url = ready["api"]
        self.check_process(server)
        self.api("GET", "/v1/admin/settings", expected=401)
        self.api("GET", "/v1/admin/settings", token="wrong-admin-token-123456", expected=401)
        settings = self.api("GET", "/v1/admin/settings", token=self.admin)
        require(settings == {"registration_policy": "approval", "registration_relay_enabled": False}, "unsafe initial registration defaults")
        info = self.api("GET", "/v1/admin/info", token=self.admin)
        require(info["storage"] == "sqlite3" and info["schema_version"] == 1 and info["quic_termination"] is False, "not the SQLite standalone service")
        untrusted = self.docker("exec", server, "oheco-broker", "--api", self.api_url, "admin", "--token-file",
                                SECRETS + "/admin.token", "info", check=False)
        require(untrusted.returncode != 0 and "remote:" in untrusted.stderr, "CLI accepted the untrusted fixture certificate")
        trusted = self.docker("run", "--rm", *self.options(trust=True), "--entrypoint", "oheco-broker", self.args.image,
                              "--api", self.api_url, "admin", "--token-file", SECRETS + "/admin.token", "info")
        require(json.loads(trusted.stdout)["storage"] == "sqlite3", "C SDK default CA trust path did not verify HTTPS")
        registered = self.cli_json(server, "tenant", "register", "--email", "docker-smoke@example.invalid")
        self.tenant = registered["tenant"]["id"]
        require(registered["tenant"]["status"] == "pending" and registered["tenant"]["relay_enabled"] is False,
                "new account bypassed approval/relay defaults")
        require("token" not in registered, "CLI printed credentials")
        caps = self.cli_json(server, "tenant", "capabilities")
        require(caps["status"] == "pending" and caps["relay_enabled"] is False and caps["turn_available"] is True, "wrong pending capabilities")
        require(caps["turn_address"] == ready["turn_advertised"], "TURN advertisement mismatch")
        self.stun(ready["turn_advertised"])
        denied = self.cli(server, "tenant", "broker", "register", "denied-before-approval", check=False)
        require(denied.returncode != 0 and "HTTP=403" in denied.stderr, "pending broker was accepted")
        self.api("POST", "/v1/admin/tenants/" + self.tenant + "/approve", token=self.admin, body={})
        caps = self.cli_json(server, "tenant", "capabilities")
        require(caps["status"] == "active" and caps["relay_enabled"] is False, "approval implicitly enabled relay")
        self.cli_json(server, "admin", "--token-file", SECRETS + "/admin.token", "tenant", "relay", "enable", self.tenant)
        require(self.cli_json(server, "tenant", "capabilities")["relay_enabled"] is True, "admin relay enable failed")
        permissions = self.docker("exec", server, "stat", "-c", "%u:%g:%a", DB,
                     STATE + "/config/oheco-broker", STATE + "/config/oheco-broker/account.json").stdout.splitlines()
        require(permissions == ["10001:10001:600", "10001:10001:700", "10001:10001:600"], "SQLite/profile permissions are unsafe")
        print("PASS verified TLS/default CA trust, SQLite, admin authentication, approval/relay gates and C SDK CLI queries", flush=True)
        self.peers(server)
        # Persist a setting that disagrees with both startup defaults.
        self.api("PATCH", "/v1/admin/settings", token=self.admin,
                 body={"registration_policy": "closed", "registration_relay_enabled": True})
        elapsed = self.stop(server)
        snapshot = self.root / "control.sqlite"
        self.docker("cp", server + ":" + DB, snapshot)
        with sqlite3.connect(snapshot) as db:
            require(db.execute("PRAGMA integrity_check").fetchone() == ("ok",), "SQLite integrity check failed after TERM")
            require(db.execute("SELECT status,relay_enabled FROM tenants WHERE id=?", (self.tenant,)).fetchone() == ("active", 1), "account not persisted in SQLite")
        listen = urlsplit(self.api_url).netloc
        restarted = self.start(self.server_flags(listen))
        self.event(restarted, "server_ready")
        require(self.api("GET", "/v1/admin/settings", token=self.admin) ==
                {"registration_policy": "closed", "registration_relay_enabled": True}, "settings did not survive container recreation")
        account = self.cli_json(restarted, "tenant", "account", "show")
        require(account["tenant"]["id"] == self.tenant and account["tenant"]["status"] == "active", "saved account/token did not survive recreation")
        self.api("POST", "/v1/tenants/register", body={"name": "closed-account", "password": secrets.token_hex(16)}, expected=403)
        self.stop(restarted)
        print(f"PASS persisted SQLite/settings/profile across recreation and clean PID 1 TERM ({elapsed:.2f}s)", flush=True)
        self.low_port()

    def stun(self, address):
        host, port = address.rsplit(":", 1)
        transaction = secrets.token_bytes(12)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(3)
            client.sendto(struct.pack("!HHI", 1, 0, 0x2112A442) + transaction, (host, int(port)))
            response, source = client.recvfrom(2048)
        require(source == (host, int(port)) and len(response) >= 20 and
                struct.unpack("!HHI", response[:8])[0] == 0x0101 and response[8:20] == transaction, "actual UDP STUN Binding failed")

    def peers(self, server):
        password = secrets.token_hex(16)
        self.secrets.append(password)
        with echoes() as (tcp_port, udp_port):
            base = ["--api", self.api_url, "--ca-file", TLS + "/cert.pem"]
            broker = self.start(base + ["tenant", "serve", "--name", "docker-native-peer", "--password", password,
                        "--allow", f"tcp@127.0.0.1:{tcp_port}", "--allow", f"udp@127.0.0.1:{udp_port}"], entrypoint="oheco-broker")
            broker_id = self.event(broker, "broker_ready")["broker_id"]
            for mode in ("never", "force"):
                for protocol, port in (("tcp", tcp_port), ("udp", udp_port)):
                    peer = self.start(base + ["tenant", "connect", "--name", "docker-native-peer", "--password", password,
                                "--protocol", protocol, "--target", f"127.0.0.1:{port}", "--local", "0", "--relay", mode],
                                entrypoint="oheco-broker")
                    local = self.event(peer, "mapping_ready", timeout=75)["local"]
                    host, mapped = local.rsplit(":", 1)
                    if protocol == "tcp":
                        tcp_payload(host, int(mapped))
                    else:
                        udp_payload(host, int(mapped))
                    self.stop(peer)
                    print(f"PASS image native C SDK {protocol.upper()} payload/close with relay={mode}", flush=True)
            usage = self.cli_json(server, "tenant", "usage", "--broker", broker_id)
            require(usage["lifetime"] > 0, "forced TURN carried no accounted bytes")
            self.stop(broker)
            print("PASS actual Pion TURN relay payload accounting", flush=True)

    def low_port(self):
        # First enforce privileged ports in an isolated bridge netns. A host
        # sysctl of zero must not mask lost capabilities for the nonroot user.
        strict = self.start(self.server_flags("0.0.0.0:443", turn=False), cap=True, bridge=True)
        self.event(strict, "server_ready")
        self.check_process(strict, cap=True)
        threshold = self.docker("exec", strict, "cat", "/proc/sys/net/ipv4/ip_unprivileged_port_start").stdout.strip()
        require(threshold == "1024", "privileged-port probe did not enforce the kernel threshold")
        published = self.docker("port", strict, "443/tcp").stdout.strip()
        require(published.startswith("127.0.0.1:"), "strict TCP 443 probe was not published only on loopback")
        self.api_url = "https://" + published
        require(self.api("GET", "/v1/admin/info", token=self.admin)["storage"] == "sqlite3", "privileged bridge TCP 443 TLS request failed")
        self.stop(strict)
        print("PASS UID10001 privileged TCP 443 bind in bridge netns (threshold 1024, NET_BIND_SERVICE, no-new-privileges)", flush=True)
        # Then exercise the documented host-network deployment independently.
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", 443))
            except OSError as error:
                raise AssertionError("test runner TCP 443 must be available for the host-network capability probe") from error
        server = self.start(self.server_flags("127.0.0.1:443", turn=False), cap=True)
        ready = self.event(server, "server_ready")
        require(ready["api"] == "https://127.0.0.1:443", "nonroot service did not bind TCP 443")
        self.check_process(server, cap=True)
        self.api_url = ready["api"]
        require(self.api("GET", "/v1/admin/info", token=self.admin)["storage"] == "sqlite3", "TLS on TCP 443 failed")
        self.docker("exec", server, "/bin/sh", "-ec", """
            test "$(stat -c '%u:%g:%a' /var/lib/oheco-broker/acme)" = 10001:10001:700
            umask 077; printf smoke > /var/lib/oheco-broker/acme/.docker-smoke
        """)
        self.stop(server)
        again = self.start(self.server_flags("127.0.0.1:443", turn=False), cap=True)
        self.event(again, "server_ready")
        self.docker("exec", again, "/bin/sh", "-ec", "test \"$(cat /var/lib/oheco-broker/acme/.docker-smoke)\" = smoke; rm /var/lib/oheco-broker/acme/.docker-smoke")
        self.stop(again)
        print("PASS nonroot host-network TCP 443 with NET_BIND_SERVICE/no-new-privileges and persisted private ACME cache directory", flush=True)

    def cleanup(self):
        failures = []
        for name in reversed(self.names):
            result = self.docker("rm", "--force", "--volumes", name, check=False)
            if result.returncode and "No such container" not in result.stderr:
                failures.append(self.redact(result.stderr))
        # Chowned bind mounts cannot be removed by the host test user. Constrain
        # privileged removal to this mkdtemp-created directory, never host state.
        self.privileged("rm", "-rf", "--", self.root)
        require(not failures, "container cleanup failed: " + "; ".join(failures))


@contextmanager
def echoes():
    stopping = threading.Event()
    tcp, udp = socket.socket(), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp.bind(("127.0.0.1", 0))
    udp.bind(("127.0.0.1", 0))
    tcp.listen()
    tcp.settimeout(0.2)
    udp.settimeout(0.2)
    workers = []

    def stream(connection):
        with connection:
            connection.settimeout(10)
            try:
                while True:
                    data = connection.recv(32768)
                    if not data:
                        break
                    connection.sendall(data)
            except (OSError, TimeoutError):
                pass

    def tcp_echo():
        while not stopping.is_set():
            try:
                connection, _ = tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            worker = threading.Thread(target=stream, args=(connection,), daemon=True)
            workers.append(worker)
            worker.start()

    def udp_echo():
        while not stopping.is_set():
            try:
                data, source = udp.recvfrom(65535)
                udp.sendto(data, source)
            except socket.timeout:
                continue
            except OSError:
                return

    threads = [threading.Thread(target=tcp_echo, daemon=True), threading.Thread(target=udp_echo, daemon=True)]
    for thread in threads:
        thread.start()
    try:
        yield tcp.getsockname()[1], udp.getsockname()[1]
    finally:
        stopping.set()
        tcp.close()
        udp.close()
        for thread in threads + workers:
            thread.join(timeout=12)


def tcp_payload(host, port):
    payload = bytes(range(256)) * 4096
    received, errors = bytearray(), []
    with socket.create_connection((host, port), timeout=10) as client:
        client.settimeout(20)

        def read_all():
            try:
                while True:
                    data = client.recv(32768)
                    if not data:
                        return
                    received.extend(data)
            except OSError as error:
                errors.append(error)

        reader = threading.Thread(target=read_all, daemon=True)
        reader.start()
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        reader.join(timeout=25)
        require(not reader.is_alive() and not errors and bytes(received) == payload, "native TCP mapping corrupted 1MiB payload or FIN")


def udp_payload(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(15)
        for payload in (b"", b"docker-native-udp", secrets.token_bytes(65507)):
            client.sendto(payload, (host, port))
            response, _ = client.recvfrom(65535)
            require(response == payload, "native UDP mapping corrupted a zero/small/maximal datagram")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-arch", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--expected-version", default="0.3.0")
    parser.add_argument("--expected-revision", default="aecc2fd8247aec361e5573412b7bfd6e75a83127")
    args = parser.parse_args()
    require(platform.system() == "Linux" and architecture(platform.machine()) == args.expected_arch,
            "this test requires the expected native Linux host; OHOS/QEMU is not Linux image verification")
    for tool in ("docker", "openssl"):
        require(shutil.which(tool), "required host command is missing: " + tool)
    if os.geteuid() != 0:
        require(shutil.which("sudo"), "root or passwordless sudo is required for UID10001 fixture ownership")
    old_mask = os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix="oheco-docker-smoke-", dir=os.environ.get("TMPDIR")))
    smoke = Smoke(args, root)
    original_handlers = {}

    def terminate(signum, _frame):
        raise SystemExit(128 + signum)

    for signum in (signal.SIGINT, signal.SIGTERM):
        original_handlers[signum] = signal.signal(signum, terminate)
    try:
        public_bundle = smoke.inventory()
        smoke.prepare(public_bundle)
        smoke.control()
    except Exception as error:
        for name in smoke.names:
            try:
                print(smoke.redact(smoke.logs(name)), flush=True)
            except Exception:
                pass
        raise AssertionError(smoke.redact(str(error))) from None
    finally:
        for signum, handler in original_handlers.items():
            signal.signal(signum, handler)
        smoke.cleanup()
        os.umask(old_mask)
    print("PASS native Linux Docker image acceptance; all endpoints and persistent test assets were isolated and removed", flush=True)


if __name__ == "__main__":
    main()
