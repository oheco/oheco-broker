#!/usr/bin/env python3
"""Bounded HarmonyOS -> real public HTTPS/TURN acceptance, using the C-SDK Go CLI.

Only reads the explicitly selected existing profile. No registration, login,
account update, fixture, TLS bypass, or direct/localhost relay fallback exists.
Credentials are loaded in memory; peer passwords travel only through stdin.
"""
import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import resource
import secrets
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from public_options import https_origin, turn_address

SECRET_KEYS = {"token", "password", "device_token", "session_token", "credential",
               "password_hash", "admin_token", "tenant_token"}


class Failure(Exception):
    pass


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def private_profile(path, api):
    """Do not return or print any raw credential content in an exception."""
    for candidate, is_dir in ((path.parent, True), (path, False)):
        info = candidate.lstat()
        kind = stat.S_ISDIR(info.st_mode) if is_dir else stat.S_ISREG(info.st_mode)
        if not kind or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Failure("profile and parent must be private, owner-owned, non-symlinks")
        if not is_dir and (info.st_size > 65536 or info.st_nlink != 1):
            raise Failure("profile size/link safety check failed")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(fd, "rb") as file:
            raw = file.read(65537)
        profile = json.loads(raw)
    except (ValueError, UnicodeError):
        raise Failure("profile JSON invalid (content suppressed)") from None
    if profile.get("version") != 1 or profile.get("api") != api:
        raise Failure("profile must select the approved public HTTPS origin")
    account = profile.get("account", {})
    if not account.get("token") or not profile.get("ca_file"):
        raise Failure("existing account token and verified CA are required")
    if not Path(profile["ca_file"]).is_file():
        raise Failure("stored CA file missing")
    values = []
    def collect(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in SECRET_KEYS and isinstance(child, str) and child:
                    values.append(child)
                else:
                    collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)
    collect(profile)
    return profile, hashlib.sha256(raw).hexdigest(), values


class Redactor:
    def __init__(self, values):
        self.values = list(values)

    def text(self, text):
        for value in sorted(self.values, key=len, reverse=True):
            text = text.replace(value, "[secret-redacted]")
        text = re.sub(r'(?i)("(?:[a-z_]*token|password|credential|password_hash)"\s*:\s*)"[^"\n]*"',
                      r'\1"[secret-redacted]"', text)
        text = re.sub(r"(?i)(Bearer\s+)\S+", r"\1[secret-redacted]", text)
        return text


class Child:
    def __init__(self, command, env, cwd, password=None):
        self.lines = deque(maxlen=512)
        self.events = queue.Queue()
        self.process = subprocess.Popen(command, env=env, cwd=cwd,
            stdin=subprocess.PIPE if password else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        def read_output():
            try:
                for raw in iter(self.process.stdout.readline, b""):
                    line = raw.decode("utf-8", errors="replace")
                    self.lines.append(line[-16384:])
                    try:
                        value = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(value, dict) and "event" in value:
                        self.events.put(value)
            finally:
                self.process.stdout.close()
        self.reader = threading.Thread(target=read_output, daemon=True)
        self.reader.start()
        if password:
            try:
                self.process.stdin.write((password + "\n").encode())
                self.process.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                self.process.stdin.close()

    def log(self):
        return "".join(list(self.lines))[-32768:]

    def event(self, name, deadline):
        while time.monotonic() < deadline:
            try:
                value = self.events.get(timeout=min(.2, max(.001, deadline - time.monotonic())))
            except queue.Empty:
                if self.process.poll() is not None:
                    raise Failure(f"child exited {self.process.returncode} before {name}")
                continue
            if value.get("event") == name:
                return value
        raise Failure(f"timeout waiting for {name}")

    def join(self, timeout=1):
        self.reader.join(timeout=timeout)


class Echo:
    def __init__(self):
        self.stop = threading.Event()
        self.tcp = socket.socket()
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen(8)
        self.tcp.settimeout(.2)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.settimeout(.2)
        self.connections = []
        self.threads = []
        self.udp_observed = []
        self.ports = {"tcp": self.tcp.getsockname()[1], "udp": self.udp.getsockname()[1]}
        for target in (self.tcp_loop, self.udp_loop):
            self.thread(target)

    def thread(self, target, *args):
        worker = threading.Thread(target=target, args=args, daemon=True)
        self.threads.append(worker)
        worker.start()

    def handle(self, connection):
        with connection:
            connection.settimeout(10)
            try:
                while not self.stop.is_set():
                    data = connection.recv(32768)
                    if not data:
                        return
                    connection.sendall(data)
            except OSError:
                return

    def tcp_loop(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.tcp.accept()
                self.connections.append(connection)
                self.thread(self.handle, connection)
            except socket.timeout:
                continue
            except OSError:
                return

    def udp_loop(self):
        while not self.stop.is_set():
            try:
                data, source = self.udp.recvfrom(65535)
                self.udp_observed.append({"source_port": source[1], "bytes": len(data)})
                self.udp.sendto(data, source)
            except socket.timeout:
                continue
            except OSError:
                return

    def close(self):
        self.stop.set()
        for sock in [self.tcp, self.udp] + self.connections:
            sock.close()
        for worker in self.threads:
            worker.join(timeout=.4)


def force_guard_evidence(repo):
    """Source checks supplement runtime byte evidence, not binary attestation."""
    requirements = {
        "sdk/c/remote/peer/engine.c": ["!ob_force_path(p)",
            "juice_get_selected_candidates", "ob_relay_candidate(local, strlen(local))"],
        "sdk/c/remote/peer/control.c": ["config.relay_only = p->relay == OB_REMOTE_RELAY_FORCE"],
        "sdk/c/tpr/libjuice/src/agent.c": ["agent->config.relay_only && !selected_entry->relay_entry",
            "Relay-only policy forbids direct application sending"],
    }
    evidence = {}
    for name, patterns in requirements.items():
        path = repo / name
        content = path.read_text()
        if any(pattern not in content for pattern in patterns):
            raise Failure("current SDK lacks required FORCE send/selection guards")
        evidence[name] = sha256(path)
    return evidence


def usage_bytes(value):
    if value.get("unit") != "forwarded_payload_bytes":
        raise Failure("unexpected public server usage accounting unit")
    lifetime = value.get("lifetime")
    if not isinstance(lifetime, int) or lifetime < 0:
        raise Failure("public server usage missing nonnegative integer lifetime")
    return lifetime


def tcp_probe(address, index, deadline):
    payload = secrets.token_bytes(512 * 1024)
    with socket.create_connection(address, timeout=min(8, deadline - time.monotonic())) as client:
        client.settimeout(min(12, max(.1, deadline - time.monotonic())))
        received = bytearray()
        errors = []
        def reader():
            try:
                while True:
                    data = client.recv(32768)
                    if not data:
                        return
                    received.extend(data)
            except Exception as error:
                errors.append(type(error).__name__)
        worker = threading.Thread(target=reader, daemon=True)
        worker.start()
        source = client.getsockname()
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        worker.join(timeout=min(15, max(.1, deadline - time.monotonic())))
        if worker.is_alive() or errors or bytes(received) != payload:
            raise Failure(f"TCP source {index}: byte mismatch/FIN timeout ({len(received)}/{len(payload)})")
    return {"source_port": source[1], "bytes_each_direction": len(payload), "fin": True}


def udp_probe(address, index, deadline):
    # Exactly one application datagram per size, no retransmission to hide loss.
    # Continue after a failure to distinguish zero-length from all-size failure.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind(("127.0.0.1", 0))
        checks = []
        for size in (0, 513, 16384, 65507):
            payload = secrets.token_bytes(size)
            client.settimeout(min(4, max(.1, deadline - time.monotonic())))
            try:
                client.sendto(payload, address)
                response, source = client.recvfrom(65535)
                if source != address or response != payload:
                    raise Failure("datagram boundary/content mismatch")
                checks.append({"bytes": size, "passed": True})
            except Exception as error:
                checks.append({"bytes": size, "passed": False,
                    "error": f"UDP source {index}: {size}-byte {type(error).__name__}: {error}"})
        return {"source_port": client.getsockname()[1], "datagrams": checks,
                "passed": all(value["passed"] for value in checks)}


def quiet_udp_diagnostics(address, deadline, trials=10, spacing=.5, on_progress=None):
    """Delivery statistics, never a retransmission-based acceptance PASS.

    Each trial has its own source socket, held open to prevent source-port reuse.
    Warmup establishes a lazy flow before zero-length steady-state measurement.
    Nonzero replies must match a fresh transaction UUID and full random payload;
    zero replies are correlated by their unique source socket after warmup.
    """
    samples, warmups, clients = [], [], []

    def snapshot(complete=False):
        summary = {}
        for size in (0, 513, 16384, 65507):
            values = [sample for sample in samples if sample["bytes"] == size]
            latencies = [value["latency_ms"] for value in values if value["passed"]]
            summary[str(size)] = {"sent": len(values), "received": len(latencies),
                "lost_or_expired": len(values) - len(latencies),
                "latency_ms": {"min": min(latencies), "max": max(latencies),
                    "mean": round(sum(latencies) / len(latencies), 3)} if latencies else None}
        return {"mode": "quiet_after_tcp", "complete": complete, "trials_each_size": trials,
            "spacing_seconds": spacing, "receive_deadline_seconds": 2.5, "retransmissions": 0,
            "warmups": list(warmups), "samples": list(samples), "summary": summary,
            "strict_all_datagrams_delivered": complete and all(value["received"] == trials for value in summary.values())}

    def progress():
        if on_progress:
            on_progress(snapshot())

    def exchange(client, size, trial, warmup=False):
        transaction = uuid.uuid4()
        payload = transaction.bytes + secrets.token_bytes(size - 16) if size else b""
        sent = time.monotonic()
        receive_deadline = min(deadline, sent + 2.5)
        result = {"trial": trial, "bytes": size, "source_port": client.getsockname()[1],
            "transaction_id": str(transaction), "correlation": "full_payload_transaction_id" if size else "unique_source_port_after_warmup",
            "warmup": warmup, "passed": False, "unexpected_datagrams": 0}
        client.sendto(payload, address)
        while time.monotonic() < receive_deadline:
            client.settimeout(max(.001, receive_deadline - time.monotonic()))
            try:
                response, source = client.recvfrom(65535)
            except socket.timeout:
                break
            if source == address and response == payload:
                result.update(passed=True, latency_ms=round((time.monotonic() - sent) * 1000, 3))
                return result
            result["unexpected_datagrams"] += 1
        result["error"] = "no matching reply before 2.5-second receive deadline"
        return result

    def pause():
        remaining = deadline - time.monotonic()
        if remaining <= spacing:
            raise Failure("quiet diagnostic work budget exhausted")
        time.sleep(spacing)

    try:
        for trial in range(1, trials + 1):
            if time.monotonic() >= deadline:
                raise Failure("quiet diagnostic work budget exhausted")
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.bind(("127.0.0.1", 0))
            clients.append(client)
            warmup = exchange(client, 513, trial, warmup=True)
            warmups.append(warmup)
            progress()
            pause()
            for size in (0, 513, 16384, 65507):
                sample = exchange(client, size, trial)
                sample["warmup_passed"] = warmup["passed"]
                samples.append(sample)
                progress()
                pause()
    finally:
        for client in clients:
            client.close()
    return snapshot(complete=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help="Approved existing private tenant profile (read-only)")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--api", required=True, type=https_origin)
    parser.add_argument("--turn-address", required=True, type=turn_address)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=120, help="Whole-attempt limit including cleanup, 60-120 seconds")
    parser.add_argument("--skip-denied-target", action="store_true", help="Skip extra default-deny negative test")
    parser.add_argument("--udp-diagnostics", action="store_true", help="Quiet 10-trial UDP delivery statistics after TCP; not an acceptance PASS")
    args = parser.parse_args()
    if not 60 <= args.timeout <= 120:
        parser.error("timeout must be 60-120 seconds")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    started = time.monotonic()
    overall_deadline = started + args.timeout
    # Reserve 25s for simultaneous graceful shutdown (20s), kill, own metadata cleanup.
    work_deadline = overall_deadline - 25
    repo = Path(__file__).resolve().parent.parent
    profile_path = Path(os.path.abspath(args.profile))  # Keep symlinks detectable by lstat.
    binary = Path(args.binary).resolve()
    report = {"event": "public_acceptance_result", "status": "failed", "api": args.api,
        "turn_address": args.turn_address, "relay_mode": "force", "same_device_peers": True,
        "cross_nat_proven": False, "relay_pool_configured": None,
        "relay_pool_all_ports_tested": False, "selected_candidate_port_observed": False,
        "account_created": False, "profile_modified": False, "acceptance_pass_claimed": False, "checks": []}
    children = []
    redactor = Redactor([])
    stage = "profile_and_native_provenance"
    broker_id = None
    echo = None
    root = None
    base = None
    env = None

    def emit(name, **value):
        item = {"event": "public_acceptance_check", "check": name, "source": "actual_public_server", **value}
        report["checks"].append(item)
        print(redactor.text(json.dumps(item, sort_keys=True)), flush=True)

    def budget(maximum=10, cleanup=False):
        end = overall_deadline if cleanup else work_deadline
        remaining = end - time.monotonic()
        if remaining <= .1:
            raise Failure("whole-attempt time budget exhausted")
        return min(maximum, remaining)

    def run_json(arguments, cleanup=False):
        result = subprocess.run(base + arguments, env=env, cwd=root, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=budget(12, cleanup))
        if result.returncode:
            raise Failure(f"CLI returned {result.returncode}: " + redactor.text(result.stdout + result.stderr)[-4096:])
        try:
            return json.loads(result.stdout) if result.stdout.strip() else {}
        except ValueError:
            raise Failure("CLI response was not JSON (content suppressed)") from None

    def start(arguments, label, password):
        child = Child(base + arguments, env, root, password)
        children.append((label, child))
        return child

    def stop_many(selected, cleanup=False):
        for child in selected:
            if child.process.poll() is None:
                child.process.send_signal(signal.SIGTERM)
        deadline = time.monotonic() + budget(20, cleanup)
        for child in selected:
            if child.process.poll() is None:
                try:
                    child.process.wait(timeout=max(.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    child.process.kill()
                    child.process.wait(timeout=2)
                    raise Failure("test-owned CLI required SIGKILL after shutdown deadline")
            child.join()

    def interrupted(signum, _frame):
        raise Failure(f"interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)

    with tempfile.TemporaryDirectory(prefix="broker-public-acceptance-", dir=os.environ["TMPDIR"]) as directory:
        root = Path(directory)
        try:
            profile, original_digest, secret_values = private_profile(profile_path, args.api)
            peer_password = secrets.token_hex(32)
            redactor.values.extend(secret_values + [peer_password])
            # A private file documents controlled secret handling, but CLI gets only stdin.
            password_file = root / "peer-password"
            password_file.write_text(peer_password + "\n")
            if password_file.stat().st_mode & 0o077 or root.stat().st_mode & 0o077:
                raise Failure("temporary filesystem cannot protect test credentials")
            report["binary_sha256"] = sha256(binary)
            report["force_guard_source_sha256"] = force_guard_evidence(repo)
            report["force_guard_evidence"] = "current-source selected LOCAL relay + atomic libjuice send guard; not binary attestation"
            env = dict(os.environ)
            for key in list(env):
                if key.upper().endswith("_PROXY") or key.startswith("OHECO_BROKER_") or key.startswith("OB_"):
                    env.pop(key, None)
            env.update(TMPDIR=str(root), XDG_CONFIG_HOME=str(root / "unused-config"),
                       NO_PROXY="*", no_proxy="*")
            base = [str(binary), "--api", args.api, "--config", str(profile_path)]
            stage = "public_verified_https_capabilities"
            caps = run_json(["tenant", "capabilities"])
            if caps.get("status") != "active" or caps.get("relay_enabled") is not True or caps.get("turn_available") is not True:
                raise Failure("approved tenant is not active and relay-enabled on real server")
            if caps.get("turn_address") != args.turn_address or caps.get("stun_address") != args.turn_address:
                raise Failure("public server advertised unexpected TURN/STUN endpoint")
            emit("verified_https_existing_tenant", turn_address=caps["turn_address"], relay_enabled=True)
            stage = "public_tenant_usage_before"
            before = usage_bytes(run_json(["tenant", "usage"]))
            report["tenant_lifetime_before"] = before
            echo = Echo()
            broker_name = "public-hos-test-" + str(uuid.uuid4())
            report["broker_name"] = broker_name
            report["echo_targets"] = {protocol: f"127.0.0.1:{port}" for protocol, port in echo.ports.items()}
            stage = "public_broker_serve"
            broker = start(["tenant", "serve", "--name", broker_name, "--password-stdin",
                "--allow", f"tcp@127.0.0.1:{echo.ports['tcp']}",
                "--allow", f"udp@127.0.0.1:{echo.ports['udp']}"], "broker", peer_password)
            ready = broker.event("broker_ready", min(work_deadline, time.monotonic() + 25))
            broker_id = ready["broker_id"]
            report["broker_id"] = broker_id
            if ready.get("name") != broker_name or ready.get("allow_rules") != 2:
                raise Failure("SDK broker did not confirm exact two-rule allowlist")
            emit("public_broker_ready", broker_id=broker_id, allow_rules=2, default_deny=True)
            stage = "public_broker_usage_before"
            broker_before = usage_bytes(run_json(["tenant", "usage", "--broker", broker_id]))
            if broker_before != 0:
                raise Failure("new unique broker unexpectedly already has usage")
            connectors = {}
            for protocol, port in echo.ports.items():
                connectors[protocol] = start(["tenant", "connect", "--broker-id", broker_id,
                    "--password-stdin", "--protocol", protocol, "--target", f"127.0.0.1:{port}",
                    "--local", "127.0.0.1:0", "--relay", "force"], "mapping-" + protocol, peer_password)
            setup_deadline = min(work_deadline, time.monotonic() + 40)
            addresses = {}
            for protocol, child in connectors.items():
                stage = "public_force_" + protocol + "_mapping_setup"
                mapping = child.event("mapping_ready", setup_deadline)
                if mapping.get("relay_mode") != "force" or mapping.get("broker_id") != broker_id:
                    raise Failure("mapping did not confirm FORCE and expected broker")
                host, port = mapping["local"].rsplit(":", 1)
                if host != "127.0.0.1" or not 0 < int(port) < 65536:
                    raise Failure("mapping must bind random loopback port")
                addresses[protocol] = (host, int(port))
                emit("public_force_" + protocol + "_mapping_ready", local=mapping["local"], relay_mode="force")
            stage = "public_force_tcp_udp_payload_and_fin"
            results, errors = {}, []
            def probe(protocol, index):
                try:
                    results[(protocol, index)] = (tcp_probe if protocol == "tcp" else udp_probe)(addresses[protocol], index, work_deadline)
                except Exception as error:
                    errors.append(f"{protocol} source {index}: {type(error).__name__}: {error}")
            protocols = ("tcp",) if args.udp_diagnostics else ("tcp", "udp")
            workers = [threading.Thread(target=probe, args=(protocol, index), daemon=True)
                       for protocol in protocols for index in (1, 2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=budget(18))
            if any(worker.is_alive() for worker in workers):
                raise Failure("payload worker time budget expired")
            payload_errors = list(errors)
            for protocol in protocols:
                values = [results[(protocol, index)] for index in (1, 2) if (protocol, index) in results]
                if len(values) == 2 and values[0]["source_port"] == values[1]["source_port"]:
                    raise Failure("multi-source probes unexpectedly reused source port")
                if protocol == "udp":
                    payload_errors.extend(datagram["error"] for value in values
                        for datagram in value["datagrams"] if not datagram["passed"])
                passed = len(values) == 2 and all(value.get("passed", True) for value in values)
                emit("public_force_" + protocol + "_payload", passed=passed, sources=values)
            if args.udp_diagnostics:
                stage = "public_force_quiet_udp_delivery_diagnostics"
                progress_directory = args.output_dir.resolve()
                progress_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                progress_file = progress_directory / ("udp-progress-" + uuid.uuid4().hex + ".json")
                report["udp_diagnostic_progress_path"] = str(progress_file)
                def checkpoint(value):
                    report["udp_delivery_diagnostics"] = value
                    temporary = root / "udp-progress.pending"
                    progress_report = dict(report)
                    progress_report["status"] = "measurements_completed_cleanup_pending" if value["complete"] else "measurements_in_progress"
                    temporary.write_text(redactor.text(json.dumps({"event": "public_udp_diagnostic_progress",
                        "status": "completed" if value["complete"] else "in_progress", "result": progress_report}, indent=2)) + "\n")
                    os.replace(temporary, progress_file)
                time.sleep(min(1, budget(1)))
                diagnostics = quiet_udp_diagnostics(addresses["udp"], work_deadline, on_progress=checkpoint)
                report["udp_delivery_diagnostics"] = diagnostics
                checkpoint(diagnostics)
                emit("public_force_quiet_udp_delivery_counts", summary=diagnostics["summary"],
                     warmup_sent=len(diagnostics["warmups"]),
                     warmup_received=sum(value["passed"] for value in diagnostics["warmups"]),
                     retransmissions=0, acceptance_pass_claimed=False)
            report["udp_echo_observed"] = list(echo.udp_observed)
            stage = "public_force_connector_close"
            stop_many(list(connectors.values()))
            if any(child.process.returncode for child in connectors.values()):
                raise Failure("FORCE connector did not shut down cleanly")
            if not args.skip_denied_target:
                stage = "default_deny_unlisted_target"
                denied_socket = socket.socket()
                denied_socket.bind(("127.0.0.1", 0))
                denied_port = denied_socket.getsockname()[1]
                denied_socket.listen(1)
                try:
                    denied = start(["tenant", "connect", "--broker-id", broker_id, "--password-stdin",
                        "--protocol", "tcp", "--target", f"127.0.0.1:{denied_port}", "--local", "0",
                        "--relay", "force"], "denied-target", peer_password)
                    # Maps are lazy: target policy is applied when a real flow opens,
                    # not when the connector creates its local listening socket.
                    denied_ready = denied.event("mapping_ready", min(work_deadline, time.monotonic() + 35))
                    host, local_port = denied_ready["local"].rsplit(":", 1)
                    if host != "127.0.0.1" or denied_ready.get("relay_mode") != "force":
                        raise Failure("negative mapping not loopback/FORCE")
                    with socket.create_connection((host, int(local_port)), timeout=budget(5)) as probe:
                        probe.settimeout(budget(5))
                        probe.sendall(b"public-default-deny-probe")
                        try:
                            response = probe.recv(128)
                        except (ConnectionResetError, BrokenPipeError):
                            response = b""
                        if response:
                            raise Failure("unlisted target flow returned unexpected data")
                    stop_many([denied])
                    if denied.process.returncode:
                        raise Failure("negative connector did not shut down cleanly")
                    denied_socket.settimeout(.25)
                    try:
                        connection, _ = denied_socket.accept()
                    except socket.timeout:
                        connection = None
                    if connection:
                        connection.close()
                        raise Failure("unlisted loopback target received a connection")
                    emit("default_deny_unlisted_target", target=f"127.0.0.1:{denied_port}",
                         denied=True, flow_closed_without_data=True, target_contacted=False)
                finally:
                    denied_socket.close()
            stage = "public_server_actual_relay_usage"
            broker_after = usage_bytes(run_json(["tenant", "usage", "--broker", broker_id]))
            after = usage_bytes(run_json(["tenant", "usage"]))
            if broker_after <= broker_before or after <= before:
                raise Failure("real public server did not account positive forwarded relay payload bytes")
            report.update(tenant_lifetime_after=after, tenant_bytes_delta=after - before,
                          broker_lifetime_bytes=broker_after, broker_bytes_delta=broker_after - broker_before)
            emit("actual_public_turn_forwarded_bytes", unit="forwarded_payload_bytes",
                 tenant_delta=after - before, broker_delta=broker_after - broker_before)
            if payload_errors:
                stage = "public_force_payload_" + ("udp_datagrams" if not errors else "tcp_or_udp")
                raise Failure("; ".join(payload_errors))
            report["status"] = "diagnostics_completed" if args.udp_diagnostics else "passed"
            report["acceptance_pass_claimed"] = not args.udp_diagnostics
            report["validation_scope"] = "real public HTTPS + TURN forced data; two peers on one HarmonyOS device; NOT cross-NAT"
        except Exception as error:
            report["failure_stage"] = stage
            report["error"] = redactor.text(f"{type(error).__name__}: {error}")[-4096:]
            if "payload_errors" in locals() and payload_errors and not stage.startswith("public_force_payload_"):
                report["secondary_failure"] = {"stage": stage, "error": report["error"]}
                report["failure_stage"] = "public_force_payload_tcp_or_udp" if errors else "public_force_payload_udp_datagrams"
                report["error"] = redactor.text("; ".join(payload_errors))[-4096:]
        finally:
            # Stop only explicitly owned child handles, never pgrep/user sessions.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            cleanup_errors = []
            try:
                stop_many([child for _, child in children], cleanup=True)
            except Exception as error:
                cleanup_errors.append(redactor.text(str(error)))
                for _, child in children:
                    if child.process.poll() is None:
                        child.process.kill()
                        try:
                            child.process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            cleanup_errors.append("test-owned child did not exit after kill")
            if echo:
                report["udp_echo_observed"] = list(echo.udp_observed)
                echo.close()
            if base and env and broker_id and "broker_lifetime_bytes" not in report:
                try:
                    broker_after = usage_bytes(run_json(["tenant", "usage", "--broker", broker_id], cleanup=True))
                    after = usage_bytes(run_json(["tenant", "usage"], cleanup=True))
                    report.update(broker_lifetime_bytes=broker_after, tenant_lifetime_after=after)
                    if "before" in locals():
                        report["tenant_bytes_delta"] = after - before
                    if "broker_before" in locals():
                        report["broker_bytes_delta"] = broker_after - broker_before
                except Exception as error:
                    report["usage_diagnostic_error"] = redactor.text(str(error))[-2048:]
            if base and env:
                try:
                    # Recover own unique registration if startup failed before ready event.
                    if not broker_id and report.get("broker_name"):
                        brokers = run_json(["tenant", "broker", "list"], cleanup=True).get("brokers", [])
                        matches = [value["id"] for value in brokers if value.get("name") == report["broker_name"]]
                        if len(matches) == 1:
                            broker_id = matches[0]
                            report["broker_id"] = broker_id
                    if broker_id:
                        run_json(["tenant", "broker", "delete", broker_id], cleanup=True)
                        remaining = run_json(["tenant", "broker", "list"], cleanup=True).get("brokers", [])
                        if any(value.get("id") == broker_id for value in remaining):
                            raise Failure("owned broker metadata remained after deletion")
                        report["broker_deleted"] = True
                except Exception as error:
                    cleanup_errors.append(redactor.text(str(error))[-2048:])
            if "original_digest" in locals():
                report["profile_modified"] = sha256(profile_path) != original_digest
                if report["profile_modified"]:
                    cleanup_errors.append("existing profile bytes changed")
            report["child_exit_codes"] = {label: child.process.poll() for label, child in children}
            report["cleanup_errors"] = cleanup_errors
            if cleanup_errors:
                if report["status"] in ("passed", "diagnostics_completed"):
                    report["failure_stage"] = "cleanup"
                report["status"] = "failed"
                report["acceptance_pass_claimed"] = False
            report["elapsed_seconds"] = round(time.monotonic() - started, 3)
            logs = {label: redactor.text(child.log()) for label, child in children}
            # Preserve only bounded redacted diagnostics, never profile/password/tempdir.
            artifacts = args.output_dir.resolve()
            artifacts.mkdir(parents=True, exist_ok=True, mode=0o700)
            artifact = artifacts / ("result-" + uuid.uuid4().hex + ".json")
            artifact.write_text(redactor.text(json.dumps({"result": report, "redacted_child_logs": logs}, indent=2)) + "\n")
            display = dict(report)
            if "udp_delivery_diagnostics" in display:
                diagnostic = display["udp_delivery_diagnostics"]
                display["udp_delivery_diagnostics"] = {key: value for key, value in diagnostic.items()
                    if key not in ("samples", "warmups")}
                display["udp_delivery_diagnostics"]["warmup_sent"] = len(diagnostic["warmups"])
                display["udp_delivery_diagnostics"]["warmup_received"] = sum(value["passed"] for value in diagnostic["warmups"])
                observed = display.pop("udp_echo_observed", [])
                display["udp_echo_observed_counts"] = {str(size): sum(value["bytes"] == size for value in observed)
                    for size in (0, 513, 16384, 65507)}
            print(redactor.text(json.dumps(display, sort_keys=True)), flush=True)
            print(json.dumps({"event": "public_acceptance_artifact", "path": str(artifact)}), flush=True)
    return 0 if report["status"] in ("passed", "diagnostics_completed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
