#!/usr/bin/env python3
"""Native lifecycle acceptance: BINARY C_SMOKE [--legacy-binary PATH] [--legacy-client PATH]."""
import argparse
import errno
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time


def live(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return fields[0] not in ("Z", "X")
    except (OSError, IndexError) as error:
        # OHOS /proc may return EINVAL while an orphan is being reaped.
        if isinstance(error, OSError) and error.errno not in (errno.ENOENT, errno.ESRCH, errno.EINVAL):
            raise
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", type=lambda p: str(Path(p).resolve()))
    ap.add_argument("client", type=lambda p: str(Path(p).resolve()))
    ap.add_argument("--legacy-binary", type=lambda p: str(Path(p).resolve()))
    ap.add_argument("--legacy-client", type=lambda p: str(Path(p).resolve()))
    args = ap.parse_args()
    shell = shutil.which("zsh") or shutil.which("sh")
    sleeper = shutil.which("sleep")
    assert shell and sleeper and os.environ.get("TMPDIR")
    with tempfile.TemporaryDirectory(prefix="broker-lifecycle-", dir=os.environ["TMPDIR"]) as directory:
        root = Path(directory)
        home = root / "home"
        home.mkdir()
        endpoint = home / ".oheco/broker/endpoint"
        processes, detached = [], set()
        serial = 0

        def environment(cache):
            return dict(os.environ, HOME=str(home), XDG_CACHE_HOME=str(root / cache), TMPDIR=str(root))

        def launch(cache="cache", binary=None):
            nonlocal serial
            serial += 1
            with (root / f"broker-{serial}.log").open("wb") as log:
                p = subprocess.Popen([binary or args.binary], env=environment(cache), cwd=root,
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
            processes.append(p)
            return p

        def ready(p):
            end = time.monotonic() + 8
            while time.monotonic() < end:
                assert p.poll() is None, f"broker exited {p.returncode}; logs: {[x.read_text() for x in root.glob('broker-*.log')]}"
                if endpoint.exists():
                    try:
                        host, port = endpoint.read_text().strip().split(":")
                        assert host == "127.0.0.1"
                        with socket.create_connection((host, int(port)), timeout=.3) as c:
                            c.settimeout(.3)
                            c.sendall(b"OHECOB1\n")
                            reply = b""
                            while len(reply) < 8:
                                chunk = c.recv(8 - len(reply))
                                if not chunk: break
                                reply += chunk
                            if reply == b"OHECOB1\n": return
                    except (OSError, ValueError, AssertionError):
                        pass
                time.sleep(.03)
            raise AssertionError("broker did not become ready")

        def stop(p, crash=False):
            if p.poll() is None:
                p.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
            code = p.wait(timeout=8)
            assert code == (-signal.SIGKILL if crash else 0), code

        def client(command):
            result = subprocess.run(command, cwd=root, env=environment("client-cache"),
                                    capture_output=True, timeout=12)
            assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
            return result.stdout

        try:
            p = launch(); ready(p)
            saved = endpoint.read_bytes()
            for cache in ("cache", "other-cache", "yet-another-cache"):
                duplicate = subprocess.run([args.binary], env=environment(cache), cwd=root,
                                           capture_output=True, timeout=8)
                assert duplicate.returncode == 0 and b"already running" in duplicate.stdout, duplicate
                assert endpoint.read_bytes() == saved and p.poll() is None
            print("PASS duplicate startup exits 0 across private caches; endpoint unchanged", flush=True)
            if args.legacy_client:
                assert client([args.legacy_client, "run", str(endpoint), shell, "-c", "printf legacy-client"]) == b"legacy-client"
                print("PASS released 0.1.0 C client talks to 0.2.0 service", flush=True)

            log = root / "detached.log"
            log.write_text("seed\n")
            script = 'if IFS= read -r line; then exit 77; fi; printf "ready\\n"; printf "stderr\\n" >&2; exec "$1" 120'
            result = client([args.client, "detached", str(endpoint), shell, "detached.log", "detached.log", "-c", script, "smoke", sleeper])
            pid = int(result.strip()); assert pid > 0; detached.add(pid)
            end = time.monotonic() + 5
            while time.monotonic() < end and "stderr\n" not in log.read_text(): time.sleep(.02)
            assert log.read_text() == "seed\nready\nstderr\n", log.read_text()
            assert live(pid) and os.getpgid(pid) == pid and os.getsid(pid) == pid
            stop(p); assert not endpoint.exists(); time.sleep(.1); assert live(pid)
            print("PASS C detached ACK/disconnect, null stdin, relative append logs, new session and broker-exit survival", flush=True)

            p = launch("new-cache"); ready(p); assert live(pid)
            stop(p, crash=True)
            assert endpoint.exists(), "SIGKILL should leave a stale endpoint for recovery test"
            p = launch("crash-recovery-cache"); ready(p); stop(p)
            print("PASS kernel releases instance guard on crash; stale endpoint recovered", flush=True)

            contenders = [launch(f"parallel-{i}") for i in range(8)]
            end = time.monotonic() + 10
            while time.monotonic() < end and sum(x.poll() is None for x in contenders) != 1: time.sleep(.04)
            winners = [x for x in contenders if x.poll() is None]
            assert len(winners) == 1 and all(x.poll() == 0 for x in contenders if x not in winners), [x.poll() for x in contenders]
            ready(winners[0]); stop(winners[0])
            print("PASS 8 concurrent starts across distinct caches produce exactly one service", flush=True)

            fake = socket.socket(); fake.bind(("127.0.0.1", 0)); fake.listen(); fake.settimeout(.1)
            halt = threading.Event()
            def fake_server():
                while not halt.is_set():
                    try:
                        c, _ = fake.accept()
                        with c: c.settimeout(.3); c.recv(8); c.sendall(b"NOTBROK\n")
                    except OSError: pass
            thread = threading.Thread(target=fake_server, daemon=True); thread.start()
            try:
                endpoint.write_text(f"127.0.0.1:{fake.getsockname()[1]}\n")
                p = launch("wrong-protocol-cache"); ready(p); stop(p)
            finally:
                halt.set(); fake.close(); thread.join(timeout=2)
            endpoint.write_text("malformed endpoint")
            p = launch("malformed-cache"); ready(p); stop(p)
            print("PASS non-broker listener and malformed discovery do not produce false success", flush=True)

            bad_cache = root / "not-a-directory"; bad_cache.write_text("file")
            failed = subprocess.run([args.binary], env=environment("not-a-directory"), cwd=root, capture_output=True, timeout=8)
            assert failed.returncode != 0 and b"already running" not in failed.stdout, failed
            print("PASS genuine startup failure remains nonzero", flush=True)

            if args.legacy_binary:
                old = launch("legacy-cache", args.legacy_binary); ready(old)
                saved = endpoint.read_bytes()
                duplicate = subprocess.run([args.binary], env=environment("new-again-cache"), cwd=root, capture_output=True, timeout=8)
                assert duplicate.returncode == 0 and endpoint.read_bytes() == saved
                assert client([args.client, "run", str(endpoint), shell, "-c", "printf new-managed-client"]) == b"new-managed-client"
                refused = subprocess.run([args.client, "detached", str(endpoint), sleeper, "", "", "1"], env=environment("client-cache"), capture_output=True, timeout=8)
                assert refused.returncode != 0 and b"PROTOCOL" in refused.stderr, refused
                stop(old)
                print("PASS live 0.1.0 detection, new managed client compatibility and detached safe refusal", flush=True)
        finally:
            for p in processes:
                if p.poll() is None:
                    p.terminate()
                    try: p.wait(timeout=5)
                    except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=3)
            for pid in detached:
                if live(pid):
                    try: os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError: pass
            # Detached grandchildren are reparented; wait for kernel reaping before
            # removing the log directory, but do not depend on being their parent.
            end = time.monotonic() + 3
            while any(live(pid) for pid in detached) and time.monotonic() < end: time.sleep(.02)
            assert not any(live(pid) for pid in detached), "test-owned detached process survived cleanup"
    print("PASS lifecycle acceptance; temporary state and test-owned services cleaned", flush=True)


if __name__ == "__main__":
    main()
