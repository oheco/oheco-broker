#!/usr/bin/env python3
"""Stdlib-only adversarial wire tests against a built/signed C smoke executable.
Usage: python3 tests/c/protocol_test.py /absolute/path/to/broker-smoke
No real broker is needed. All files are isolated under TMPDIR and removed.
"""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

MAGIC = b"OHECOB1\n"


def frame(kind, payload=b""):
    return bytes([kind]) + struct.pack("!I", len(payload)) + payload


def exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise RuntimeError("unexpected client EOF")
        data += chunk
    return data


def wire_test(binary, root, name, reply, expected=None, handshake=True, delay=0,
              mode="run", chunk_delay=0.01):
    failures = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    endpoint = root / "endpoint"
    endpoint.write_text(f"127.0.0.1:{listener.getsockname()[1]}\n")

    def serve():
        try:
            with listener:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(5)
                    assert exact(conn, 8) == MAGIC
                    if not handshake:
                        time.sleep(delay)
                        if reply:
                            conn.sendall(reply)
                        return
                    conn.sendall(MAGIC)
                    header = exact(conn, 5)
                    assert header[0] == 1
                    size = struct.unpack("!I", header[1:])[0]
                    assert size <= 1048576
                    exact(conn, size)
                    time.sleep(delay)
                    if isinstance(reply, list):
                        for part in reply:
                            conn.sendall(part)
                            time.sleep(chunk_delay)
                    elif reply:
                        conn.sendall(reply)
        except (BrokenPipeError, ConnectionResetError):
            pass  # Negative tests intentionally close immediately.
        except Exception as exc:
            failures.append(exc)

    worker = threading.Thread(target=serve)
    worker.start()
    started = time.monotonic()
    command = [binary, mode, str(endpoint)] + (["/unused"] if mode == "run" else [])
    proc = subprocess.run(command, capture_output=True, timeout=10)
    elapsed = time.monotonic() - started
    worker.join(timeout=10)
    assert not worker.is_alive() and not failures, (name, failures)
    if expected:
        assert proc.returncode == 1 and expected.encode() in proc.stderr, (name, proc)
    else:
        assert proc.returncode == 0, (name, proc)
    print(f"PASS {name} ({elapsed:.2f}s)")
    return proc, elapsed


def main():
    binary = os.path.abspath(sys.argv[1])
    assert os.environ.get("TMPDIR"), "Set TMPDIR explicitly"
    with tempfile.TemporaryDirectory(prefix="ob-c-wire-", dir=os.environ["TMPDIR"]) as temporary:
        root = Path(temporary)
        for value in [b"", b"127.0.0.1:0", b"127.0.0.1:65536", b"localhost:123", b"127.0.0.2:1",
                      b"127.0.0.1:1\n\n", b"127.0.0.1:1\x00", b"127.0.0.1: 1", b"x" * 65]:
            endpoint = root / "invalid"
            endpoint.write_bytes(value)
            proc = subprocess.run([binary, "discovery", str(endpoint)], capture_output=True, timeout=5)
            assert proc.returncode == 0 and b"UNAVAILABLE" in proc.stdout, proc
        # Bind but do not listen: reliably refuse without assuming an unused port.
        with socket.socket() as closed_port:
            closed_port.bind(("127.0.0.1", 0))
            endpoint.write_text(f"127.0.0.1:{closed_port.getsockname()[1]}\r\n")
            proc = subprocess.run([binary, "discovery", str(endpoint)], capture_output=True, timeout=5)
            assert proc.returncode == 0 and b"stage=connect" in proc.stdout, proc
        print("PASS malformed discovery and refused connect -> UNAVAILABLE")
        started = frame(2)
        exited = frame(8, struct.pack("!III", 0, 0, 0))
        proc, _ = wire_test(binary, root, "fragmented binary streams", [bytes([b]) for b in started + frame(5, b"a\x00b") + frame(6, b"err") + exited])
        assert proc.stdout == b"a\x00b" and proc.stderr == b"err", proc
        resumable = frame(5, b"resume")
        for split in (2, 7):
            wire_test(binary, root, f"resume partial frame at {split}",
                      [started + resumable[:split], resumable[split:] + exited],
                      mode="resume", chunk_delay=0.1)
        tests = [
            ("output before STARTED", frame(5, b"bad"), "PROTOCOL"),
            ("oversize frame", started + bytes([5]) + struct.pack("!I", 1048577), "PROTOCOL"),
            ("oversize stream", started + bytes([5]) + struct.pack("!I", 65537), "PROTOCOL"),
            ("empty stream", started + frame(5), "PROTOCOL"),
            ("unknown frame", started + frame(255), "PROTOCOL"),
            ("duplicate STARTED", started + started, "PROTOCOL"),
            ("invalid EXIT", started + frame(8, struct.pack("!III", 0, 256, 0)), "PROTOCOL"),
            ("invalid ERROR UTF-8", frame(9, struct.pack("!II", 3, 3) + b"\xed\xa0\x80"), "PROTOCOL"),
            ("ERROR trailing data", frame(9, struct.pack("!II", 3, 0) + b"x"), "PROTOCOL"),
            ("startup ERROR", frame(9, struct.pack("!II", 3, 6) + b"failed"), "SPAWN_FAILED"),
            ("post-start ERROR", started + frame(9, struct.pack("!II", 7, 0)), "IO"),
            ("post-start disconnect", started, "CONNECTION_LOST"),
        ]
        for name, reply, expected in tests:
            wire_test(binary, root, name, reply, expected)
        wire_test(binary, root, "wrong handshake", b"BADMAGIC", "PROTOCOL", handshake=False)
        _, elapsed = wire_test(binary, root, "handshake deadline", b"", "PROTOCOL", handshake=False, delay=3.3)
        assert 2.8 <= elapsed < 4.5, elapsed
        _, elapsed = wire_test(binary, root, "START response deadline", b"", "TIMEOUT", delay=3.3)
        assert 2.8 <= elapsed < 4.5, elapsed
    print("All C protocol fixtures passed")


if __name__ == "__main__":
    main()
