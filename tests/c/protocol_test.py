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
DETACHED_MAGIC = b"OHECOB2\n"


def string(value):
    data = value.encode("utf-8")
    return struct.pack("!I", len(data)) + data


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
              mode="run", chunk_delay=0.01, log_paths=("日志/输出", "")):
    failures = []
    detached = mode == "detached"
    magic = DETACHED_MAGIC if detached else MAGIC
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
                    assert exact(conn, 8) == magic
                    if not handshake:
                        time.sleep(delay)
                        if reply:
                            conn.sendall(reply)
                        conn.shutdown(socket.SHUT_WR)
                        assert conn.recv(1) == b"", "START sent after failed greeting"
                    else:
                        # Fragment the detached greeting as well as selected ACKs.
                        for part in ([magic[:3], magic[3:]] if detached else [magic]):
                            conn.sendall(part)
                        header = exact(conn, 5)
                        assert header[0] == (10 if detached else 1)
                        size = struct.unpack("!I", header[1:])[0]
                        assert size <= 1048576
                        payload = exact(conn, size)
                        if detached:
                            wanted = (string("/unused") + string("") + struct.pack("!I", 2)
                                      + string("参数-🚀") + string("") + struct.pack("!I", 0)
                                      + b"\0" + string(log_paths[0]) + string(log_paths[1]))
                            assert payload == wanted, "detached START encoding changed"
                        time.sleep(delay)
                        if isinstance(reply, list):
                            for part in reply:
                                conn.sendall(part)
                                time.sleep(chunk_delay)
                        elif reply:
                            conn.sendall(reply)
                        if detached:
                            if not reply or (isinstance(reply, bytes) and len(reply) < 9):
                                conn.shutdown(socket.SHUT_WR)
                            assert conn.recv(1) == b"", "client sent control/fallback or waited for EOF"
                # A second connection must never be used to retry or fall back.
                listener.settimeout(0.2)
                try:
                    retry, _ = listener.accept()
                except socket.timeout:
                    pass
                else:
                    retry.close()
                    raise AssertionError("unexpected retry/managed fallback connection")
        except (BrokenPipeError, ConnectionResetError):
            pass  # Negative tests intentionally close immediately.
        except Exception as exc:
            failures.append(exc)

    worker = threading.Thread(target=serve)
    worker.start()
    started = time.monotonic()
    command = [binary, mode, str(endpoint)]
    if mode == "run":
        command += ["/unused"]
    elif detached:
        command += ["/unused", *log_paths, "参数-🚀", ""]
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
        for target in [root / "missing", root, endpoint]:
            proc = subprocess.run([binary, "detached", str(target), "/unused", "", ""],
                                  capture_output=True, timeout=5)
            assert proc.returncode == 1 and b": UNAVAILABLE stage=" in proc.stderr, proc
        for value in [b"", b"127.0.0.1:0", b"localhost:123", b"127.0.0.1:1\x00", b"x" * 65]:
            endpoint.write_bytes(value)
            proc = subprocess.run([binary, "detached", str(endpoint), "/unused", "", ""],
                                  capture_output=True, timeout=5)
            assert proc.returncode == 1 and b": UNAVAILABLE stage=discovery" in proc.stderr, proc
        print("PASS managed/detached discovery and refused connect -> UNAVAILABLE")
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
        ack = frame(11, struct.pack("!I", 12345))
        proc, _ = wire_test(binary, root, "detached fragmented ACK and client close",
                            [bytes([b]) for b in ack], mode="detached")
        assert proc.stdout == b"12345\n" and not proc.stderr, proc
        for pid in (1, 2147483647):
            proc, _ = wire_test(binary, root, f"detached valid PID {pid}",
                                frame(11, struct.pack("!I", pid)), mode="detached", log_paths=("", ""))
            assert proc.stdout == f"{pid}\n".encode(), proc
        tests = [
            ("managed ACK rejected", frame(2), "PROTOCOL"),
            ("output rejected", frame(5, b"x"), "PROTOCOL"),
            ("EXIT rejected", exited, "PROTOCOL"),
            ("unknown ACK", frame(255), "PROTOCOL"),
            ("empty ACK", frame(11), "PROTOCOL"),
            ("short ACK", frame(11, b"\0\0\1"), "PROTOCOL"),
            ("ACK trailing bytes", frame(11, struct.pack("!I", 1) + b"x"), "PROTOCOL"),
            ("zero PID", frame(11, struct.pack("!I", 0)), "PROTOCOL"),
            ("overflow PID", frame(11, struct.pack("!I", 2147483648)), "PROTOCOL"),
            ("negative PID", frame(11, struct.pack("!I", 4294967295)), "PROTOCOL"),
            ("oversize frame", bytes([11]) + struct.pack("!I", 1048577), "PROTOCOL"),
            ("ERROR unknown code", frame(9, struct.pack("!II", 9, 0)), "PROTOCOL"),
            ("ERROR zero code", frame(9, struct.pack("!II", 0, 0)), "PROTOCOL"),
            ("ERROR short", frame(9, b"x"), "PROTOCOL"),
            ("ERROR trailing", frame(9, struct.pack("!II", 3, 0) + b"x"), "PROTOCOL"),
            ("ERROR invalid UTF8", frame(9, struct.pack("!II", 3, 3) + b"\xed\xa0\x80"), "PROTOCOL"),
            ("ERROR NUL", frame(9, struct.pack("!II", 3, 1) + b"\0"), "PROTOCOL"),
            ("startup error", frame(9, struct.pack("!II", 3, 6) + b"failed"), "SPAWN_FAILED"),
            ("capacity error", frame(9, struct.pack("!II", 8, 0)), "LIMIT"),
            ("connection lost", b"", "CONNECTION_LOST"),
            ("truncated ACK header", ack[:3], "CONNECTION_LOST"),
            ("truncated ACK payload", ack[:7], "CONNECTION_LOST"),
        ]
        for name, reply, expected in tests:
            wire_test(binary, root, "detached " + name, reply, expected, mode="detached")
        wire_test(binary, root, "old v1 server refuses v2 safely", b"", "PROTOCOL",
                  handshake=False, mode="detached")
        wire_test(binary, root, "v1 greeting cannot downgrade detached", MAGIC, "PROTOCOL",
                  handshake=False, mode="detached")
        _, elapsed = wire_test(binary, root, "detached handshake deadline", b"", "PROTOCOL",
                               handshake=False, mode="detached", delay=3.3)
        assert 2.8 <= elapsed < 4.5, elapsed
        proc, elapsed = wire_test(binary, root, "detached ACK timeout unknown outcome", b"", "TIMEOUT",
                                  mode="detached", delay=3.3)
        assert 2.8 <= elapsed < 4.5 and b"outcome unknown" in proc.stderr, (elapsed, proc)
        proc, elapsed = wire_test(binary, root, "detached partial ACK timeout", [ack[:7], b""], "TIMEOUT",
                                  mode="detached", chunk_delay=1.65)
        assert 2.8 <= elapsed < 4.5 and b"outcome unknown" in proc.stderr, (elapsed, proc)
    print("All C protocol fixtures passed")


if __name__ == "__main__":
    main()
