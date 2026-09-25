#!/usr/bin/env python3
"""Native release acceptance; usage: python3 tests/release_smoke.py ARCHIVE.tar.gz.

Only Python's standard library is used. Requires installed git and dotnet, plus
TMPDIR on the native private filesystem. All disposable state lives underneath
TMPDIR; the installed HOME is never used. The only external request is GitHub
ls-remote through the explicitly configured SOCKS5 proxy. No downloads/builds.
Use --test-layout for synthetic slim-payload policy checks only (no tools/network).
"""

import hashlib
import io
import os
import errno
from pathlib import Path, PurePosixPath
import re
import runpy
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET


RELEASE_VERSION = "0.2.0"
ROOT_NAME = f"oheco-broker-{RELEASE_VERSION}-ohos-arm64"
VERSION = f"oheco-broker {RELEASE_VERSION}\n".encode("ascii")
PROXY = "socks5h://127.0.0.1:10808"
MAGIC = b"OHECOB1\n"
MAX_FRAME = 1048576
MAX_STREAM = 65536
MAX_OUTPUT = 8 * MAX_FRAME
# Intentionally independent of the packager: both must agree on the slim payload.
SOURCE_FILES = {name: name for name in (
    "LICENSE", "protocol/PROTOCOL.md",
    "sdk/c/CMakeLists.txt", "sdk/c/README.md", "sdk/c/oheco_broker.c", "sdk/c/oheco_broker.h",
    "sdk/dotnet/BrokerProcess.cs", "sdk/dotnet/Oheco.Broker.csproj", "sdk/dotnet/README.md",
)}
SOURCE_FILES["README.md"] = "docs/PACKAGE-README.md"
LICENSE_FILES = {"licenses/Go-LICENSE", "licenses/Go-PATENTS"}
LICENSE_FILES.update(f"licenses/Go-vendor-x-{module}-LICENSE" for module in ("crypto", "net", "sys", "text"))
PAYLOAD_FILES = set(SOURCE_FILES) | LICENSE_FILES | {"bin/oheco-broker", "BUILDINFO.txt"}
PAYLOAD_DIRS = {str(parent) for name in PAYLOAD_FILES
                for parent in PurePosixPath(name).parents if str(parent) != "."}


class SmokeError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise SmokeError(message)


def kill_group(pid, sig):
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        pass


def session_members(session_id):
    """Find separate command groups too: the broker creates one per command."""
    members = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            # comm can contain spaces and parentheses; fields after it start at 3.
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[3]) == session_id:
                members.append((int(entry.name), int(fields[2])))
        except (OSError, ValueError, IndexError):
            continue  # Process exited during the snapshot.
    return members


def stop_process(proc):
    """Bounded, best-effort failure cleanup, including broker command groups."""
    members = session_members(proc.pid)
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            pass
    # Normal broker shutdown handles/reaps its commands. On failure, independently
    # kill any remaining process groups in the private session before reaping it.
    groups = {group for _, group in members + session_members(proc.pid)}
    for group in groups:
        kill_group(group, signal.SIGKILL)
    if proc.poll() is None:
        proc.kill()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired as exc:
        raise SmokeError("process cleanup timed out (pid %d)" % proc.pid) from exc


def local_command(args, env, cwd, timeout=10):
    proc = subprocess.Popen(args, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    try:
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise SmokeError("local command timed out: %r" % args) from exc
        require(proc.returncode == 0,
                "local command failed (%s): %r\n%s" %
                (proc.returncode, args, err.decode("utf-8", "replace")))
        return out, err
    finally:
        stop_process(proc)


def isolated_environment(base, original_path):
    env = {"PATH": original_path, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    for key, name in {
        "HOME": "home", "XDG_CONFIG_HOME": "config", "XDG_CACHE_HOME": "cache",
        "XDG_DATA_HOME": "data", "XDG_STATE_HOME": "state",
        "XDG_RUNTIME_DIR": "runtime", "TMPDIR": "tmp", "DOTNET_CLI_HOME": "dotnet",
        "NUGET_PACKAGES": "nuget", "GOCACHE": "gocache", "GOTMPDIR": "gotmp",
    }.items():
        directory = base / name
        directory.mkdir(mode=0o700)
        env[key] = str(directory)
    env.update({
        "TMP": env["TMPDIR"], "TEMP": env["TMPDIR"],
        "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "DOTNET_GENERATE_ASPNET_CERTIFICATE": "false", "DOTNET_NOLOGO": "1",
        "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "true",
        "DOTNET_CLI_WORKLOAD_UPDATE_ADVERTISING_DISABLE": "true",
        "GOPROXY": "off", "GOSUMDB": "off", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "HTTP_PROXY": PROXY, "HTTPS_PROXY": PROXY, "ALL_PROXY": PROXY,
        "http_proxy": PROXY, "https_proxy": PROXY, "all_proxy": PROXY,
        "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
    })
    # In particular, no inherited LD_LIBRARY_PATH, LD_PRELOAD, broker config,
    # GIT_CONFIG_COUNT, real user HOME, or NuGet configuration is needed.
    return env


def extract_release(archive, base):
    require(hasattr(tarfile, "data_filter"),
            "Python with tarfile's safe data filter is required (Python 3.12+)")
    destination = base / "unpack"
    destination.mkdir()
    with tarfile.open(archive, "r:gz") as package:
        members = package.getmembers()
        require(bool(members), "empty release archive")
        seen = set()
        files = set()
        for member in members:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and
                    path.parts and path.parts[0] == ROOT_NAME,
                    "unexpected archive path: %r" % member.name)
            require(member.isfile() or member.isdir(),
                    "release must contain regular files/directories, not links/devices: %r" % member.name)
            require(str(path) not in seen, "duplicate archive entry: %r" % member.name)
            seen.add(str(path))
            relative = str(path.relative_to(ROOT_NAME))
            allowed = (relative in PAYLOAD_FILES if member.isfile()
                       else relative == "." or relative in PAYLOAD_DIRS)
            require(allowed, "entry outside slim payload allowlist: %r" % member.name)
            if member.isfile():
                files.add(relative)
        require(files == PAYLOAD_FILES, "missing slim payload files: %r" % sorted(PAYLOAD_FILES - files))
        package.extractall(destination, members=members, filter="data")
    require([p.name for p in destination.iterdir()] == [ROOT_NAME],
            "archive must have exactly one expected release root")
    relocated = base / "relocated release 空间" / ROOT_NAME
    relocated.parent.mkdir()
    (destination / ROOT_NAME).rename(relocated)
    return relocated


def inspect_source(root):
    checkout = Path(__file__).resolve().parents[1]
    require((checkout / ".git").exists(), "run release acceptance from the source Git checkout")
    for name, origin in sorted(SOURCE_FILES.items()):
        path = root / name
        require(path.is_file() and path.stat().st_size > 0,
                "missing/empty packaged SDK/document: %s" % name)
        require(path.read_bytes() == (checkout / origin).read_bytes(),
                "packaged SDK/document differs from checkout: %s" % name)
    project = ET.parse(root / "sdk/dotnet/Oheco.Broker.csproj").getroot()
    require(project.tag == "Project" and project.get("Sdk") == "Microsoft.NET.Sdk",
            "invalid .NET SDK project")
    require(project.findtext(".//TargetFramework") == "net10.0",
            "unexpected .NET SDK target framework")
    require(not project.findall(".//PackageReference"),
            ".NET SDK must not introduce third-party package dependencies")
    require("MIT License" in (root / "LICENSE").read_text(encoding="utf-8"),
            "release must include the MIT LICENSE")
    print("PASS slim C/.NET SDK sources, protocol, installed README and LICENSE match checkout", flush=True)


def inspect_provenance(root, git, env):
    info = {}
    for line in (root / "BUILDINFO.txt").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        require(separator and key and value and key not in info,
                "malformed/duplicate BUILDINFO entry: %r" % line)
        info[key] = value
    require(info.get("version") == RELEASE_VERSION, "BUILDINFO version mismatch")
    require(info.get("platform") == "ohos-arm64", "BUILDINFO platform mismatch")
    commit = info.get("source_commit", "")
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "invalid BUILDINFO source_commit")
    digest = info.get("binary_sha256", "")
    require(re.fullmatch(r"[0-9a-f]{64}", digest), "invalid BUILDINFO binary_sha256")
    require(hashlib.sha256((root / "bin/oheco-broker").read_bytes()).hexdigest() == digest,
            "BUILDINFO binary_sha256 does not match packaged executable")
    require(info.get("toolchain") and info.get("runtime_dependencies") == "system libc.so" and
            info.get("configuration") == "none; foreground; unauthenticated loopback development service",
            "missing/unexpected BUILDINFO toolchain, runtime dependencies or configuration")
    checkout = Path(__file__).resolve().parents[1]
    if (checkout / ".git").exists():
        head, _ = local_command(
            [git, "-c", "safe.directory=" + str(checkout), "rev-parse", "HEAD"], env, checkout)
        require(head.decode("ascii").strip() == commit,
                "BUILDINFO source_commit does not match checkout HEAD")
    for name in sorted(LICENSE_FILES):
        path = root / name
        require(path.is_file() and path.stat().st_size > 0,
                "missing/empty bundled license: %s" % name)
    print("PASS BUILDINFO commit=%s binary_sha256=%s and Go/vendor licenses" %
          (commit, digest), flush=True)


def inspect_elf(binary):
    """Read ELF64 DT_NEEDED directly; no readelf/ldd dependency or loader tricks."""
    data = binary.read_bytes()

    def unpack(fmt, offset):
        require(0 <= offset <= len(data) - struct.calcsize(fmt), "truncated ELF")
        return struct.unpack_from(fmt, data, offset)

    require(data[:6] == b"\x7fELF\x02\x01", "broker is not little-endian ELF64")
    header = unpack("<HHIQQQIHHHHHH", 16)
    require(header[1] == 183, "release executable is not AArch64")
    phoff, phsize, phcount = header[4], header[8], header[9]
    require(phsize >= 56 and 0 < phcount < 4096, "invalid ELF program headers")
    segments = [unpack("<IIQQQQQQ", phoff + i * phsize) for i in range(phcount)]
    dynamic = []
    interpreter = None
    for kind, flags, offset, vaddr, paddr, size, memsize, align in segments:
        require(offset + size <= len(data), "ELF segment exceeds file")
        if kind == 3:
            raw = data[offset:offset + size]
            require(raw.endswith(b"\0"), "unterminated ELF interpreter")
            interpreter = raw[:-1].decode("utf-8", "strict")
            require(Path(interpreter).is_absolute() and Path(interpreter).is_file() and
                    interpreter.startswith(("/lib/", "/system/", "/usr/lib/")),
                    "ELF interpreter is not an installed system loader: %r" % interpreter)
        if kind == 2:
            require(size % 16 == 0, "invalid ELF dynamic segment")
            for cursor in range(offset, offset + size, 16):
                tag, value = unpack("<qQ", cursor)
                if tag == 0:
                    break
                dynamic.append((tag, value))
    require(not any(tag in (15, 29) for tag, _ in dynamic),
            "broker must not require RPATH/RUNPATH")
    needed = [value for tag, value in dynamic if tag == 1]
    names = []
    if needed:
        strings = [value for tag, value in dynamic if tag == 5]
        sizes = [value for tag, value in dynamic if tag == 10]
        require(len(strings) == len(sizes) == 1, "invalid ELF string table")
        table = None
        for kind, flags, offset, vaddr, paddr, size, memsize, align in segments:
            if kind == 1 and vaddr <= strings[0] and strings[0] + sizes[0] <= vaddr + size:
                start = offset + strings[0] - vaddr
                table = data[start:start + sizes[0]]
                break
        require(table is not None, "ELF dynamic string table not in loadable segment")
        for index in needed:
            require(index < len(table), "invalid ELF dependency name offset")
            end = table.find(b"\0", index)
            require(end >= 0, "unterminated ELF dependency name")
            names.append(table[index:end].decode("ascii", "strict"))
    require(set(names) <= {"libc.so"}, "unexpected ELF dependencies: %r" % names)
    print("PASS native ELF; dependencies=%r interpreter=%r" % (names, interpreter), flush=True)


def remaining(deadline, stage):
    seconds = deadline - time.monotonic()
    require(seconds > 0, "%s timed out" % stage)
    return seconds


def receive(sock, length, deadline, stage):
    data = bytearray()
    while len(data) < length:
        sock.settimeout(remaining(deadline, stage))
        chunk = sock.recv(length - len(data))
        require(bool(chunk), "%s: unexpected connection EOF" % stage)
        data.extend(chunk)
    return bytes(data)


def wire_string(value):
    raw = str(value).encode("utf-8", "strict")
    require(b"\0" not in raw, "NUL in START string")
    return struct.pack("!I", len(raw)) + raw


def expect_eof(sock, deadline, stage):
    sock.settimeout(remaining(min(deadline, time.monotonic() + 3), stage))
    require(sock.recv(1) == b"", "%s: bytes after terminal frame" % stage)


def start_payload(executable, args, cwd, overrides=None):
    overrides = overrides or {}
    require(len(args) <= 4096 and len(overrides) <= 4096, "START array too large")
    payload = wire_string(executable) + wire_string(cwd) + struct.pack("!I", len(args))
    payload += b"".join(wire_string(arg) for arg in args)
    payload += struct.pack("!I", len(overrides))
    for key, value in overrides.items():
        require(key and "=" not in key, "invalid START environment key")
        payload += wire_string(key) + wire_string(value)
    payload += b"\0"  # stdin disabled; no half-close and no input/control before STARTED.
    require(len(payload) <= MAX_FRAME, "START exceeds frame limit")
    return payload


def broker_detached(endpoint, executable, args, cwd, stdout_file):
    payload = start_payload(executable, args, cwd) + wire_string(stdout_file) + wire_string("")
    require(len(payload) <= MAX_FRAME, "detached START exceeds frame limit")
    deadline = time.monotonic() + 3
    with socket.create_connection(endpoint, timeout=3) as sock:
        sock.settimeout(remaining(deadline, "detached greeting"))
        sock.sendall(b"OHECOB2\n")
        require(receive(sock, 8, deadline, "detached greeting") == b"OHECOB2\n",
                "invalid detached greeting")
        deadline = time.monotonic() + 3
        sock.settimeout(remaining(deadline, "detached START"))
        sock.sendall(struct.pack("!BI", 10, len(payload)) + payload)
        kind, size = struct.unpack("!BI", receive(sock, 5, deadline, "detached ACK"))
        require(kind == 11 and size == 4, "expected detached PID ACK, got type=%s size=%s" % (kind, size))
        pid, = struct.unpack("!I", receive(sock, 4, deadline, "detached PID"))
        require(1 <= pid <= 2147483647, "invalid detached PID")
        # Close the client immediately after ACK; never fallback or retry.
        return pid


def detached_alive(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return fields[0] not in ("Z", "X") and int(fields[3]) == pid
    except (OSError, IndexError) as error:
        if isinstance(error, OSError) and error.errno not in (errno.ENOENT, errno.ESRCH, errno.EINVAL):
            raise
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True  # OHOS /proc can return EINVAL transiently while reaping.


def broker_command(endpoint, executable, args, cwd, label, timeout=20, overrides=None):
    deadline = time.monotonic() + timeout
    payload = start_payload(executable, args, cwd, overrides)
    started = False
    stdout, stderr = bytearray(), bytearray()
    try:
        with socket.create_connection(endpoint, timeout=min(3, remaining(deadline, label))) as sock:
            handshake = min(deadline, time.monotonic() + 3)
            sock.settimeout(remaining(handshake, label + " greeting"))
            sock.sendall(MAGIC)
            require(receive(sock, len(MAGIC), handshake, label + " greeting") == MAGIC,
                    label + ": invalid greeting")
            start_deadline = min(deadline, time.monotonic() + 3)
            sock.settimeout(remaining(start_deadline, label + " START"))
            sock.sendall(struct.pack("!BI", 1, len(payload)) + payload)
            while True:
                frame_deadline = deadline if started else start_deadline
                kind, size = struct.unpack("!BI", receive(sock, 5, frame_deadline, label))
                require(size <= MAX_FRAME, label + ": oversized frame")
                require(kind in (2, 5, 6, 8, 9), label + ": unexpected frame type %d" % kind)
                if kind in (5, 6):
                    require(1 <= size <= MAX_STREAM, label + ": invalid stream frame size")
                body = receive(sock, size, frame_deadline, label)
                if kind == 9:
                    require(size >= 8, label + ": short ERROR")
                    code, length = struct.unpack("!II", body[:8])
                    require(1 <= code <= 8 and length == size - 8,
                            label + ": malformed ERROR")
                    message = body[8:].decode("utf-8", "strict")
                    require("\0" not in message, label + ": NUL in ERROR")
                    expect_eof(sock, deadline, label + " ERROR")
                    raise SmokeError("%s: broker ERROR %d (%s STARTED): %s" %
                                     (label, code, "after" if started else "before", message))
                if not started:
                    require(kind == 2 and size == 0, label + ": expected empty STARTED")
                    started = True
                elif kind in (5, 6):
                    target = stdout if kind == 5 else stderr
                    require(len(stdout) + len(stderr) + size <= MAX_OUTPUT,
                            label + ": output exceeds smoke limit")
                    target.extend(body)
                elif kind == 8:
                    require(size == 12, label + ": EXIT must be exactly 12 bytes")
                    reason, code, sig = struct.unpack("!IiI", body)
                    valid = ((reason == 0 and 0 <= code <= 255 and sig == 0) or
                             (reason == 1 and code == -1 and sig > 0) or
                             (reason == 2 and ((0 <= code <= 255 and sig == 0) or
                                               (code == -1 and sig > 0))))
                    require(valid, label + ": invalid EXIT semantics %r" % ((reason, code, sig),))
                    expect_eof(sock, deadline, label + " EXIT")
                    require(reason == 0, label + ": unexpected signal/cancellation EXIT")
                    return code, bytes(stdout), bytes(stderr)
                else:
                    raise SmokeError(label + ": duplicate/out-of-order STARTED")
    except (OSError, UnicodeError) as exc:
        raise SmokeError("%s: transport/protocol failure or timeout: %s" % (label, exc)) from exc


def wait_endpoint(path, proc):
    deadline = time.monotonic() + 10
    while True:
        require(proc.poll() is None, "broker exited before endpoint publication")
        if path.exists():
            with path.open("rb") as stream:
                raw = stream.read(65)
            match = re.fullmatch(rb"127\.0\.0\.1:([0-9]+)(?:\r?\n)?", raw)
            require(len(raw) <= 64 and match is not None, "malformed broker endpoint")
            port = int(match.group(1))
            require(1 <= port <= 65535, "endpoint port out of range")
            return "127.0.0.1", port
        remaining(deadline, "endpoint publication")
        time.sleep(0.05)


def run_smoke(archive, base, original_path):
    env = isolated_environment(base, original_path)
    git = shutil.which("git", path=original_path)
    dotnet = shutil.which("dotnet", path=original_path)
    shell = ("/usr/bin/zsh" if os.access("/usr/bin/zsh", os.X_OK) else
             shutil.which("zsh", path=original_path) or shutil.which("sh", path=original_path))
    require(git and dotnet and shell, "installed git, dotnet and a shell are required on original PATH")
    git, dotnet, shell = (os.path.abspath(p) for p in (git, dotnet, shell))
    root = extract_release(archive, base)
    inspect_source(root)
    inspect_provenance(root, git, env)
    binary = root / "bin/oheco-broker"
    require(binary.is_file() and stat.S_IMODE(binary.stat().st_mode) & 0o111,
            "packaged broker lost executable mode")
    inspect_elf(binary)
    links = base / "command links 命令"
    links.mkdir()
    link = links / f"oheco-broker@{RELEASE_VERSION}"
    link.symlink_to(binary)
    for executable in (binary, link):
        out, err = local_command([str(executable), "--version"], env, base)
        require(out == VERSION and not err, "wrong version through %s: %r %r" % (executable, out, err))
    print("PASS relocated direct and versioned-symlink --version", flush=True)
    endpoint_path = Path(env["HOME"]) / ".oheco/broker/endpoint"
    log_path = base / "broker.log"
    proc = None
    detached_pid = None
    try:
        with log_path.open("wb") as log:
            # No flags, pre-created endpoint, or configuration: defaults must work.
            proc = subprocess.Popen([str(binary)], cwd=root, env=env, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            endpoint = wait_endpoint(endpoint_path, proc)
            duplicate_env = dict(env, XDG_CACHE_HOME=str(base / "duplicate-cache"))
            Path(duplicate_env["XDG_CACHE_HOME"]).mkdir(mode=0o700)
            before = endpoint_path.read_bytes()
            out, err = local_command([str(binary)], duplicate_env, root)
            require(out == b"oheco-broker is already running.\n" and not err,
                    "duplicate invocation must exit zero with already-running message")
            require(proc.poll() is None and endpoint_path.read_bytes() == before,
                    "duplicate invocation replaced endpoint or stopped owner")
            print("PASS duplicate startup exit 0 with distinct cache, original endpoint retained", flush=True)
            shell_args = ["-f", "-c"] if Path(shell).name == "zsh" else ["-c"]
            detached_log = base / "detached output 日志"
            detached_pid = broker_detached(
                endpoint, shell, shell_args + ["printf 'detached-ready\\n'; while :; do sleep 1; done"],
                root, detached_log)
            ready_deadline = time.monotonic() + 5
            while not detached_log.exists() or detached_log.read_bytes() != b"detached-ready\n":
                require(detached_alive(detached_pid), "detached child did not survive client closure")
                remaining(ready_deadline, "detached log readiness")
                time.sleep(0.05)
            require(detached_alive(detached_pid), "detached child died after client closure")
            print("PASS detached v2 ACK/client close and live independent session", flush=True)
            command = 'printf "stdout:%s:%s\\n" "$1" "$SMOKE_VALUE"; printf "stderr:ok\\n" >&2; exit 23'
            code, out, err = broker_command(
                endpoint, shell, shell_args + [command, "smoke", "space 空间"], root,
                "shell stdout/stderr/nonzero", overrides={"SMOKE_VALUE": "环境"})
            require((code, out, err) == (23, "stdout:space 空间:环境\n".encode(), b"stderr:ok\n"),
                    "shell result mismatch: %r" % ((code, out, err),))
            print("PASS greeting, STARTED, shell streams/Unicode/env and nonzero EXIT", flush=True)
            code, out, err = broker_command(endpoint, dotnet, ["--version"], root,
                                            "dotnet --version", timeout=30)
            require(code == 0 and re.fullmatch(rb"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\r?\n?", out),
                    "dotnet --version failed: %r" % ((code, out, err),))
            print("PASS broker dotnet --version: " + out.decode().strip(), flush=True)
            code, out, err = broker_command(
                endpoint, git,
                ["-c", "http.proxy=" + PROXY, "-c", "http.sslVerify=true",
                 "-c", "http.lowSpeedLimit=1", "-c", "http.lowSpeedTime=20",
                 "ls-remote", "https://github.com/oheco/oheco-broker.git", "HEAD"],
                root, "real proxied git ls-remote", timeout=60)
            require(code == 0 and re.fullmatch(rb"[0-9a-f]{40}\tHEAD\r?\n?", out),
                    "proxied git must return a real 40-hex HEAD commit: %r" % ((code, out, err),))
            print("PASS real GitHub HEAD via %s: %s" % (PROXY, out.decode().strip()), flush=True)
            proc.send_signal(signal.SIGTERM)
            try:
                result = proc.wait(timeout=8)
            except subprocess.TimeoutExpired as exc:
                raise SmokeError("broker TERM shutdown timed out after 8 seconds") from exc
            require(result == 0, "broker TERM shutdown returned %s" % result)
            require(not endpoint_path.exists(), "endpoint was not removed on TERM shutdown")
            require(not session_members(proc.pid), "broker left processes alive after shutdown")
            require(detached_alive(detached_pid), "detached child did not survive normal broker shutdown")
            print("PASS bounded TERM shutdown, managed cleanup and detached survival", flush=True)
    except BaseException:
        if log_path.exists():
            print("--- isolated broker log ---", file=sys.stderr)
            print(log_path.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
        raise
    finally:
        # Detached setsid children are intentionally outside the broker session.
        # This test owns their cleanup; the broker must never kill them for us.
        if detached_pid is not None and detached_alive(detached_pid):
            kill_group(detached_pid, signal.SIGKILL)
        if proc is not None:
            stop_process(proc)
        if detached_pid is not None:
            deadline = time.monotonic() + 3
            while detached_alive(detached_pid) and time.monotonic() < deadline:
                time.sleep(0.02)
            require(not detached_alive(detached_pid), "test-owned detached service survived cleanup")


def test_layout(base):
    """Synthetic archives only: no Go build, executable, broker or network needed."""
    checkout = Path(__file__).resolve().parents[1]
    packager = runpy.run_path(str(checkout / "scripts/package.py"))
    require(packager["SOURCE_FILES"] == SOURCE_FILES, "packager and acceptance source allowlists differ")
    staged = base / "staged"
    staged.mkdir()
    packager["stage_sources"](checkout, staged)
    actual = {p.relative_to(staged).as_posix() for p in staged.rglob("*") if p.is_file()}
    require(actual == set(SOURCE_FILES), "source staging copied unexpected files")
    inspect_source(staged)
    # Ensure consistency checks cannot silently accept different SDK bytes.
    changed = staged / "sdk/c/oheco_broker.h"
    original = changed.read_bytes()
    changed.write_bytes(original + b"\n/* modified */\n")
    try:
        inspect_source(staged)
    except SmokeError:
        pass
    else:
        raise SmokeError("modified packaged SDK passed checkout comparison")
    changed.write_bytes(original)

    cases = [("valid", None, None, False)]
    for name in ("go.mod", "cmd/main.go", "internal/server.go", "scripts/build.sh",
                 "examples/c/smoke.c", "tests/test.py", "VALIDATION.md", "docs/releases/history.md",
                 ".git/config", "sdk/c/unexpected.c", "sdk/dotnet/bin/library.dll"):
        cases.append(("extra " + name, name, None, False))
    cases += [("unexpected directory", "tests", None, True),
              ("missing SDK", None, "sdk/c/oheco_broker.h", False)]
    for index, (label, extra, missing, directory) in enumerate(cases):
        case = base / f"case-{index}"
        case.mkdir()
        archive = case / "fixture.tar.gz"
        with tarfile.open(archive, "w:gz") as package:
            for name in sorted(PAYLOAD_FILES - ({missing} if missing else set())):
                member = tarfile.TarInfo(f"{ROOT_NAME}/{name}")
                member.size = 1
                package.addfile(member, io.BytesIO(b"x"))
            if extra:
                member = tarfile.TarInfo(f"{ROOT_NAME}/{extra}")
                if directory:
                    member.type = tarfile.DIRTYPE
                package.addfile(member)
        try:
            extract_release(archive, case)
        except SmokeError:
            require(label != "valid", "valid slim payload was rejected")
        else:
            require(label == "valid", "unexpected payload accepted: " + label)
    print("PASS slim staging/SDK consistency and %d archive allowlist fixtures" % len(cases), flush=True)


def interrupted(signum, frame):
    raise SmokeError("interrupted by signal %d" % signum)


def main():
    require(len(sys.argv) == 2, "usage: python3 tests/release_smoke.py ARCHIVE.tar.gz | --test-layout")
    tmpdir = os.environ.get("TMPDIR")
    require(tmpdir and Path(tmpdir).is_dir() and Path(tmpdir).is_absolute(),
            "TMPDIR must name an existing absolute native private temporary directory")
    if sys.argv[1] == "--test-layout":
        with tempfile.TemporaryDirectory(prefix="broker-layout-test-", dir=tmpdir) as name:
            test_layout(Path(name))
        return
    archive = Path(sys.argv[1]).absolute()
    require(archive.is_file() and archive.name.endswith(".tar.gz"), "expected one existing .tar.gz archive")
    require(Path("/proc/self/stat").is_file(), "native /proc is required for process-tree cleanup")
    original_path = os.environ.get("PATH", os.defpath)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with tempfile.TemporaryDirectory(prefix="broker-release-smoke-", dir=tmpdir) as name:
        run_smoke(archive, Path(name), original_path)
    print("PASS release smoke; isolated temporary state removed", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (SmokeError, OSError, ValueError, tarfile.TarError, ET.ParseError) as exc:
        print("FAIL release smoke: %s" % exc, file=sys.stderr)
        sys.exit(1)
