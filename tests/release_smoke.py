#!/usr/bin/env python3
"""Native release acceptance; usage: python3 tests/release_smoke.py ARCHIVE.tar.gz.

Requires native Go/clang, git, dotnet, binary-sign-tool and private TMPDIR.
All disposable state lives underneath TMPDIR; the installed HOME is never used.
The only external request is GitHub ls-remote through the explicit SOCKS5 proxy.
--sdk-env must name the environment emitted by a separate offline build of this
archive's extracted SDK, not a pre-existing checkout build. Only minimal C/Go/
.NET consumers are compiled here; the full native dependency build is not repeated.
Use --test-layout for synthetic payload policy checks only (no build/network).
"""

import hashlib
import http.client
import io
import json
import os
import errno
from pathlib import Path, PurePosixPath
import re
import runpy
import shutil
import shlex
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


RELEASE_VERSION = "0.5.0"
ROOT_NAME = f"oheco-broker-{RELEASE_VERSION}-ohos-arm64"
VERSION = f"oheco-broker {RELEASE_VERSION}\n".encode("ascii")
PROXY = "socks5h://127.0.0.1:10808"
MAGIC = b"OHECOB1\n"
MAX_FRAME = 1048576
MAX_STREAM = 65536
MAX_OUTPUT = 8 * MAX_FRAME
# Independent of the packager; complete trees replace the former SDK whitelist.
SOURCE_FILES = {name: name for name in ("LICENSE", "protocol/PROTOCOL.md", "docs/RECONNECT.md", "docs/AUTH-REFRESH.md", "go.mod", "go.sum")}
SOURCE_FILES["README.md"] = "docs/PACKAGE-README.md"
SOURCE_TREES = ("sdk/c", "sdk/go", "sdk/dotnet", "vendor", "vendor-manifests")
GENERATED_FILES = {"bin/oheco-broker", "bin/oheco-broker-server", "libexec/oheco-broker",
                   "lib/runtime/libc++_shared.so", "BUILDINFO.txt", "RUNTIME.json", "LICENSES.json",
                   "THIRD-PARTY-NOTICES.txt", "SHA256SUMS"}
ELF_FILES = ("libexec/oheco-broker", "bin/oheco-broker-server", "lib/runtime/libc++_shared.so")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_inventory(checkout):
    sources = dict(SOURCE_FILES)
    for tree in SOURCE_TREES:
        directory = checkout / tree
        require(directory.is_dir(), "missing source SDK/module tree: " + tree)
        for path in directory.rglob("*"):
            require(not path.is_symlink(), "unexpected source symlink: " + str(path))
            if path.is_file():
                name = path.relative_to(checkout).as_posix()
                parts = PurePosixPath(name).parts
                require(not any(p in {".git", "__pycache__", "CMakeFiles", "node_modules"} for p in parts),
                        "source cache/metadata: " + name)
                require(path.name not in {"remote.env", "native-deps.env", "curl-deps.env", "CMakeCache.txt"},
                        "SDK build environment in sources: " + name)
                if name.startswith("sdk/") and not name.startswith("sdk/c/tpr/"):
                    require(not any(p in {"bin", "obj", "cache", ".cache"} for p in parts) and
                            path.suffix.lower() not in {".o", ".a", ".so", ".dll", ".pyc"},
                            "SDK generated output: " + name)
                sources[name] = name
    return sources


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
    require(not base.stat().st_mode & 0o077, "TMPDIR filesystem must enforce private temporary directory permissions")
    env = {"PATH": original_path, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    for key, name in {
        "HOME": "home", "XDG_CONFIG_HOME": "config", "XDG_CACHE_HOME": "cache",
        "XDG_DATA_HOME": "data", "XDG_STATE_HOME": "state",
        "XDG_RUNTIME_DIR": "runtime", "TMPDIR": "tmp", "DOTNET_CLI_HOME": "dotnet",
        "NUGET_PACKAGES": "nuget", "GOCACHE": "gocache", "GOTMPDIR": "gotmp",
        "GOMODCACHE": "gomodcache",
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
        "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off",
        "GOFLAGS": "-mod=vendor", "CGO_ENABLED": "1", "CC": "clang", "CXX": "clang++",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "HTTP_PROXY": PROXY, "HTTPS_PROXY": PROXY, "ALL_PROXY": PROXY,
        "http_proxy": PROXY, "https_proxy": PROXY, "all_proxy": PROXY,
        "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
    })
    # In particular, no inherited LD_LIBRARY_PATH, LD_PRELOAD, broker config,
    # GIT_CONFIG_COUNT, real user HOME, or NuGet configuration is needed.
    return env


def extract_release(archive, base, sources=None):
    require(hasattr(tarfile, "data_filter"),
            "Python with tarfile's safe data filter is required (Python 3.12+)")
    if sources is None:
        sources = source_inventory(Path(__file__).resolve().parents[1])
    expected = set(sources) | GENERATED_FILES
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
            if member.isfile():
                require(relative in expected or relative.startswith("licenses/"),
                        "entry outside source/runtime payload: %r" % member.name)
                files.add(relative)
        require(expected <= files, "missing source/runtime payload files: %r" % sorted(expected - files))
        allowed_dirs = {str(parent) for name in files for parent in PurePosixPath(name).parents}
        for member in members:
            if member.isdir():
                relative = str(PurePosixPath(member.name).relative_to(ROOT_NAME))
                require(relative in allowed_dirs or relative == ".", "unnecessary payload directory: " + member.name)
        package.extractall(destination, members=members, filter="data")
    license_index = json.loads((destination / ROOT_NAME / "LICENSES.json").read_text(encoding="utf-8"))
    require(isinstance(license_index, dict) and bool(license_index), "invalid/empty license inventory")
    require(files == expected | set(license_index), "unindexed or absent license payload")
    require(all(isinstance(name, str) and name.startswith("licenses/") for name in license_index),
            "license inventory entry outside licenses/")
    require([p.name for p in destination.iterdir()] == [ROOT_NAME],
            "archive must have exactly one expected release root")
    relocated = base / "relocated release 空间" / ROOT_NAME
    relocated.parent.mkdir()
    (destination / ROOT_NAME).rename(relocated)
    return relocated


def inspect_source(root):
    checkout = Path(__file__).resolve().parents[1]
    require((checkout / ".git").exists(), "run release acceptance from the source Git checkout")
    sources = source_inventory(checkout)
    for name, origin in sorted(sources.items()):
        path = root / name
        require(path.is_file(), "missing packaged source/document: %s" % name)
        require(digest(path) == digest(checkout / origin),
                "packaged SDK/document differs from checkout: %s" % name)
    for tree in SOURCE_TREES:
        actual = {p.relative_to(root).as_posix() for p in (root / tree).rglob("*") if p.is_file()}
        expected = {name for name in sources if name.startswith(tree + "/")}
        require(actual == expected, "incomplete/extra SDK source tree: " + tree)
    for resource in ("sdk/c/build.sh", "sdk/c/build/check-native-sources.py",
                     "sdk/c/tpr/native-dependencies.json", "sdk/c/tpr/manifests/curl.json",
                     "sdk/c/tpr/patches/libjuice-relay-only.patch", "vendor/modules.txt"):
        require((root / resource).is_file(), "missing offline SDK build/provenance input: " + resource)
    project = ET.parse(root / "sdk/dotnet/Oheco.Broker.csproj").getroot()
    require(project.tag == "Project" and project.get("Sdk") == "Microsoft.NET.Sdk",
            "invalid .NET SDK project")
    require(project.findtext(".//TargetFramework") == "net10.0",
            "unexpected .NET SDK target framework")
    require(not project.findall(".//PackageReference"),
            ".NET SDK must not introduce third-party package dependencies")
    require("MIT License" in (root / "LICENSE").read_text(encoding="utf-8"),
            "release must include the MIT LICENSE")
    print("PASS complete C/Go/.NET SDK, tpr fixtures, pinned manifests, build resources and vendor sources (%d files)" %
          len(sources), flush=True)


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
    for key, name in (("cli_sha256", "libexec/oheco-broker"), ("server_sha256", "bin/oheco-broker-server"),
                      ("runtime_sha256", "lib/runtime/libc++_shared.so")):
        require(re.fullmatch(r"[0-9a-f]{64}", info.get(key, "")), "invalid BUILDINFO " + key)
        require(digest(root / name) == info[key], "BUILDINFO hash does not match " + name)
    require(info.get("toolchain") and
            info.get("runtime_dependencies") == "system libc.so; bundled lib/runtime/libc++_shared.so" and
            info.get("sdk_distribution") == "source-only; complete sdk/c including tpr, sdk/go, sdk/dotnet" and
            info.get("build") == "clean committed snapshot; offline; private TMPDIR; signed native probes and binaries",
            "missing/unexpected BUILDINFO toolchain, source SDK or clean offline build contract")
    sums = {}
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, "invalid internal SHA256SUMS line")
        value, name = match.groups()
        require(name not in sums and not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts,
                "duplicate/unsafe internal checksum path")
        sums[name] = value
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()} - {"SHA256SUMS"}
    require(set(sums) == actual, "internal checksum inventory incomplete or extra")
    for name, value in sums.items():
        require(digest(root / name) == value, "payload checksum mismatch: " + name)
    checkout = Path(__file__).resolve().parents[1]
    if (checkout / ".git").exists():
        head, _ = local_command(
            [git, "-c", "safe.directory=" + str(checkout), "rev-parse", "HEAD"], env, checkout)
        require(head.decode("ascii").strip() == commit,
                "BUILDINFO source_commit does not match checkout HEAD")
    require(info.get("source_files") == str(len(source_inventory(checkout))), "BUILDINFO source inventory count mismatch")
    notices = json.loads((root / "LICENSES.json").read_text(encoding="utf-8"))
    for name, record in notices.items():
        path = root / name
        require(path.is_file() and path.stat().st_size > 0 and
                record == {"sha256": digest(path), "bytes": path.stat().st_size},
                "missing/changed dependency license: " + name)
    for tree, prefix in (("vendor", "licenses/vendor"), ("sdk/c/tpr", "licenses/native")):
        for path in (root / tree).rglob("*"):
            if path.is_file() and re.match(r"^(LICENSE|LICENCE|COPYING|NOTICE|PATENTS|COPYRIGHT)([._-]|$)", path.name, re.I):
                copy = prefix + "/" + path.relative_to(root / tree).as_posix()
                require(copy in notices and digest(root / copy) == digest(path),
                        "actual source license omitted/changed: " + copy)
    for name in ("licenses/Go-LICENSE", "licenses/Go-PATENTS", "licenses/OHOS-native-NOTICE.txt",
                 "licenses/SQLite-PUBLIC-DOMAIN.txt"):
        require(name in notices, "missing toolchain/runtime/SQLite notice: " + name)
    require(any(name.startswith("licenses/Go-toolchain-vendor/") for name in notices),
            "Go standard-library vendored dependencies lack notices")
    text = (root / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
    for source in ("vendor/modules.txt", "sdk/c/tpr/native-dependencies.json", "sdk/c/tpr/manifests/curl.json"):
        require((root / source).read_text(encoding="utf-8") in text, "third-party notices omit actual provenance: " + source)
    require("disclaims copyright" in (root / "licenses/SQLite-PUBLIC-DOMAIN.txt").read_text(encoding="utf-8"),
            "SQLite public-domain notice missing")
    print("PASS BUILDINFO commit=%s, complete payload hashes and %d Go/native/runtime license notices" %
          (commit, len(notices)), flush=True)


def inspect_elf(binary, allowed):
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
    require(set(names) <= allowed, "unexpected ELF dependencies: %r" % names)
    print("PASS native ELF %s; dependencies=%r interpreter=%r" % (binary.name, names, interpreter), flush=True)
    return {"needed": names, "interpreter": interpreter, "sha256": digest(binary)}


def inspect_runtime(root, env, base):
    recorded = json.loads((root / "RUNTIME.json").read_text(encoding="utf-8"))
    require(recorded.get("system_libraries") == ["libc.so"] and recorded.get("launcher") == "bin/oheco-broker" and
            set(recorded.get("elf", {})) == set(ELF_FILES), "unexpected runtime closure manifest")
    signer = shutil.which("binary-sign-tool", path=env["PATH"])
    require(signer, "binary-sign-tool is required to inspect actual release signatures")
    for name in ELF_FILES:
        allowed = {"libc.so", "libc++_shared.so"} if name == "libexec/oheco-broker" else {"libc.so"}
        actual = inspect_elf(root / name, allowed)
        require(actual == recorded["elf"][name], "runtime manifest differs from actual ELF: " + name)
        if name == "libexec/oheco-broker":
            require(set(actual["needed"]) == allowed, "CLI C++ dependency must be bundled and explicit")
        local_command([signer, "display-sign", "-inFile", str(root / name)], env, base)
    launcher = (root / "bin/oheco-broker").read_text(encoding="utf-8")
    require(launcher.startswith("#!/usr/bin/sh\n") and 'exec "$root/libexec/oheco-broker" "$@"' in launcher and
            'LD_LIBRARY_PATH="$root/lib/runtime' in launcher, "CLI launcher does not resolve bundled runtime")
    print("PASS signed CLI/server/C++ runtime and actual recursive ELF dependency closure", flush=True)


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


def standalone_smoke(binary, base, env):
    directory = base / "standalone server 状态"
    directory.mkdir(mode=0o700)
    log_path = directory / "server.log"
    server_env = dict(env, OHECO_BROKER_ADMIN_TOKEN="release-smoke-isolated-admin-token-0123456789abcdef")
    with log_path.open("wb") as log:
        proc = subprocess.Popen([str(binary), "--listen", "127.0.0.1:0", "--db", str(directory / "control.sqlite")],
                                env=server_env, cwd=directory, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + 10
            ready = None
            while ready is None:
                require(proc.poll() is None, "standalone server exited before readiness: " + log_path.read_text(errors="replace"))
                for line in log_path.read_text(errors="replace").splitlines():
                    if line.startswith('{'):
                        event = json.loads(line)
                        if event.get("event") == "server_ready":
                            ready = event
                if ready is None:
                    remaining(deadline, "standalone server readiness")
                    time.sleep(0.05)
            require(ready.get("version") == RELEASE_VERSION and not ready.get("turn") and
                    re.fullmatch(r"http://127\.0\.0\.1:[0-9]+", ready.get("api", "")),
                    "standalone server readiness mismatch")
            port = int(ready["api"].rsplit(":", 1)[1])
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            try:
                connection.request("GET", "/v1/me")
                response = connection.getresponse()
                response.read(65536)
                require(response.status == 401, "standalone API did not reject an unauthenticated request")
            finally:
                connection.close()
            database = directory / "control.sqlite"
            require(database.is_file() and database.read_bytes()[:16] == b"SQLite format 3\0",
                    "standalone server failed actual SQLite initialization")
            proc.send_signal(signal.SIGTERM)
            require(proc.wait(timeout=12) == 0, "standalone server TERM shutdown failed")
            require(not session_members(proc.pid), "standalone server left child processes")
        finally:
            stop_process(proc)
    print("PASS relocated standalone server, private SQLite, loopback API and bounded TERM shutdown", flush=True)


def sdk_environment(path, root, env, base):
    require(path.is_file() and path.name == "remote.env", "--sdk-env must name the unpacked SDK helper's remote.env")
    code = "import json,os; print(json.dumps({k:v for k,v in os.environ.items() if k.startswith(('OB_', 'CGO_'))}))"
    out, err = local_command(["sh", "-c", '. "$1"; exec "$2" -c "$3"', "sdk-smoke-env", str(path),
                              sys.executable, code], env, base)
    exports = json.loads(out)
    for key in ("OB_REMOTE_BUILD", "OB_NATIVE_PREFIX", "OB_CURL_PREFIX", "CGO_CFLAGS", "CGO_LDFLAGS"):
        require(exports.get(key), "unpacked SDK environment lacks " + key)
    for key in ("OB_REMOTE_BUILD", "OB_NATIVE_PREFIX", "OB_CURL_PREFIX"):
        directory = Path(exports[key])
        require(directory.is_absolute() and directory.is_dir() and
                not directory.resolve().is_relative_to(Path(__file__).resolve().parents[1]),
                "SDK prefix must come from a separate extracted-source build: " + key)
    include_paths = [Path(flag[2:]) for flag in shlex.split(exports["CGO_CFLAGS"]) if flag.startswith("-I")]
    c_sdk = next((path.parent.resolve() for path in include_paths if (path / "ob_api.h").is_file()), None)
    require(c_sdk and not c_sdk.is_relative_to(Path(__file__).resolve().parents[1]),
            "--sdk-env must refer to independently extracted release SDK sources")
    expected = {path.relative_to(root / "sdk/c").as_posix(): path for path in (root / "sdk/c").rglob("*") if path.is_file()}
    actual = {path.relative_to(c_sdk).as_posix(): path for path in c_sdk.rglob("*") if path.is_file()}
    require(set(actual) == set(expected), "external SDK source tree missing/extra release paths")
    for name, source in expected.items():
        require(not actual[name].is_symlink() and digest(actual[name]) == digest(source),
                "external SDK build source differs from this release: " + name)
    # Include the relocated archive's headers first. Native archives are reused
    # from the independently built prefix, never copied into the release SDK.
    exports["CGO_CFLAGS"] = shlex.quote("-I" + str(root / "sdk/c/remote")) + " " + exports["CGO_CFLAGS"]
    return dict(env, **exports)


def sign_consumer(unsigned, signed, env, base):
    signer = shutil.which("binary-sign-tool", path=env["PATH"])
    require(signer, "binary-sign-tool is required for native SDK consumers")
    local_command([signer, "sign", "-inFile", str(unsigned), "-outFile", str(signed), "-selfSign", "1"], env, base, timeout=30)
    signed.chmod(0o755)


def build_consumers(root, base, env, sdk_env):
    """Only small consumers; no dependency or peer test suite is rebuilt here."""
    work = base / "source consumers 空间"
    work.mkdir()
    c_source = work / "consume.c"
    c_source.write_text(r'''#include "oheco_broker.h"
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    const char *args[] = {"--version"};
    ob_options options = {0}; options.executable = argv[2]; options.args = args; options.argc = 1;
    ob_diagnostic diagnostic = {0}; ob_process *process = NULL;
    if (ob_start(argv[1], &options, &process, &diagnostic) != OB_OK) {
        fprintf(stderr, "%s: %s\n", diagnostic.stage, diagnostic.message); return 3;
    }
    ob_event event; int result = 4;
    for (;;) {
        if (ob_read_event(process, 10000, &event, &diagnostic) != OB_OK) break;
        if (event.type == OB_STDOUT && fwrite(event.data, 1, event.size, stdout) != event.size) break;
        if (event.type == OB_STDERR && fwrite(event.data, 1, event.size, stderr) != event.size) break;
        if (event.type == OB_EXIT) { result = event.result.reason ? 5 : event.result.exit_code; break; }
    }
    ob_release(process); return result;
}
''', encoding="utf-8")
    cc = shutil.which("clang", path=env["PATH"])
    go = shutil.which("go", path=env["PATH"])
    dotnet = shutil.which("dotnet", path=env["PATH"])
    require(cc and go and dotnet, "native clang, Go and dotnet are required for source consumers")
    unsigned, c_binary = work / "c-consumer.unsigned", work / "c-consumer"
    local_command([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread", "-I" + str(root / "sdk/c"),
                   str(c_source), str(root / "sdk/c/oheco_broker.c"), "-o", str(unsigned)], env, work, timeout=30)
    sign_consumer(unsigned, c_binary, env, work)
    go_work = root / "sdk-consumer-smoke"
    go_work.mkdir()
    (go_work / "main.go").write_text('''package main
import (
    "fmt"
    "net"
    "net/http"
    "time"
    "github.com/oheco/oheco-broker/sdk/go/remote"
)
func main() {
    listener, err := net.Listen("tcp4", "127.0.0.1:0"); if err != nil { panic(err) }
    server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != "GET" || r.URL.Path != "/v1/sdk-smoke" { http.Error(w, "wrong request", 400); return }
        w.Header().Set("Content-Type", "application/json"); fmt.Fprint(w, `{\"ok\":true}`)
    })}
    go server.Serve(listener); defer server.Close()
    client, err := remote.New(remote.Options{URL: "http://" + listener.Addr().String(), Timeout: 3 * time.Second})
    if err != nil { panic(err) }; defer client.Close()
    data, err := client.Request("GET", "/v1/sdk-smoke", nil, nil)
    if err != nil || string(data) != `{\"ok\":true}` { panic(fmt.Sprintf("response=%s err=%v", data, err)) }
    fmt.Println("go-sdk-ok")
}
''', encoding="utf-8")
    unsigned, go_binary = work / "go-consumer.unsigned", work / "go-consumer"
    local_command([go, "build", "-mod=vendor", "-trimpath", "-buildvcs=false", "-o", str(unsigned),
                   "./sdk-consumer-smoke"], sdk_env, root, timeout=180)
    sign_consumer(unsigned, go_binary, env, work)
    runtime_env = dict(env, LD_LIBRARY_PATH=str(root / "lib/runtime"))
    out, err = local_command([str(go_binary)], runtime_env, work, timeout=15)
    require(out == b"go-sdk-ok\n" and not err, "Go SDK source consumer failed loopback native API request")
    dotnet_work = work / "dotnet"
    dotnet_work.mkdir()
    source = dotnet_work / "BrokerProcess.cs"
    shutil.copyfile(root / "sdk/dotnet/BrokerProcess.cs", source)
    (dotnet_work / "Smoke.csproj").write_text('''<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>
<OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework><ImplicitUsings>enable</ImplicitUsings>
<Nullable>enable</Nullable></PropertyGroup></Project>''', encoding="utf-8")
    (dotnet_work / "NuGet.Config").write_text('<configuration><packageSources><clear /></packageSources></configuration>', encoding="utf-8")
    (dotnet_work / "Program.cs").write_text('''using Oheco.Broker;
var info = new BrokerProcessStartInfo { EndpointFile = args[0], FileName = args[1],
    RedirectStandardOutput = true, RedirectStandardError = true };
info.ArgumentList.Add("--version");
using var process = new BrokerProcess(info);
await process.StartAsync();
var output = process.StandardOutput.ReadToEndAsync();
var errors = process.StandardError.ReadToEndAsync();
await process.WaitForExitAsync();
Console.Write(await output); Console.Error.Write(await errors);
return process.ExitCode;
''', encoding="utf-8")
    local_command([dotnet, "build", str(dotnet_work / "Smoke.csproj"), "--configuration", "Release", "--nologo",
                   "--verbosity", "quiet", "--configfile", str(dotnet_work / "NuGet.Config")], env, dotnet_work, timeout=90)
    print("PASS source SDK C compile/sign, actual Go native link/loopback request and offline .NET build", flush=True)
    return c_binary, dotnet_work / "bin/Release/net10.0/Smoke.dll"


def run_smoke(archive, base, original_path, sdk_env_path):
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
    inspect_runtime(root, env, base)
    local_command([sys.executable, str(root / "sdk/c/build/check-native-sources.py"),
                   "--include-go", "--repository-root", str(root)], env, root, timeout=90)
    print("PASS extracted SDK's offline pinned-source checker", flush=True)
    consumer_env = sdk_environment(sdk_env_path, root, env, base)
    binary = root / "bin/oheco-broker"
    server_binary = root / "bin/oheco-broker-server"
    for executable in (binary, server_binary):
        require(executable.is_file() and stat.S_IMODE(executable.stat().st_mode) & 0o111,
                "packaged command lost executable mode: " + executable.name)
    links = base / "command links 命令"
    links.mkdir()
    for command, expected in ((binary, VERSION), (server_binary, f"oheco-broker-server {RELEASE_VERSION}\n".encode())):
        link = links / (command.name + "@" + RELEASE_VERSION)
        link.symlink_to(command)
        normal = links / command.name
        normal.symlink_to(link.name)  # Relative link and a second hop, as installed command maps may use.
        for executable in (command, link, normal):
            out, err = local_command([str(executable), "--version"], env, base)
            require(out == expected and not err, "wrong version through %s: %r %r" % (executable, out, err))
        path_env = dict(env, PATH=str(links) + os.pathsep + env["PATH"])
        out, err = local_command([command.name, "--version"], path_env, base)
        require(out == expected and not err, "PATH command-map version failed")
    out, err = local_command([str(binary)], env, base)
    require(b"Usage:" in out and b"shell" in out and b"tenant" in out and not err,
            "CLI with no arguments must print help and exit successfully")
    out, err = local_command([str(server_binary), "--help"], env, base)
    require(b"Usage: oheco-broker-server" in err and not out, "standalone server --help failed")
    require(not (Path(env["HOME"]) / ".oheco/broker/endpoint").exists(), "help/version started the shell server")
    require(not list(Path(env["XDG_CONFIG_HOME"]).rglob("*")), "help/version wrote account configuration")
    print("PASS relocated two entries, direct/PATH/versioned/relative symlinks and no-argument CLI help", flush=True)
    c_consumer, dotnet_consumer = build_consumers(root, base, env, consumer_env)
    standalone_smoke(server_binary, base, env)
    endpoint_path = Path(env["HOME"]) / ".oheco/broker/endpoint"
    log_path = base / "broker.log"
    proc = None
    detached_pid = None
    try:
        with log_path.open("wb") as log:
            # Legacy shell service remains an explicit 0.3.0 command.
            proc = subprocess.Popen([str(binary), "shell", "serve"], cwd=root, env=env, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            endpoint = wait_endpoint(endpoint_path, proc)
            duplicate_env = dict(env, XDG_CACHE_HOME=str(base / "duplicate-cache"))
            Path(duplicate_env["XDG_CACHE_HOME"]).mkdir(mode=0o700)
            before = endpoint_path.read_bytes()
            out, err = local_command([str(binary), "shell", "serve"], duplicate_env, root)
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
            for consumer, arguments, label in (
                (str(c_consumer), [str(endpoint_path), str(binary)], "legacy source C SDK"),
                (dotnet, [str(dotnet_consumer), str(endpoint_path), str(binary)], "legacy source .NET SDK"),
            ):
                out, err = local_command([consumer, *arguments], env, base, timeout=30)
                require(out == VERSION and not err, label + " did not execute the relocated CLI through shell serve")
                print("PASS " + label + " command lifecycle through explicit shell serve", flush=True)
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
    """Complete real source staging plus small independent archive policy fixtures."""
    checkout = Path(__file__).resolve().parents[1]
    packager = runpy.run_path(str(checkout / "scripts/package.py"))
    sources = source_inventory(checkout)
    require(packager["SOURCE_FILES"] == SOURCE_FILES and packager["SOURCE_TREES"] == SOURCE_TREES and
            packager["source_inventory"](checkout) == sources, "packager and acceptance source inventories differ")
    staged = base / "staged"
    staged.mkdir()
    packager["stage_sources"](checkout, staged)
    actual = {p.relative_to(staged).as_posix() for p in staged.rglob("*") if p.is_file()}
    require(actual == set(sources), "source staging copied unexpected files")
    inspect_source(staged)
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
    # These extensions are valid pristine source fixtures, never a reason to prune tpr.
    fixtures = dict(SOURCE_FILES, **{name: name for name in (
        "sdk/c/oheco_broker.h", "sdk/c/tpr/upstream/test.o", "sdk/c/tpr/upstream/test.a",
        "sdk/c/tpr/upstream/test.key", "sdk/go/remote/client.go", "vendor/modules.txt")})
    license_name = "licenses/upstream/LICENSE"
    files = set(fixtures) | GENERATED_FILES | {license_name}
    cases = [("valid", None, None, "file")]
    for name in ("cmd/main.go", "internal/server.go", "scripts/build.sh", "remote.env",
                 "examples/c/smoke.c", "tests/test.py", "VALIDATION.md", "docs/releases/history.md",
                 ".git/config", "sdk/c/unexpected.c", "sdk/c/generated.a", "sdk/dotnet/bin/library.dll",
                 "sdk/c/tpr/upstream/unrecorded.o", "licenses/unindexed/LICENSE"):
        cases.append(("extra " + name, name, None, "file"))
    cases += [("unexpected directory", "tests", None, "directory"),
              ("missing SDK", None, "sdk/c/oheco_broker.h", "file"),
              ("missing fixture", None, "sdk/c/tpr/upstream/test.o", "file"),
              ("missing Go module", None, "go.mod", "file"),
              ("symlink", "link", None, "symlink"),
              ("traversal", "../escape", None, "file"),
              ("duplicate", "go.mod", None, "file")]
    for index, (label, extra, missing, kind) in enumerate(cases):
        case = base / f"case-{index}"
        case.mkdir()
        archive = case / "fixture.tar.gz"
        with tarfile.open(archive, "w:gz") as package:
            for name in sorted(files - ({missing} if missing else set())):
                data = json.dumps({license_name: {"sha256": "0" * 64, "bytes": 1}}).encode() if name == "LICENSES.json" else b"x"
                member = tarfile.TarInfo(f"{ROOT_NAME}/{name}")
                member.size = len(data)
                package.addfile(member, io.BytesIO(data))
            if extra:
                member = tarfile.TarInfo(f"{ROOT_NAME}/{extra}")
                if kind == "directory":
                    member.type = tarfile.DIRTYPE
                elif kind == "symlink":
                    member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
                package.addfile(member)
        try:
            extract_release(archive, case, sources=fixtures)
        except SmokeError:
            require(label != "valid", "valid complete source payload was rejected")
        else:
            require(label == "valid", "unexpected payload accepted: " + label)
    print("PASS complete source staging/tpr fixture preservation and %d archive policy fixtures" % len(cases), flush=True)


def interrupted(signum, frame):
    raise SmokeError("interrupted by signal %d" % signum)


def main():
    usage = "usage: python3 tests/release_smoke.py ARCHIVE.tar.gz --sdk-env EXTRACTED_BUILD/remote.env | --test-layout"
    require(len(sys.argv) == 2 and sys.argv[1] == "--test-layout" or
            len(sys.argv) == 4 and sys.argv[2] == "--sdk-env", usage)
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
        run_smoke(archive, Path(name), original_path, Path(sys.argv[3]).absolute())
    print("PASS release smoke; isolated temporary state removed", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (SmokeError, OSError, ValueError, tarfile.TarError, ET.ParseError) as exc:
        print("FAIL release smoke: %s" % exc, file=sys.stderr)
        sys.exit(1)
