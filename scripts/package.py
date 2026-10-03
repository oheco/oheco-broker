#!/usr/bin/env python3
"""Build the 0.3.0 native release from a clean committed snapshot, offline.

All native dependencies, the peer SDK, CLI and standalone server are rebuilt in
fresh private TMPDIR directories. SDKs are shipped as complete source trees;
SDK libraries, build caches and remote.env are never installation payloads.
This script does not tag, upload or publish, and refuses to replace an archive.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tarfile
import tempfile


RELEASE_VERSION = "0.3.0"
SOURCE_FILES = {name: name for name in (
    "LICENSE", "protocol/PROTOCOL.md", "go.mod", "go.sum",
)}
SOURCE_FILES["README.md"] = "docs/PACKAGE-README.md"
SOURCE_TREES = ("sdk/c", "sdk/go", "sdk/dotnet", "vendor", "vendor-manifests")
SYSTEM_LIBRARIES = {"libc.so"}
# The command map remains bin/oheco-broker and bin/oheco-broker-server.
# readlink resolves both oo's ordinary and versioned command symlinks.
CLI_LAUNCHER = """#!/usr/bin/sh
set -eu
entry=$0
case "$entry" in /*) ;; *) entry=$(command -v -- "$entry") ;; esac
count=0
while [ -L "$entry" ]; do
    count=$((count + 1))
    [ "$count" -le 40 ] || { printf '%s\\n' 'oheco-broker: symlink loop' >&2; exit 1; }
    directory=$(CDPATH= cd -- "$(dirname -- "$entry")" && pwd -P)
    target=$(readlink -- "$entry")
    case "$target" in /*) entry=$target ;; *) entry=$directory/$target ;; esac
done
root=$(CDPATH= cd -- "$(dirname -- "$entry")/.." && pwd -P)
export LD_LIBRARY_PATH="$root/lib/runtime${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$root/libexec/oheco-broker" "$@"
"""


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_inventory(source):
    """Exact source inventory, including upstream .o/.a/.key test fixtures."""
    files = dict(SOURCE_FILES)
    for tree in SOURCE_TREES:
        directory = source / tree
        if not directory.is_dir() or directory.is_symlink():
            raise RuntimeError(f"Missing/non-directory source tree: {tree}")
        for path in sorted(directory.rglob("*")):
            relative = path.relative_to(source).as_posix()
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise RuntimeError(f"Non-regular source entry: {relative}")
            parts = Path(relative).parts
            if any(part in {".git", "__pycache__", "CMakeFiles", "node_modules"} for part in parts):
                raise RuntimeError(f"Unexpected cache/metadata in source payload: {relative}")
            if path.name in {"remote.env", "native-deps.env", "curl-deps.env", "CMakeCache.txt"}:
                raise RuntimeError(f"Build environment/cache in source payload: {relative}")
            # Pristine upstream fixture names are validated by pinned manifests.
            # Only SDK-owned paths are subject to the generated-output rule.
            if relative.startswith("sdk/") and not relative.startswith("sdk/c/tpr/"):
                if any(part in {"bin", "obj", "cache", ".cache"} for part in parts) or (
                    path.is_file() and path.suffix.lower() in {".o", ".a", ".so", ".dll", ".pyc"}
                ):
                    raise RuntimeError(f"SDK build output in source payload: {relative}")
            if path.is_file():
                files[relative] = relative
    return files


def stage_sources(source, payload):
    inventory = source_inventory(source)
    for destination, origin in inventory.items():
        path = source / origin
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"Missing/non-regular package source: {origin}")
        target = payload / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        target.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
    return inventory


def notice_sources(source):
    """Retain actual license, patent and copyright files from every source tree."""
    notices = {}
    for tree, destination in (("vendor", "vendor"), ("sdk/c/tpr", "native")):
        for path in sorted((source / tree).rglob("*")):
            if path.is_file() and re.match(r"^(LICENSE|LICENCE|COPYING|NOTICE|PATENTS|COPYRIGHT)([._-]|$)",
                                          path.name, re.I):
                relative = path.relative_to(source / tree).as_posix()
                notices[f"licenses/{destination}/{relative}"] = path
    return notices


def elf_dependencies(binary):
    """Inspect actual little-endian AArch64 ELF DT_NEEDED without executing it."""
    data = binary.read_bytes()
    def unpack(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise RuntimeError(f"Truncated ELF: {binary.name}")
        return struct.unpack_from(fmt, data, offset)
    if data[:6] != b"\x7fELF\x02\x01":
        raise RuntimeError(f"Not a little-endian ELF64: {binary.name}")
    header = unpack("<HHIQQQIHHHHHH", 16)
    if header[1] != 183 or header[8] < 56 or not 0 < header[9] < 4096:
        raise RuntimeError(f"Not a valid AArch64 ELF: {binary.name}")
    segments = [unpack("<IIQQQQQQ", header[4] + i * header[8]) for i in range(header[9])]
    dynamic, interpreter = [], None
    for kind, flags, offset, vaddr, paddr, size, memsize, align in segments:
        if offset + size > len(data):
            raise RuntimeError("ELF segment exceeds file")
        if kind == 3:
            raw = data[offset:offset + size]
            if not raw.endswith(b"\0"):
                raise RuntimeError("Unterminated ELF interpreter")
            interpreter = raw[:-1].decode("ascii")
        if kind == 2:
            for cursor in range(offset, offset + size, 16):
                tag, value = unpack("<qQ", cursor)
                if tag == 0:
                    break
                dynamic.append((tag, value))
    if any(tag in (15, 29) for tag, value in dynamic):
        raise RuntimeError(f"Unexpected RPATH/RUNPATH: {binary.name}")
    needed = [value for tag, value in dynamic if tag == 1]
    names = []
    if needed:
        strings = [value for tag, value in dynamic if tag == 5]
        sizes = [value for tag, value in dynamic if tag == 10]
        if len(strings) != 1 or len(sizes) != 1:
            raise RuntimeError("Invalid ELF string table")
        table = None
        for kind, flags, offset, vaddr, paddr, size, memsize, align in segments:
            if kind == 1 and vaddr <= strings[0] and strings[0] + sizes[0] <= vaddr + size:
                start = offset + strings[0] - vaddr
                table = data[start:start + sizes[0]]
                break
        if table is None:
            raise RuntimeError("ELF string table not loadable")
        for index in needed:
            end = table.find(b"\0", index)
            if index >= len(table) or end < 0:
                raise RuntimeError("Invalid ELF dependency string")
            names.append(table[index:end].decode("ascii"))
    return {"needed": names, "interpreter": interpreter, "sha256": sha256(binary)}


def output(*args, cwd, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def stage_licenses(source, payload, goroot, runtime_source):
    notices = notice_sources(source)
    for filename in ("LICENSE", "PATENTS"):
        notices[f"licenses/Go-{filename}"] = goroot / filename
    go_vendor = goroot / "src/vendor"
    for path in sorted(go_vendor.rglob("*")):
        if path.is_file() and re.match(r"^(LICENSE|NOTICE|PATENTS)([._-]|$)", path.name, re.I):
            notices["licenses/Go-toolchain-vendor/" + path.relative_to(go_vendor).as_posix()] = path
    # Compiler-owned redistributable runtime: ship its actual SDK distribution notices.
    sdk_root = next((parent for parent in runtime_source.parents
                     if (parent / "NOTICE.txt").is_file() and (parent / "llvm").is_dir()), None)
    if sdk_root is None:
        raise RuntimeError("Cannot find actual OHOS C++ runtime distribution NOTICE.txt")
    notices["licenses/OHOS-native-NOTICE.txt"] = sdk_root / "NOTICE.txt"
    records = {}
    for destination, original in notices.items():
        if not original.is_file() or original.stat().st_size == 0:
            raise RuntimeError(f"Missing actual dependency license: {original}")
        target = payload / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        # Avoid embedding the local installation path or other machine metadata.
        records[destination] = {"sha256": sha256(target), "bytes": target.stat().st_size}
    sqlite = source / "vendor/github.com/mattn/go-sqlite3/sqlite3-binding.c"
    text = sqlite.read_text(encoding="utf-8")
    match = re.search(r"/\*\n\*\* 2001 September 15\n.*?\n\*\* \*+.*?\n", text, re.S)
    if not match or "disclaims copyright" not in match.group():
        raise RuntimeError("Missing SQLite upstream public-domain blessing")
    target = payload / "licenses/SQLite-PUBLIC-DOMAIN.txt"
    target.write_text("SQLite amalgamation notice, copied from vendor/github.com/mattn/go-sqlite3/sqlite3-binding.c:\n" +
                      match.group(), encoding="utf-8")
    records[target.relative_to(payload).as_posix()] = {"sha256": sha256(target), "bytes": target.stat().st_size}
    (payload / "LICENSES.json").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    native = (source / "sdk/c/tpr/native-dependencies.json").read_text(encoding="utf-8")
    curl = (source / "sdk/c/tpr/manifests/curl.json").read_text(encoding="utf-8")
    modules = (source / "vendor/modules.txt").read_text(encoding="utf-8")
    (payload / "THIRD-PARTY-NOTICES.txt").write_text(
        "Third-party source and runtime notices\n\n"
        "The complete vendored source files retain their upstream copyright and license headers,\n"
        "including embedded support-code notices. LICENSES.json inventories copies of all named\n"
        "license/notice/patent/copyright files, the Go toolchain notices, SQLite's public-domain\n"
        "blessing, and the OHOS native SDK distribution notices for libc++_shared.so.\n\n"
        "Go modules (exact vendor/modules.txt):\n" + modules +
        "\nNative dependency provenance (sdk/c/tpr/native-dependencies.json):\n" + native +
        "\nCurl provenance (sdk/c/tpr/manifests/curl.json):\n" + curl,
        encoding="utf-8")


def main():
    root = Path(__file__).resolve().parent.parent
    temporary = os.environ.get("TMPDIR")
    if not temporary or not Path(temporary).is_absolute() or not Path(temporary).is_dir():
        raise SystemExit("TMPDIR must name an existing absolute private directory")
    if output("git", "status", "--porcelain", "--untracked-files=all", cwd=root):
        raise SystemExit("Commit source changes before packaging; worktree must be clean")
    if output("go", "env", "GOOS", "GOARCH", cwd=root).splitlines() != ["ohos", "arm64"]:
        raise SystemExit("Release packages must be built natively with ohos/arm64 Go")
    commit = output("git", "rev-parse", "HEAD", cwd=root)
    timestamp = int(output("git", "show", "-s", "--format=%ct", "HEAD", cwd=root))
    toolchain = output("go", "version", cwd=root)
    goroot = Path(output("go", "env", "GOROOT", cwd=root))
    signer = shutil.which("binary-sign-tool")
    if not signer:
        raise SystemExit("binary-sign-tool is required in PATH")
    name = f"oheco-broker-{RELEASE_VERSION}-ohos-arm64"
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    archive = dist / f"{name}.tar.gz"
    if archive.exists():
        raise SystemExit(f"Refusing to overwrite {archive}; released bytes are immutable")
    log_path = dist / f"{name}.build.log"
    with tempfile.TemporaryDirectory(prefix="broker-package-", dir=temporary) as work_name, log_path.open("w") as log:
        work = Path(work_name)
        if work.stat().st_mode & 0o077:
            raise RuntimeError("TMPDIR filesystem does not enforce private directory permissions")
        source, payload = work / "source", work / name
        source.mkdir()
        payload.mkdir()
        snapshot = subprocess.check_output(["git", "archive", "--format=tar", "HEAD"], cwd=root)
        with tarfile.open(fileobj=io.BytesIO(snapshot)) as source_tar:
            source_tar.extractall(source, filter="data")
        for filename, spelling in (("cmd/oheco-broker/main.go", "version"),
                                    ("cmd/oheco-broker-server/main.go", "Version")):
            text = (source / filename).read_text(encoding="utf-8")
            if not re.search(r'^const ' + spelling + r' = "0\.3\.0"$', text, re.M):
                raise RuntimeError(f"Committed {filename} must declare formal version 0.3.0")
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("CGO_", "OB_", "NATIVE_", "CURL_")) and
               key not in {"LD_PRELOAD", "LD_LIBRARY_PATH", "GOFLAGS", "GOENV", "GOWORK"}}
        for key, directory in (("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                               ("XDG_CACHE_HOME", "cache"), ("GOCACHE", "gocache"),
                               ("GOMODCACHE", "gomodcache"), ("TMPDIR", "tmp"), ("GOTMPDIR", "gotmp")):
            path = work / directory
            path.mkdir(mode=0o700)
            env[key] = str(path)
        env.update(GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOENV="off", GOWORK="off",
                   GOFLAGS="-mod=vendor", CGO_ENABLED="1", CC="clang", CXX="clang++",
                   SOURCE_DATE_EPOCH=str(timestamp))
        def run(args, command_env=None):
            print("+ " + shlex.join(map(str, args)), file=log, flush=True)
            subprocess.run(args, cwd=source, env=command_env or env, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
        def sign(original, target):
            run([signer, "sign", "-inFile", str(original), "-outFile", str(target), "-selfSign", "1"])
            target.chmod(0o755)
            run([signer, "display-sign", "-inFile", str(target)])
        # This checker/build helper is SDK-owned and uses only snapshot inputs.
        checker = ["python3", str(source / "sdk/c/build/check-native-sources.py"),
                   "--include-go", "--repository-root", str(source)]
        run(checker)
        run(["sh", str(source / "sdk/c/build.sh")])
        run(checker)
        remote_env = work / "cache/oheco-broker/remote-sdk/remote.env"
        if not remote_env.is_file():
            raise RuntimeError("SDK helper did not emit the private remote.env build contract")
        # Shell interprets helper quoting. Only helper exports are used for CLI.
        command = '. "$1"; shift; exec "$@"'
        cli = work / "oheco-broker.unsigned"
        run(["sh", "-c", command, "package-go", str(remote_env), "go", "build", "-trimpath",
             "-buildvcs=false", "-o", str(cli), "./cmd/oheco-broker"])
        server = work / "oheco-broker-server.unsigned"
        # No peer CGO flags or native library paths are inherited by the server.
        run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(server), "./cmd/oheco-broker-server"])
        for child in ("bin", "libexec", "lib/runtime"):
            (payload / child).mkdir(parents=True, exist_ok=True)
        sign(cli, payload / "libexec/oheco-broker")
        sign(server, payload / "bin/oheco-broker-server")
        cli_info = elf_dependencies(payload / "libexec/oheco-broker")
        server_info = elf_dependencies(payload / "bin/oheco-broker-server")
        if set(cli_info["needed"]) != {"libc++_shared.so", "libc.so"}:
            raise RuntimeError(f"Unexpected actual CLI runtime dependencies: {cli_info['needed']}")
        if not set(server_info["needed"]) <= SYSTEM_LIBRARIES:
            raise RuntimeError(f"Standalone server links native peer libraries: {server_info['needed']}")
        runtime_source = Path(output("clang", "-print-file-name=libc++_shared.so", cwd=source, env=env)).resolve()
        runtime_info = elf_dependencies(runtime_source)
        if not set(runtime_info["needed"]) <= SYSTEM_LIBRARIES:
            raise RuntimeError(f"Unresolved recursive C++ runtime dependencies: {runtime_info['needed']}")
        sign(runtime_source, payload / "lib/runtime/libc++_shared.so")
        launcher = payload / "bin/oheco-broker"
        launcher.write_text(CLI_LAUNCHER, encoding="utf-8")
        launcher.chmod(0o755)
        for executable, label in ((launcher, "oheco-broker"), (payload / "bin/oheco-broker-server", "oheco-broker-server")):
            actual = output(str(executable), "--version", cwd=payload, env=env)
            if actual != f"{label} {RELEASE_VERSION}":
                raise RuntimeError(f"Version mismatch: {actual}")
        inventory = stage_sources(source, payload)
        stage_licenses(source, payload, goroot, runtime_source)
        runtime = {"system_libraries": sorted(SYSTEM_LIBRARIES), "launcher": "bin/oheco-broker",
                   "elf": {path: elf_dependencies(payload / path) for path in
                           ("libexec/oheco-broker", "bin/oheco-broker-server", "lib/runtime/libc++_shared.so")}}
        (payload / "RUNTIME.json").write_text(json.dumps(runtime, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (payload / "BUILDINFO.txt").write_text(
            f"version={RELEASE_VERSION}\nplatform=ohos-arm64\nsource_commit={commit}\n"
            f"toolchain={toolchain}\ncli_sha256={runtime['elf']['libexec/oheco-broker']['sha256']}\n"
            f"server_sha256={runtime['elf']['bin/oheco-broker-server']['sha256']}\n"
            f"runtime_sha256={runtime['elf']['lib/runtime/libc++_shared.so']['sha256']}\n"
            "runtime_dependencies=system libc.so; bundled lib/runtime/libc++_shared.so\n"
            "sdk_distribution=source-only; complete sdk/c including tpr, sdk/go, sdk/dotnet\n"
            f"source_files={len(inventory)}\nbuild=clean committed snapshot; offline; private TMPDIR; signed native probes and binaries\n",
            encoding="utf-8")
        hashes = {p.relative_to(payload).as_posix(): sha256(p) for p in sorted(payload.rglob("*")) if p.is_file()}
        (payload / "SHA256SUMS").write_text("".join(f"{digest}  {path}\n" for path, digest in hashes.items()), encoding="utf-8")
        def normalize(info):
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = timestamp
            if not (info.isfile() or info.isdir()):
                raise RuntimeError(f"Unexpected non-regular release entry: {info.name}")
            info.mode = 0o755 if info.isdir() or info.mode & 0o111 else 0o644
            return info
        # Exclusively install the finished archive; incomplete temporary bytes vanish.
        staged_archive = work / archive.name
        with staged_archive.open("xb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as packed:
                    packed.add(payload, arcname=name, filter=normalize)
        digest = sha256(staged_archive)
        with archive.open("xb") as destination, staged_archive.open("rb") as original:
            shutil.copyfileobj(original, destination)
        (dist / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
        print(f"source_commit={commit}\narchive={archive}\nsize={archive.stat().st_size}\nsha256={digest}\nbuild_log={log_path}")


if __name__ == "__main__":
    main()
