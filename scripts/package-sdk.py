#!/usr/bin/env python3
"""Derive the immutable source SDK attachment from a verified runtime archive.

No Git, network, native compilation or checkout source reads are needed. Every
runtime payload file is checked against its internal SHA256SUMS before copying
source bytes. All intermediate files live in a private TMPDIR directory.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile


VERSION = "0.3.0"
RUNTIME_ROOT = f"oheco-broker-{VERSION}-ohos-arm64"
SDK_ROOT = f"oheco-broker-{VERSION}-sdk-source"
SOURCE_TREES = ("sdk/c", "sdk/go", "sdk/dotnet", "vendor", "vendor-manifests")
SOURCE_FILES = {"LICENSE", "protocol/PROTOCOL.md", "go.mod", "go.sum"}
RUNTIME_METADATA = {"README.md", "BUILDINFO.txt", "RUNTIME.json", "LICENSES.json",
                    "THIRD-PARTY-NOTICES.txt", "SHA256SUMS"}
RUNTIME_BINARIES = {"bin/oheco-broker", "bin/oheco-broker-server", "libexec/oheco-broker",
                    "lib/runtime/libc++_shared.so"}
README = """# oheco-broker 0.3.0 source SDKs

Download this source SDK attachment from the GitHub Release and extract it
into an editable directory. The installed runtime package also includes SDK sources.
It contains complete C, Go and .NET SDK sources, pinned third-party source
fixtures, manifests, patches, licenses and offline build resources. Build output
belongs in a separate private temporary/cache directory. The SDK directories and
this module root may be moved together, including to paths containing spaces.

The legacy local C client is `sdk/c/oheco_broker.c` and `oheco_broker.h`; embed the
source or its CMake OBJECT target with C11/POSIX sockets/poll and pthreads.
For the management/peer C SDK, use `sdk/c/remote` and its complete inputs in
`sdk/c/tpr`. Install native C/C++, CMake, Ninja, Python 3 and Go first; HarmonyOS
also requires `binary-sign-tool` and a native OHOS toolchain. Then run:

```sh
: "${TMPDIR:?set a writable private temporary directory}"
: "${XDG_CACHE_HOME:?set a writable private cache directory}"
sh sdk/c/build.sh --build-dir "$XDG_CACHE_HOME/oheco-broker-sdk"
. "$XDG_CACHE_HOME/oheco-broker-sdk/remote-sdk/remote.env"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=vendor
```

The Go SDK in `sdk/go/remote` wraps this same native engine through cgo. Keep the
included `go.mod`, `go.sum`, `vendor` and `vendor-manifests` at the module root;
use the helper's include/link environment when building a Go consumer. Supply
the target platform's C/C++ runtimes and sign executables when required. The
helper-generated environment and compiled libraries remain local build outputs.

The managed local-command SDK in `sdk/dotnet` targets .NET 10 with no external
NuGet packages. Reference its project or include `BrokerProcess.cs`. Local C and
.NET clients connect to an independently installed `oheco-broker shell serve`;
they do not start it. Remote management/peer consumers connect to the trusted
service configured by their application.

Read `sdk/c/README.md`, `sdk/c/remote/README.md`, `sdk/go/README.md` and
`sdk/dotnet/README.md` for API integration. The source fixtures may
include `.o`, `.a`, `.pem` or `.key` files retained verbatim from pinned upstream
archives; they are test data, not SDK build outputs or personal signing material.

`BUILDINFO.txt` preserves the validated SDK source commit and identifies the
runtime archive from which these bytes were derived. `SHA256SUMS` checks every
file in this source SDK archive. Preserve `LICENSE`, dependency source notices,
`licenses`, `LICENSES.json` and `THIRD-PARTY-NOTICES.txt`. SDK builds are offline;
no account configuration, personal credentials or local SDK installation paths
are embedded in this archive. Application/server source and the full test suite
are available at https://github.com/oheco/oheco-broker.
"""


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_path(name):
    return name in SOURCE_FILES or any(name.startswith(tree + "/") for tree in SOURCE_TREES)


def validate_source_path(name):
    parts = PurePosixPath(name).parts
    if any(part in {".git", "__pycache__", "CMakeFiles", "node_modules"} for part in parts):
        raise ValueError(f"Unexpected source metadata/cache: {name}")
    path = PurePosixPath(name)
    if path.name in {"remote.env", "native-deps.env", "curl-deps.env", "CMakeCache.txt"}:
        raise ValueError(f"Unexpected source build environment: {name}")
    if name.startswith("sdk/") and not name.startswith("sdk/c/tpr/"):
        if any(part in {"bin", "obj", "cache", ".cache"} for part in parts) or path.suffix.lower() in {
            ".o", ".a", ".so", ".dll", ".pyc"
        }:
            raise ValueError(f"SDK-owned build output in source payload: {name}")


def parse_buildinfo(data):
    info = {}
    for line in data.decode("utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or not value or key in info:
            raise ValueError("Malformed runtime BUILDINFO entry")
        info[key] = value
    if info.get("version") != VERSION or not re.fullmatch(r"[0-9a-f]{40}", info.get("source_commit", "")):
        raise ValueError("Runtime archive must identify formal 0.3.0 and a source commit")
    return info


def derive(runtime_archive, output_dir, temporary):
    archive = output_dir / f"{SDK_ROOT}.tar.gz"
    checksum = output_dir / f"{SDK_ROOT}.SHA256SUMS"
    for path in (archive, checksum):
        if path.exists():
            raise ValueError(f"Refusing to overwrite immutable SDK output: {path}")
    runtime_digest = sha256(runtime_archive)
    with tempfile.TemporaryDirectory(prefix="broker-sdk-source-", dir=temporary) as name:
        work = Path(name)
        if work.stat().st_mode & 0o077:
            raise ValueError("TMPDIR filesystem must enforce private temporary permissions")
        payload = work / SDK_ROOT
        payload.mkdir()
        with tarfile.open(runtime_archive, "r:gz") as package:
            members, files, seen, folded = package.getmembers(), {}, set(), set()
            for member in members:
                path = PurePosixPath(member.name)
                if (path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != RUNTIME_ROOT or
                    path.as_posix() != member.name.rstrip("/") or
                    any(char in member.name for char in "\n\r\\\0") or
                    not (member.isfile() or member.isdir())):
                    raise ValueError(f"Unsafe/non-regular runtime archive path: {member.name!r}")
                if path.as_posix() in seen or path.as_posix().casefold() in folded:
                    raise ValueError(f"Duplicate/case-conflicting archive path: {member.name!r}")
                seen.add(path.as_posix())
                folded.add(path.as_posix().casefold())
                if member.isfile():
                    relative = path.relative_to(RUNTIME_ROOT).as_posix()
                    if not (source_path(relative) or relative in RUNTIME_METADATA or
                            relative in RUNTIME_BINARIES or relative.startswith("licenses/")):
                        raise ValueError(f"Unexpected runtime payload entry: {relative}")
                    if member.size < 0:
                        raise ValueError("Negative runtime payload size")
                    if source_path(relative):
                        validate_source_path(relative)
                    files[relative] = member
            required = SOURCE_FILES | RUNTIME_METADATA | RUNTIME_BINARIES
            if not required <= files.keys():
                raise ValueError("Runtime archive lacks required source/provenance/binary payload")
            for tree in SOURCE_TREES:
                if not any(path.startswith(tree + "/") for path in files):
                    raise ValueError(f"Runtime archive lacks complete SDK tree: {tree}")
            def contents(path):
                with package.extractfile(files[path]) as stream:
                    return stream.read()
            info = parse_buildinfo(contents("BUILDINFO.txt"))
            sums = {}
            for line in contents("SHA256SUMS").decode("utf-8").splitlines():
                match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
                if not match or match[2] in sums:
                    raise ValueError("Malformed/duplicate runtime checksum entry")
                sums[match[2]] = match[1]
            if set(sums) != set(files) - {"SHA256SUMS"}:
                raise ValueError("Runtime internal checksum inventory does not exactly cover payload")
            license_index = json.loads(contents("LICENSES.json"))
            actual_licenses = {path for path in files if path.startswith("licenses/")}
            if not isinstance(license_index, dict) or set(license_index) != actual_licenses:
                raise ValueError("Runtime license inventory is incomplete or has extra paths")
            # Check ALL files, including excluded executable/runtime payloads.
            for path, expected in sums.items():
                with package.extractfile(files[path]) as stream:
                    actual = hashlib.file_digest(stream, "sha256").hexdigest()
                if actual != expected:
                    raise ValueError(f"Runtime internal checksum mismatch: {path}")
            for key, path in (("cli_sha256", "libexec/oheco-broker"),
                              ("server_sha256", "bin/oheco-broker-server"),
                              ("runtime_sha256", "lib/runtime/libc++_shared.so")):
                if info.get(key) != sums[path]:
                    raise ValueError(f"Runtime BUILDINFO disagrees with actual {path}")
            selected = {path for path in files if source_path(path)}
            # The native distribution notice relates to the excluded C++ ELF.
            selected |= actual_licenses - {"licenses/OHOS-native-NOTICE.txt"}
            for path in sorted(selected):
                target = payload / path
                target.parent.mkdir(parents=True, exist_ok=True)
                with package.extractfile(files[path]) as stream, target.open("xb") as destination:
                    shutil.copyfileobj(stream, destination)
                target.chmod(0o755 if files[path].mode & 0o111 else 0o644)
                if sha256(target) != sums[path]:
                    raise ValueError(f"SDK source copy changed runtime payload bytes: {path}")
            notices = {path: license_index[path] for path in sorted(selected & actual_licenses)}
            for path, record in notices.items():
                target = payload / path
                if record != {"sha256": sha256(target), "bytes": target.stat().st_size}:
                    raise ValueError(f"Runtime source license record mismatch: {path}")
            timestamp = int(files["BUILDINFO.txt"].mtime)
        (payload / "README.md").write_text(README, encoding="utf-8")
        (payload / "BUILDINFO.txt").write_text(
            f"version={VERSION}\nsource_commit={info['source_commit']}\nsdk_source_only=true\n"
            f"derive_from_runtime_archive_sha256={runtime_digest}\n", encoding="utf-8")
        (payload / "LICENSES.json").write_text(json.dumps(notices, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        notice_text = (
            "Source SDK third-party notices\n\nAll vendored files retain their upstream license/copyright headers, including\n"
            "embedded support-code notices and pinned test fixtures. LICENSES.json indexes\n"
            "source license/notice/patent/copyright copies, Go toolchain notices and SQLite's\n"
            "public-domain blessing. libjuice and the recorded relay-policy changes are\n"
            "provided in complete source form under MPL-2.0.\n")
        for path in ("vendor/modules.txt", "sdk/c/tpr/native-dependencies.json", "sdk/c/tpr/manifests/curl.json"):
            if not (payload / path).is_file():
                raise ValueError(f"Source SDK lacks pinned dependency provenance: {path}")
            notice_text += "\n" + path + ":\n" + (payload / path).read_text(encoding="utf-8")
        (payload / "THIRD-PARTY-NOTICES.txt").write_text(notice_text, encoding="utf-8")
        hashes = {path.relative_to(payload).as_posix(): sha256(path)
                  for path in sorted(payload.rglob("*")) if path.is_file()}
        manifest = "".join(f"{value}  {path}\n" for path, value in hashes.items()).encode("utf-8")
        (payload / "SHA256SUMS").write_bytes(manifest)
        manifest_digest = hashlib.sha256(manifest).hexdigest()
        def normalize(member):
            if not (member.isfile() or member.isdir()):
                raise ValueError("Unexpected non-regular source SDK entry")
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mtime = timestamp
            member.mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
            return member
        staged = work / archive.name
        with staged.open("xb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as package:
                    package.add(payload, arcname=SDK_ROOT, filter=normalize)
        sdk_digest = sha256(staged)
        output_dir.mkdir(parents=True, exist_ok=True)
        with archive.open("xb") as target, staged.open("rb") as original:
            shutil.copyfileobj(original, target)
        with checksum.open("x", encoding="ascii") as target:
            target.write(f"{sdk_digest}  {archive.name}\n")
        return {"archive": str(archive), "size": archive.stat().st_size, "sha256": sdk_digest,
                "source_commit": info["source_commit"], "runtime_archive_sha256": runtime_digest,
                "sdk_manifest_sha256": manifest_digest, "source_files": len(hashes) + 1,
                "checksum": str(checksum)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime_archive", type=Path)
    parser.add_argument("--output-dir", type=Path, help="Default: input archive directory")
    args = parser.parse_args()
    temporary = os.environ.get("TMPDIR")
    if not temporary or not Path(temporary).is_absolute() or not Path(temporary).is_dir():
        parser.error("TMPDIR must name an existing absolute private temporary directory")
    archive = args.runtime_archive.resolve()
    if not archive.is_file() or archive.name != RUNTIME_ROOT + ".tar.gz":
        parser.error("Input must be the verified oheco-broker-0.3.0-ohos-arm64.tar.gz archive")
    result = derive(archive, (args.output_dir or archive.parent).resolve(), temporary)
    for key, value in result.items():
        print(f"{key}={value}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, tarfile.TarError) as error:
        raise SystemExit(f"SDK source packaging failed: {error}") from error
