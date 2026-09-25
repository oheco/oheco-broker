#!/usr/bin/env python3
"""Build an immutable native release candidate from a clean committed snapshot.

Requires native ohos/arm64 Go, binary-sign-tool and Python 3.12+. All intermediate
files live under TMPDIR. Output: dist/<name>.tar.gz, SHA256SUMS, <name>.build.log.
Only the signed binary, source SDKs, protocol and install documentation/notices
are archived; the complete committed snapshot stays private for the native build.
This does not tag, upload or publish anything and refuses to replace an archive.
"""
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile


# Explicit install payload: never recursively archive the private build snapshot.
# Destination -> committed source path. SDK additions require deliberate review.
SOURCE_FILES = {name: name for name in (
    "LICENSE", "protocol/PROTOCOL.md",
    "sdk/c/CMakeLists.txt", "sdk/c/README.md", "sdk/c/oheco_broker.c", "sdk/c/oheco_broker.h",
    "sdk/dotnet/BrokerProcess.cs", "sdk/dotnet/Oheco.Broker.csproj", "sdk/dotnet/README.md",
)}
SOURCE_FILES["README.md"] = "docs/PACKAGE-README.md"


def stage_sources(source, payload):
    for destination, origin in SOURCE_FILES.items():
        path = source / origin
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"Missing/non-regular SDK package source: {origin}")
        target = payload / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def output(*args, cwd):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def main():
    root = Path(__file__).resolve().parent.parent
    temporary = os.environ.get("TMPDIR")
    if not temporary:
        raise SystemExit("TMPDIR must name a writable private directory")
    if output("git", "status", "--porcelain", cwd=root):
        raise SystemExit("Commit source changes before packaging; worktree must be clean")
    target = output("go", "env", "GOOS", "GOARCH", cwd=root).splitlines()
    if target != ["ohos", "arm64"]:
        raise SystemExit("Release packages must be built natively with ohos/arm64 Go")
    commit = output("git", "rev-parse", "HEAD", cwd=root)
    timestamp = int(output("git", "show", "-s", "--format=%ct", "HEAD", cwd=root))
    toolchain = output("go", "version", cwd=root)
    goroot = Path(output("go", "env", "GOROOT", cwd=root))
    signer = shutil.which("binary-sign-tool")
    if not signer:
        raise SystemExit("binary-sign-tool is required in PATH")
    version_text = output("git", "show", "HEAD:cmd/oheco-broker/main.go", cwd=root)
    match = re.search(r'^const version = "([0-9]+\.[0-9]+\.[0-9]+)"$', version_text, re.M)
    if not match:
        raise SystemExit("Cannot determine release version from committed main.go")
    version = match.group(1)
    name = f"oheco-broker-{version}-ohos-arm64"
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    archive = dist / f"{name}.tar.gz"
    if archive.exists():
        raise SystemExit(f"Refusing to overwrite {archive}; released bytes are immutable")
    log_path = dist / f"{name}.build.log"
    with tempfile.TemporaryDirectory(prefix="broker-package-", dir=temporary) as work, log_path.open("w") as log:
        work = Path(work)
        source = work / "source"
        source.mkdir()
        payload = work / name
        payload.mkdir()
        snapshot = subprocess.check_output(["git", "archive", "--format=tar", "HEAD"], cwd=root)
        with tarfile.open(fileobj=io.BytesIO(snapshot)) as source_tar:
            source_tar.extractall(source, filter="data")
        env = dict(os.environ, GOCACHE=str(work / "gocache"), GOTMPDIR=str(work),
                   TMPDIR=str(work), GOPROXY="off", GOSUMDB="off")

        def run(args):
            print("+ " + " ".join(map(str, args)), file=log, flush=True)
            subprocess.run(args, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)

        binary = source / "bin" / "oheco-broker"
        binary.parent.mkdir()
        run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(binary), "./cmd/oheco-broker"])
        signed = work / "oheco-broker.signed"
        run([signer, "sign", "-inFile", str(binary), "-outFile", str(signed), "-selfSign", "1"])
        shutil.copyfile(signed, binary)
        binary.chmod(0o755)
        actual = output(str(binary), "--version", cwd=source)
        if actual != f"oheco-broker {version}":
            raise SystemExit(f"Version mismatch: {actual}")
        run([signer, "display-sign", "-inFile", str(binary)])
        stage_sources(source, payload)
        (payload / "bin").mkdir()
        shutil.copyfile(binary, payload / "bin/oheco-broker")
        (payload / "bin/oheco-broker").chmod(0o755)
        license_dir = payload / "licenses"
        license_dir.mkdir()
        for filename in ("LICENSE", "PATENTS"):
            shutil.copyfile(goroot / filename, license_dir / f"Go-{filename}")
        for module in ("crypto", "net", "sys", "text"):
            shutil.copyfile(goroot / "src" / "vendor" / "golang.org" / "x" / module / "LICENSE",
                            license_dir / f"Go-vendor-x-{module}-LICENSE")
        binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        (payload / "BUILDINFO.txt").write_text(
            f"version={version}\nplatform=ohos-arm64\nsource_commit={commit}\n"
            f"toolchain={toolchain}\nbinary_sha256={binary_digest}\n"
            "runtime_dependencies=system libc.so\n"
            "configuration=none; foreground; unauthenticated loopback development service\n",
            encoding="utf-8")

        def normalize(info):
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = timestamp
            if not (info.isfile() or info.isdir()):
                raise RuntimeError(f"Unexpected non-regular release entry: {info.name}")
            info.mode = 0o755 if info.isdir() or info.mode & 0o111 else 0o644
            return info

        # Create exclusively: never replace a locally staged or published archive.
        with archive.open("xb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as packed:
                    packed.add(payload, arcname=name, filter=normalize)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (dist / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n", encoding="ascii")
        print(f"source_commit={commit}")
        print(f"archive={archive}")
        print(f"size={archive.stat().st_size}")
        print(f"sha256={digest}")
        print(f"build_log={log_path}")


if __name__ == "__main__":
    main()
