#!/bin/sh
# Local offline Linux C SDK consumer build. No upload, SSH, or network work.
set -eu
umask 077
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_root=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --build-dir) [ "$#" -ge 2 ] || exit 2; build_root=$2; shift 2 ;;
        --help|-h) printf '%s\n' 'Usage: sh scripts/deploy-client-build.sh --build-dir ABSOLUTE_PATH' 'Run on native Linux with GCC/G++, CMake, Ninja, Python 3 and TMPDIR.' 'Builds the pinned SDK and the public-peer consumer locally; performs no network acceptance.'; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -n "$build_root" ] || { printf '%s\n' '--build-dir is required' >&2; exit 2; }
case "$build_root" in /*) ;; *) printf '%s\n' '--build-dir must be absolute' >&2; exit 2 ;; esac
: "${TMPDIR:?private temporary directory required}"
export CC=${CC:-gcc} CXX=${CXX:-g++}
case "$("$CC" -dumpmachine)" in *linux*ohos*) printf '%s\n' 'Run this consumer build on Linux' >&2; exit 1 ;; *linux*) ;; *) printf '%s\n' 'Run this consumer build on Linux' >&2; exit 1 ;; esac
# The shared SDK builder uses the real native probes and the GNU C++ runtime.
sh "$root/sdk/c/build.sh" --build-dir "$build_root"
. "$build_root/remote-sdk/remote.env"
mkdir -p "$build_root/bin"
priv=$(mktemp -d "${TMPDIR%/}/linux-peer-build.XXXXXX")
trap 'rm -rf "$priv"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export TMPDIR="$priv"
python3 - "$root/tests/public_peer.c" "$priv/public-peer" <<'PY'
import os, shlex, subprocess, sys
flags = shlex.split(os.environ['CGO_CFLAGS'])
flags += ['-I'+os.environ['OB_NATIVE_PREFIX']+'/include', '-I'+os.environ['OB_CURL_PREFIX']+'/include']
subprocess.run([os.environ['CC'], '-std=c11', '-O2', '-pthread', '-DJUICE_STATIC', '-DCURL_STATICLIB',
                '-Wall', '-Wextra', '-Werror', *flags, sys.argv[1],
                *shlex.split(os.environ['CGO_LDFLAGS']), '-o', sys.argv[2]], check=True)
PY
"$priv/public-peer" --version
python3 - "$priv/public-peer" "$build_root" <<'PY'
import hashlib, json, pathlib, shutil, subprocess, sys, time
binary, output = map(pathlib.Path, sys.argv[1:])
version = json.loads(subprocess.check_output([str(binary), '--version'], text=True))
report = {'created_unix':int(time.time()), 'native_target':subprocess.check_output(
          [__import__('os').environ['CC'], '-dumpmachine'], text=True).strip(),
          'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
          'offline_version':version, 'network_acceptance':'NOT RUN'}
if shutil.which('readelf'):
    report['elf_header'] = subprocess.check_output(['readelf', '-h', str(binary)], text=True)
    report['elf_dynamic'] = subprocess.check_output(['readelf', '-d', str(binary)], text=True)
(output/'build-report.json').write_text(json.dumps(report, indent=2)+'\n')
(output/'SHA256SUMS').write_text(report['binary_sha256']+'  bin/public-peer\n')
PY
cp "$priv/public-peer" "$build_root/bin/public-peer.new"
chmod 700 "$build_root/bin/public-peer.new"
mv "$build_root/bin/public-peer.new" "$build_root/bin/public-peer"
printf 'Native peer: %s/bin/public-peer\nReport: %s/build-report.json\n' "$build_root" "$build_root"
