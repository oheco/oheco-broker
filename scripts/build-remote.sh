#!/bin/sh
# Full-checkout entry: the SDK builds independently; only this wrapper adds tests.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "${1:-}" in --help|-h) exec sh "$root/sdk/c/build.sh" --help ;; esac
[ "$#" = 0 ] || { printf '%s\n' 'Use SDK build.sh --build-dir for an independent SDK; repository builds use OB_SDK_BUILD_DIR overrides' >&2; exit 2; }
: "${XDG_CACHE_HOME:?private build cache required}"
: "${TMPDIR:?private temporary directory required}"
# Skip dependency rebuilds only after the same inputs passed SDK build/probes.
if [ "${OB_SKIP_SDK_BUILD:-0}" != 1 ]; then sh "$root/sdk/c/build.sh"; fi
base=${OB_SDK_BUILD_DIR:-${XDG_CACHE_HOME%/}/oheco-broker}
build=${OB_REMOTE_BUILD_DIR:-$base/remote-sdk}
. "$build/remote.env"
export GOFLAGS=-mod=vendor
cmake=${CMAKE:-cmake}
"$cmake" -S "$root/sdk/c/remote" -B "$build" -G Ninja \
    -DOB_NATIVE_PREFIX="$OB_NATIVE_PREFIX" -DOB_CURL_PREFIX="$OB_CURL_PREFIX" \
    -DOB_CXX_RUNTIME="$OB_CXX_RUNTIME" -DOB_REMOTE_BUILD_TESTS=ON \
    -DOB_REMOTE_TEST_SOURCE_DIR="$root/tests/c"
"$cmake" --build "$build" --parallel "${NATIVE_JOBS:-4}"
sign_work=$(mktemp -d "${TMPDIR%/}/oheco-native-test-sign.XXXXXX")
trap 'rm -rf "$sign_work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
for name in remote_peer_test websocket_test recovery_peer_test auth_refresh_test udp_fault_preload.so; do
    binary="$build/$name"
    # The platform signer cannot reliably replace an existing signed output.
    # Fresh input/output also avoids modifying an inode used by an older test.
    cp "$binary" "$sign_work/$name"
    if [ "$(go env GOOS)" = ohos ]; then
        binary-sign-tool sign -inFile "$sign_work/$name" -outFile "$sign_work/$name.signed" -selfSign 1
        chmod 755 "$sign_work/$name.signed"
    else
        cp "$sign_work/$name" "$sign_work/$name.signed"
    fi
    mv -f "$sign_work/$name.signed" "$binary.signed"
done
python3 - "$build" <<'PY'
import pathlib, shlex, sys
build = pathlib.Path(sys.argv[1])
with (build/'remote.env').open('a') as env:
    for key, value in {'GOFLAGS':'-mod=vendor', 'OB_REMOTE_TEST':str(build/'remote_peer_test.signed'),
                       'OB_WS_TEST':str(build/'websocket_test.signed'),
                       'OB_RECOVERY_TEST':str(build/'recovery_peer_test.signed'),
                       'OB_AUTH_TEST':str(build/'auth_refresh_test.signed'),
                       'OB_UDP_FAULT_PRELOAD':str(build/'udp_fault_preload.so.signed')}.items():
        env.write('export '+key+'='+shlex.quote(value)+'\n')
PY
printf 'Built full-checkout tests; source %s/remote.env for Go/cgo builds.\n' "$build"
