#!/bin/sh
# Full-checkout entry: the SDK builds independently; only this wrapper adds tests.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "${1:-}" in --help|-h) exec sh "$root/sdk/c/build.sh" --help ;; esac
[ "$#" = 0 ] || { printf '%s\n' 'Use SDK build.sh --build-dir for an independent SDK; repository builds use OB_SDK_BUILD_DIR overrides' >&2; exit 2; }
: "${XDG_CACHE_HOME:?private build cache required}"
: "${TMPDIR:?private temporary directory required}"
sh "$root/sdk/c/build.sh"
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
for name in remote_peer_test websocket_test; do
    binary="$build/$name"
    if [ "$(go env GOOS)" = ohos ]; then
        binary-sign-tool sign -inFile "$binary" -outFile "$binary.signed" -selfSign 1 >/dev/null
        chmod 755 "$binary.signed"
    else
        cp "$binary" "$binary.signed"
    fi
done
python3 - "$build" <<'PY'
import pathlib, shlex, sys
build = pathlib.Path(sys.argv[1])
with (build/'remote.env').open('a') as env:
    for key, value in {'GOFLAGS':'-mod=vendor', 'OB_REMOTE_TEST':str(build/'remote_peer_test.signed'),
                       'OB_WS_TEST':str(build/'websocket_test.signed')}.items():
        env.write('export '+key+'='+shlex.quote(value)+'\n')
PY
printf 'Built full-checkout tests; source %s/remote.env for Go/cgo builds.\n' "$build"
