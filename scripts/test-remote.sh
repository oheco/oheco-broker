#!/usr/bin/sh
# Offline native local acceptance. Never touches installed/user broker state.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${TMPDIR:?private temporary directory required}"
: "${XDG_CACHE_HOME:?private cache directory required}"
# Set skips only after the same source has passed the corresponding gates.
if [ "${OB_SKIP_BUILD:-0}" != 1 ]; then sh "$root/scripts/build-remote.sh"; fi
. "$XDG_CACHE_HOME/oheco-broker/remote-sdk/remote.env"
priv=$(mktemp -d "${TMPDIR%/}/oheco-remote-tests.XXXXXX")
trap 'rm -rf "$priv"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$priv/temp" "$priv/home"
export TMPDIR="$priv/temp" GOTMPDIR="$priv/temp" HOME="$priv/home"
# A fresh cache ensures Go/cgo cannot reuse links against old external archives.
export GOCACHE="$priv/gocache" GOPROXY=off GOSUMDB=off GOFLAGS=-mod=vendor
cd "$root"
if [ "${OB_SKIP_GO_CHECKS:-0}" != 1 ]; then
    go test -count=1 -timeout=180s -exec "sh $root/scripts/go-test-exec.sh" ./...
    go vet ./...
fi
# Isolated HOME deliberately has no user's Git safe.directory configuration.
# Local fixtures record the source baseline separately, not via VCS stamping.
go build -buildvcs=false -trimpath -o "$priv/oheco-broker" ./cmd/oheco-broker
go build -buildvcs=false -trimpath -o "$priv/control-fixture" ./tests/control-server
clang -std=c11 -D_GNU_SOURCE -DJUICE_STATIC -DCURL_STATICLIB -Wall -Wextra -Werror -pthread \
    -I"$root/sdk/c/remote" -I"$OB_NATIVE_PREFIX/include" -I"$OB_CURL_PREFIX/include" \
    "$root/sdk/c/remote/ob_api.c" "$root/sdk/c/remote/ob_json.c" "$root/tests/c/remote_api_test.c" \
    "$OB_CURL_PREFIX/lib/libcurl.a" "$OB_NATIVE_PREFIX/lib/libcjson.a" \
    "$OB_NATIVE_PREFIX/lib/libssl.a" "$OB_NATIVE_PREFIX/lib/libcrypto.a" \
    -lc++ -pthread -lm -ldl -o "$priv/remote-api-test"
for binary in "$priv/oheco-broker" "$priv/control-fixture" "$priv/remote-api-test"; do
    if [ "$(go env GOOS)" = ohos ]; then
        binary-sign-tool sign -inFile "$binary" -outFile "$binary.signed" -selfSign 1 >/dev/null
        chmod 755 "$binary.signed"
        mv "$binary.signed" "$binary"
    fi
done
"$priv/remote-api-test"
"$priv/remote-api-test" --keylog-existing
"$OB_WS_TEST"
"$OB_REMOTE_TEST"
python3 "$root/tests/cli_control.py" "$priv/oheco-broker"
python3 "$root/tests/remote_acceptance.py" --fixture "$priv/control-fixture" \
    --native "$OB_REMOTE_TEST" --api-test "$priv/remote-api-test" --binary "$priv/oheco-broker"
python3 "$root/tests/peer_lifecycle.py" --fixture "$priv/control-fixture" --binary "$priv/oheco-broker"
printf '%s\n' 'PASS local Go/SQLite/Pion STUN-TURN/C API/xquic TCP-UDP/Go CLI acceptance'
