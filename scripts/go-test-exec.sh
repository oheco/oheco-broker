#!/usr/bin/sh
# go test -exec wrapper: sign the actual temporary test executable on OHOS.
set -eu
binary=$1
shift
if [ "$(go env GOOS)" = ohos ]; then
    signed="$binary.ob-signed"
    trap 'rm -f "$signed"' EXIT
    binary-sign-tool sign -inFile "$binary" -outFile "$signed" -selfSign 1 >/dev/null
    chmod 755 "$signed"
    "$signed" "$@"
else
    "$binary" "$@"
fi
