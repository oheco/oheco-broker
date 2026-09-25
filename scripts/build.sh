#!/usr/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${TMPDIR:?TMPDIR must be a writable private directory}"
priv=$(mktemp -d "${TMPDIR%/}/oheco-broker-build.XXXXXX")
trap 'rm -rf "$priv"' EXIT
export GOCACHE="$priv/gocache" GOTMPDIR="$priv" GOPROXY=off GOSUMDB=off
cd "$root"
go build -trimpath -o "$priv/oheco-broker" ./cmd/oheco-broker
if [ "$(go env GOOS)" = ohos ]; then
    command -v binary-sign-tool >/dev/null
    binary-sign-tool sign -inFile "$priv/oheco-broker" -outFile "$priv/oheco-broker.signed" -selfSign 1
    # Create the destination with executable mode before copying signed bytes.
    cp "$priv/oheco-broker.signed" "$priv/oheco-broker"
fi
"$priv/oheco-broker" --version
mkdir -p "$root/build"
cp -p "$priv/oheco-broker" "$root/build/oheco-broker"
"$root/build/oheco-broker" --version
printf 'Built %s\n' "$root/build/oheco-broker"
