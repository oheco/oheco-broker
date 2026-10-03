#!/usr/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${TMPDIR:?TMPDIR must be a writable private directory}"
sh "$root/scripts/build-remote.sh"
. "$XDG_CACHE_HOME/oheco-broker/remote-sdk/remote.env"
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
# Native artifacts belong on a real cache filesystem, not HOME/hmdfs. Avoid
# overwriting the old checkout binary or an inode used by a running process.
dest="$XDG_CACHE_HOME/oheco-broker/bin"
mkdir -p "$dest"
staged=$(mktemp "$dest/.oheco-broker.XXXXXX")
trap 'rm -rf "$priv"; rm -f "$staged"' EXIT
cp -p "$priv/oheco-broker" "$staged"
mv -f "$staged" "$dest/oheco-broker"
"$dest/oheco-broker" --version
printf 'Built %s\n' "$dest/oheco-broker"
