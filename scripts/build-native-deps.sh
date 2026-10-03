#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec sh "$root/sdk/c/build/build-native-deps.sh" "$@"
