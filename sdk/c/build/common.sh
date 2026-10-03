#!/bin/sh
# Shared native-only tooling. Sourced by SDK-owned offline builders.
cc=${CC:-clang}
cxx=${CXX:-clang++}
cmake=${CMAKE:-cmake}
for tool in "$cc" "$cxx" "$cmake" ninja python3; do
    command -v "$tool" >/dev/null || { printf 'Missing tool: %s\n' "$tool" >&2; exit 1; }
done
triple=$("$cc" -dumpmachine)
case "$triple" in
    *ohos*) sdk_platform=ohos; sdk_cxx_runtime=c++ ;;
    *linux*) sdk_platform=linux; sdk_cxx_runtime=stdc++ ;;
    *) printf 'Unsupported native compiler target: %s\n' "$triple" >&2; exit 1 ;;
esac
sdk_cxx_runtime=${OB_CXX_RUNTIME:-$sdk_cxx_runtime}
case "$sdk_cxx_runtime" in c++|stdc++) ;; *) printf '%s\n' 'OB_CXX_RUNTIME must be c++ or stdc++' >&2; exit 1 ;; esac
if [ "$sdk_platform" = ohos ]; then command -v binary-sign-tool >/dev/null; fi
export CC="$cc" CXX="$cxx" OB_CXX_RUNTIME="$sdk_cxx_runtime"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local

sdk_output_directory() {
    case "$1" in /*) ;; *) printf '%s\n' 'Build directories must be absolute' >&2; exit 1 ;; esac
    if [ "$sdk_platform" = ohos ]; then
        case "$1/" in "$HOME/"*) printf '%s\n' 'OHOS outputs must not be stored on HOME/hmdfs' >&2; exit 1 ;; esac
    fi
}
sdk_run() {
    binary=$1; shift
    if [ "$sdk_platform" = ohos ]; then
        binary-sign-tool sign -inFile "$binary" -outFile "$binary.signed" -selfSign 1
        chmod 755 "$binary.signed"
        "$binary.signed" "$@"
    else
        "$binary" "$@"
    fi
}
# Relocating an SDK changes CMake's source path. Only discard a cache owned by
# this build directory when it belongs to the old source location.
sdk_refresh_cache() {
    python3 - "$1" "$2" <<'PY'
import pathlib, shutil, sys
source, output = map(pathlib.Path, sys.argv[1:])
cache = output / 'CMakeCache.txt'
if cache.is_file():
    old = next((line.partition('=')[2] for line in cache.read_text().splitlines()
                if line.startswith('CMAKE_HOME_DIRECTORY:')), '')
    if old and pathlib.Path(old).resolve() != source.resolve():
        shutil.rmtree(output)
PY
}
