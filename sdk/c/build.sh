#!/bin/sh
# Build the extracted C SDK and its complete pinned inputs without a repository.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build_root=${OB_SDK_BUILD_DIR:-}
while [ "$#" -gt 0 ]; do
    case "$1" in
        --build-dir) [ "$#" -ge 2 ] || { printf '%s\n' 'Missing --build-dir value' >&2; exit 2; }; build_root=$2; shift 2 ;;
        --help|-h) printf '%s\n' 'Usage: sh build.sh [--build-dir ABSOLUTE_PATH]' 'Requires native C/C++, CMake, Ninja, Python 3, TMPDIR and a private build/cache directory.' 'All dependencies are local. OHOS probes require binary-sign-tool; Linux uses the native C++ runtime.'; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done
: "${TMPDIR:?private temporary directory required}"
if [ -z "$build_root" ]; then
    : "${XDG_CACHE_HOME:?set XDG_CACHE_HOME or pass --build-dir}"
    build_root="${XDG_CACHE_HOME%/}/oheco-broker"
fi
export XDG_CACHE_HOME=${XDG_CACHE_HOME:-$build_root}
. "$root/build/common.sh"
sdk_output_directory "$build_root"
export NATIVE_BUILD_DIR=${NATIVE_BUILD_DIR:-$build_root/native-deps}
export NATIVE_PREFIX="$NATIVE_BUILD_DIR/prefix"
export CURL_BUILD_DIR=${CURL_BUILD_DIR:-$build_root/curl-deps}
build=${OB_REMOTE_BUILD_DIR:-$build_root/remote-sdk}
sdk_output_directory "$build"
sh "$root/build/build-native-deps.sh"
sh "$root/build/build-curl-deps.sh"
native="$NATIVE_BUILD_DIR/prefix"
curl="$CURL_BUILD_DIR/prefix"
sdk_refresh_cache "$root/remote" "$build"
"$cmake" -S "$root/remote" -B "$build" -G Ninja \
    -DCMAKE_C_COMPILER="$cc" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
    -DOB_NATIVE_PREFIX="$native" -DOB_CURL_PREFIX="$curl" \
    -DOB_CXX_RUNTIME="$sdk_cxx_runtime" -DOB_REMOTE_BUILD_TESTS=OFF
"$cmake" --build "$build" --parallel "${NATIVE_JOBS:-4}"
python3 - "$build" "$native" "$curl" "$root" "$sdk_cxx_runtime" <<'PY'
import pathlib, shlex, sys
build, native, curl, root = sys.argv[1:5]
quote = shlex.quote
flags = ' '.join('-L'+quote(str(pathlib.Path(p)/'lib')) for p in (native, curl))
flags = '-L'+quote(build)+' '+flags+' -lob_remote -lcurl -lxquic-static -ljuice -lcjson -lssl -lcrypto -l'+sys.argv[5]+' -pthread -lm -ldl'
values = {'OB_REMOTE_BUILD':build, 'OB_NATIVE_PREFIX':native, 'OB_CURL_PREFIX':curl,
          'OB_CXX_RUNTIME':sys.argv[5], 'CGO_ENABLED':'1',
          'CGO_CFLAGS':'-I'+quote(str(pathlib.Path(root)/'remote')), 'CGO_LDFLAGS':flags,
          'GOPROXY':'off', 'GOSUMDB':'off'}
pathlib.Path(build, 'remote.env').write_text(''.join('export '+k+'='+quote(v)+'\n' for k,v in values.items()))
PY
printf 'Built source SDK: %s/libob_remote.a\nLocal consumer environment: %s/remote.env\n' "$build" "$build"
