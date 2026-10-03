#!/usr/bin/sh
# Offline native consumer build. Upstream xquic/cJSON/BoringSSL are pristine.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${XDG_CACHE_HOME:?private native build cache required}"
: "${TMPDIR:?private temporary directory required}"
umask 077
priv=$(mktemp -d "${TMPDIR%/}/oheco-native.XXXXXX")
trap 'rm -rf "$priv"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export TMPDIR="$priv" GOTMPDIR="$priv" GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
export GOCACHE="${XDG_CACHE_HOME%/}/oheco-broker/native-go"
build=${NATIVE_BUILD_DIR:-${XDG_CACHE_HOME%/}/oheco-broker/native-deps}
case "$build" in /*) ;; *) printf '%s\n' 'NATIVE_BUILD_DIR must be absolute' >&2; exit 1 ;; esac
prefix="$build/prefix"
jobs=${NATIVE_JOBS:-4}
. "$root/build/common.sh"
sdk_output_directory "$build"
python3 "$root/build/check-native-sources.py"
mkdir -p "$build" "$prefix/include" "$prefix/lib" "$GOCACHE"
configure() {
    src=$1; out=$2; shift 2
    sdk_refresh_cache "$src" "$out"
    "$cmake" -S "$src" -B "$out" -G Ninja \
        -DCMAKE_C_COMPILER="$cc" -DCMAKE_CXX_COMPILER="$cxx" \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        "-DCMAKE_C_FLAGS=-ffile-prefix-map=\"$root=.\" -ffile-prefix-map=\"$build=./native-build\"" \
        "-DCMAKE_CXX_FLAGS=-ffile-prefix-map=\"$root=.\" -ffile-prefix-map=\"$build=./native-build\"" \
        -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
        -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_SHARED_LIBS=OFF "$@"
}
configure "$root/tpr/boringssl" "$build/boringssl" -DBUILD_TESTING=OFF -DFIPS=OFF -DOPENSSL_NO_ASM=ON
"$cmake" --build "$build/boringssl" --target ssl crypto -j "$jobs"
cp "$build/boringssl/libssl.a" "$build/boringssl/libcrypto.a" "$prefix/lib/"
cp -R "$root/tpr/boringssl/include/openssl" "$prefix/include/"
# Stock xquic CMake writes xqc_configure.h into its source directory. Build a
# cache-owned source snapshot instead of editing the checked-in upstream tree.
python3 - "$root/tpr/xquic" "$build/xquic-source" <<'PY'
import hashlib,pathlib,shutil,sys
source,dest=map(pathlib.Path,sys.argv[1:]);h=hashlib.sha256()
for p in sorted(source.rglob('*')):
    if p.is_file():
        name=p.relative_to(source).as_posix();h.update(name.encode()+b'\0');h.update(hashlib.sha256(p.read_bytes()).digest())
stamp=dest.parent/'xquic-source.sha256';digest=h.hexdigest()
if not dest.is_dir() or not stamp.is_file() or stamp.read_text().strip()!=digest:
    if dest.exists():shutil.rmtree(dest)
    shutil.copytree(source,dest)
    stamp.write_text(digest+'\n')
PY
configure "$build/xquic-source" "$build/xquic-pristine" \
    -DSSL_TYPE=boringssl -DSSL_PATH="$root/tpr/boringssl" \
    -DSSL_INC_PATH="$prefix/include" \
    "-DSSL_LIB_PATH=$prefix/lib/libssl.a;$prefix/lib/libcrypto.a" \
    -DXQC_ENABLE_TESTING=OFF -DXQC_ENABLE_MOQ=OFF \
    -DXQC_ENABLE_BBR2=OFF -DXQC_ENABLE_COPA=OFF -DXQC_ENABLE_RENO=OFF \
    -DXQC_ENABLE_UNLIMITED=OFF -DXQC_ENABLE_MP_INTEROP=OFF \
    -DXQC_ENABLE_FEC=OFF -DXQC_ENABLE_XOR=OFF -DXQC_ENABLE_RSC=OFF \
    -DXQC_ENABLE_PKM=OFF -DXQC_SUPPORT_SENDMMSG_BUILD=OFF \
    -DXQC_ENABLE_EVENT_LOG=OFF -DXQC_PRINT_SECRET=OFF -DGCOV=off
"$cmake" --build "$build/xquic-pristine" --target xquic-static -j "$jobs"
cp "$build/xquic-pristine/libxquic-static.a" "$prefix/lib/"
cp -R "$build/xquic-source/include/xquic" "$prefix/include/"
configure "$root/tpr/libjuice" "$build/libjuice" \
    -DNO_TESTS=ON -DNO_SERVER=ON -DUSE_NETTLE=OFF -DFUZZER=OFF \
    -DDISABLE_CONSENT_FRESHNESS=OFF -DENABLE_LOCALHOST_ADDRESS=ON
"$cmake" --build "$build/libjuice" --target juice -j "$jobs"
"$cmake" --install "$build/libjuice"
configure "$root/tpr/cjson" "$build/cjson" \
    -DENABLE_CJSON_TEST=OFF -DENABLE_CJSON_UTILS=OFF \
    -DENABLE_CUSTOM_COMPILER_FLAGS=OFF -DENABLE_SANITIZERS=OFF \
    -DCMAKE_C_STANDARD=11 -DCMAKE_C_STANDARD_REQUIRED=ON
"$cmake" --build "$build/cjson" --target cjson -j "$jobs"
"$cmake" --install "$build/cjson"
python3 - "$build" "$prefix" "$sdk_cxx_runtime" <<'PY'
import pathlib,shlex,sys
build,prefix=map(pathlib.Path,sys.argv[1:3]);runtime=sys.argv[3];libs=['libxquic-static.a','libjuice.a','libcjson.a','libssl.a','libcrypto.a']
values={'NATIVE_BUILD_DIR':str(build),'NATIVE_PREFIX':str(prefix),'NATIVE_INCLUDE_DIR':str(prefix/'include'),
        'BORINGSSL_BUILD_DIR':str(build/'boringssl'),'BORINGSSL_INCLUDE_DIR':str(prefix/'include'),
        'BORINGSSL_SSL_LIBRARY':str(prefix/'lib/libssl.a'),'BORINGSSL_CRYPTO_LIBRARY':str(prefix/'lib/libcrypto.a'),
        'XQUIC_LIBRARY':str(prefix/'lib/libxquic-static.a'),'JUICE_LIBRARY':str(prefix/'lib/libjuice.a'),'CJSON_LIBRARY':str(prefix/'lib/libcjson.a'),
        'NATIVE_CPPFLAGS':'-I'+shlex.quote(str(prefix/'include'))+' -DJUICE_STATIC',
        'NATIVE_LDFLAGS':' '.join(shlex.quote(str(prefix/'lib'/n)) for n in libs)+' -l'+runtime+' -pthread -lm -ldl'}
(build/'native-deps.env').write_text(''.join('export '+k+'='+shlex.quote(v)+'\n' for k,v in values.items()))
cm='find_package(Threads REQUIRED)\n'
for name,lib in zip(['xquic','juice','cjson','ssl','crypto'],libs):
    cm+='if(NOT TARGET OhecoNative::'+name+')\n  add_library(OhecoNative::'+name+' STATIC IMPORTED)\n  set_target_properties(OhecoNative::'+name+' PROPERTIES IMPORTED_LOCATION "'+str(prefix/'lib'/lib)+'" INTERFACE_INCLUDE_DIRECTORIES "'+str(prefix/'include')+'")\nendif()\n'
cm+='set_property(TARGET OhecoNative::juice PROPERTY INTERFACE_COMPILE_DEFINITIONS JUICE_STATIC)\n'
cm+='set_property(TARGET OhecoNative::juice PROPERTY INTERFACE_LINK_LIBRARIES Threads::Threads)\n'
cm+='set_property(TARGET OhecoNative::ssl PROPERTY INTERFACE_LINK_LIBRARIES OhecoNative::crypto)\n'
cm+='set_property(TARGET OhecoNative::crypto PROPERTY INTERFACE_LINK_LIBRARIES "'+runtime+';Threads::Threads")\n'
cm+='set_property(TARGET OhecoNative::cjson PROPERTY INTERFACE_LINK_LIBRARIES m)\n'
cm+='set_property(TARGET OhecoNative::xquic PROPERTY INTERFACE_LINK_LIBRARIES "OhecoNative::ssl;OhecoNative::crypto;Threads::Threads;m;dl")\n'
(build/'NativeDependencies.cmake').write_text(cm)
PY
"$cc" -std=c11 -Wall -Wextra -Werror -DJUICE_STATIC -I"$prefix/include" -I"$root/remote" \
    "$root/build/probes/native_probe.c" "$root/remote/ob_json.c" \
    "$prefix/lib/libxquic-static.a" "$prefix/lib/libjuice.a" "$prefix/lib/libcjson.a" \
    "$prefix/lib/libssl.a" "$prefix/lib/libcrypto.a" -l"$sdk_cxx_runtime" -pthread -lm -ldl -o "$priv/native-probe"
sdk_run "$priv/native-probe"
"$cc" -std=c11 -Wall -Wextra -Werror -DJUICE_STATIC \
    -I"$root/tpr/libjuice/src" -I"$prefix/include" -I"$prefix/include/juice" \
    "$root/build/probes/relay_policy_probe.c" "$prefix/lib/libjuice.a" -pthread -o "$priv/relay-probe"
sdk_run "$priv/relay-probe"
python3 - "$prefix" <<'PY'
import hashlib,pathlib,sys
p=pathlib.Path(sys.argv[1]);(p/'SHA256SUMS').write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  lib/'+f.name+'\n' for f in sorted((p/'lib').glob('*.a'))))
PY
printf 'Native prefix: %s\nShell exports: %s\nCMake imports: %s\n' "$prefix" "$build/native-deps.env" "$build/NativeDependencies.cmake"
