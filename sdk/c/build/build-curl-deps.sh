#!/usr/bin/sh
# Offline libcurl using precisely the peer engine's BoringSSL static archives.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${XDG_CACHE_HOME:?XDG_CACHE_HOME is required}"
: "${TMPDIR:?TMPDIR is required}"
umask 077
priv=$(mktemp -d "${TMPDIR%/}/oheco-curl.XXXXXX")
trap 'rm -rf "$priv"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export TMPDIR="$priv"
native=${NATIVE_BUILD_DIR:-${XDG_CACHE_HOME%/}/oheco-broker/native-deps}
np=${NATIVE_PREFIX:-$native/prefix}
build=${CURL_BUILD_DIR:-${XDG_CACHE_HOME%/}/oheco-broker/curl-deps}
prefix="$build/prefix"
. "$root/build/common.sh"
jobs=${NATIVE_JOBS:-4}
sdk_output_directory "$np"
sdk_output_directory "$build"
for input in "$np/include/openssl/base.h" "$np/lib/libssl.a" "$np/lib/libcrypto.a"; do
    test -f "$input" || { printf 'Build native dependencies first; missing %s\n' "$input" >&2; exit 1; }
done
mkdir -p "$build" "$prefix"
python3 "$root/build/check-native-sources.py" --curl-only
# Curl's only runtime configure checks are executed natively AFTER signing,
# rather than faking cross-compilation results or executing unsigned try_run.
"$cc" -std=c11 -Wall -Wextra -Werror "$root/build/probes/curl-native-probe.c" -o "$priv/probe"
if [ "$sdk_platform" = ohos ]; then
    binary-sign-tool sign -inFile "$priv/probe" -outFile "$priv/probe.signed" -selfSign 1
    chmod 755 "$priv/probe.signed"
    probe=$("$priv/probe.signed")
else
    probe=$("$priv/probe")
fi
case "$probe" in '1 0'|'1 1'|'0 0'|'0 1') ;; *) printf 'Unexpected native probe result\n' >&2; exit 1 ;; esac
writable=${probe% *}
time_unsigned=${probe#* }
# Reconfiguration from older curl versions must not retain their feature cache.
rm -rf "$build/curl"
"$cmake" -S "$root/build/curl-cmake" -B "$build/curl" -G Ninja \
    -DCMAKE_C_COMPILER="$cc" -DCMAKE_BUILD_TYPE=Release \
    -DOB_CXX_RUNTIME="$sdk_cxx_runtime" \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_INSTALL_PREFIX="$prefix" -DCMAKE_INSTALL_LIBDIR=lib \
    -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON \
    -DBUILD_CURL_EXE=OFF -DBUILD_TESTING=OFF -DBUILD_EXAMPLES=OFF \
    -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF \
    -DHTTP_ONLY=OFF -DCURL_DISABLE_HTTP=OFF -DCURL_DISABLE_WEBSOCKETS=OFF \
    -DCURL_DISABLE_DICT=ON -DCURL_DISABLE_FILE=ON -DCURL_DISABLE_FTP=ON \
    -DCURL_DISABLE_GOPHER=ON -DCURL_DISABLE_IMAP=ON -DCURL_DISABLE_IPFS=ON \
    -DCURL_DISABLE_LDAP=ON -DCURL_DISABLE_LDAPS=ON -DCURL_DISABLE_MQTT=ON \
    -DCURL_DISABLE_POP3=ON -DCURL_DISABLE_RTSP=ON -DCURL_DISABLE_SMTP=ON \
    -DCURL_DISABLE_TELNET=ON -DCURL_DISABLE_TFTP=ON -DCURL_DISABLE_ALTSVC=ON \
    -DCURL_DISABLE_DOH=ON -DCURL_DISABLE_HSTS=ON -DCURL_DISABLE_NETRC=ON \
    -DCURL_DISABLE_VERBOSE_STRINGS=ON -DCURL_DISABLE_COOKIES=ON \
    -DCURL_ENABLE_NTLM=OFF -DCURL_DISABLE_NEGOTIATE_AUTH=ON \
    -DCURL_DISABLE_KERBEROS_AUTH=ON -DCURL_DISABLE_AWS=ON \
    -DCURL_USE_PKGCONFIG=OFF -DCURL_USE_CMAKECONFIG=OFF -DCURL_USE_OPENSSL=ON \
    -DOPENSSL_ROOT_DIR="$np" -DOPENSSL_INCLUDE_DIR="$np/include" \
    -DOPENSSL_SSL_LIBRARY="$np/lib/libssl.a" -DOPENSSL_CRYPTO_LIBRARY="$np/lib/libcrypto.a" \
    -DCURL_ZLIB=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF \
    -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF -DCURL_USE_LIBSSH=OFF \
    -DCURL_USE_GSSAPI=OFF -DUSE_LIBIDN2=OFF \
    -DUSE_NGHTTP2=OFF -DUSE_NGTCP2=OFF -DUSE_QUICHE=OFF \
    -DENABLE_ARES=OFF -DENABLE_THREADED_RESOLVER=ON \
    -DCURL_CA_BUNDLE=none -DCURL_CA_PATH=none -DCURL_CA_FALLBACK=ON \
    -DHAVE_WRITABLE_ARGV="$writable" -DHAVE_TIME_T_UNSIGNED="$time_unsigned"
"$cmake" --build "$build/curl" --target libcurl_static -j "$jobs"
"$cmake" --install "$build/curl"
python3 -B - "$build" "$prefix" "$np" "$writable" "$time_unsigned" "$sdk_cxx_runtime" "$sdk_platform" "$root" <<'PY'
import hashlib,json,pathlib,shlex,sys
sys.path.insert(0, str(pathlib.Path(sys.argv[8])/'build'))
from cgo_flags import join
build,prefix,native=map(pathlib.Path,sys.argv[1:4])
cache=(build/'curl/CMakeCache.txt').read_text()
probes={'writable_argv':bool(int(sys.argv[4])), 'time_t_unsigned':bool(int(sys.argv[5])),
        'linux_tcp_with_libc_socket_headers': 'OHECO_CURL_LINUX_TCP_COMPATIBLE:INTERNAL=1' in cache,
        'runtime_probe':'native compiled, OHOS-signed when required, executed before CMake',
        'compile_probes':'native CMake compile/link checks; no unsigned execution',
        'tls_libraries':[str(native/'lib/libssl.a'),str(native/'lib/libcrypto.a')],
        'cxx_runtime':sys.argv[6], 'platform':sys.argv[7], 'curl_version':'8.22.0',
        'protocol_profile':['http','https','ws','wss'],
        'websocket_api':'public curl_ws_recv/curl_ws_send, CONNECT_ONLY=2'}
(build/'curl-native-probes.json').write_text(json.dumps(probes,indent=2)+'\n')
lib=prefix/'lib/libcurl.a'
assert lib.is_file()
values={'CURL_BUILD_DIR':str(build),'CURL_PREFIX':str(prefix),
        'CURL_INCLUDE_DIR':str(prefix/'include'),'CURL_STATIC_LIBRARY':str(lib),
        'CURL_CPPFLAGS':join(['-DCURL_STATICLIB', '-I'+str(prefix/'include')]),
        'CURL_LDFLAGS':join([str(lib)])}
(build/'curl-deps.env').write_text(''.join('export '+k+'='+shlex.quote(v)+'\n' for k,v in values.items()))
cm=('find_package(Threads REQUIRED)\n'
    'if(NOT TARGET OhecoCurl::curl)\n  add_library(OhecoCurl::curl STATIC IMPORTED)\n'
    '  set_target_properties(OhecoCurl::curl PROPERTIES\n'
    '    IMPORTED_LOCATION "'+str(lib)+'"\n'
    '    INTERFACE_INCLUDE_DIRECTORIES "'+str(prefix/'include')+'"\n'
    '    INTERFACE_COMPILE_DEFINITIONS CURL_STATICLIB\n'
    '    INTERFACE_LINK_LIBRARIES "'+str(native/'lib/libssl.a')+';'+str(native/'lib/libcrypto.a')+';'+sys.argv[6]+';Threads::Threads;m;dl")\nendif()\n')
(build/'CurlDependencies.cmake').write_text(cm)
lines=[]
for path in [lib,native/'lib/libssl.a',native/'lib/libcrypto.a']:
    lines.append(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+str(path))
(prefix/'SHA256SUMS').write_text('\n'.join(lines)+'\n')
PY
printf 'Curl prefix: %s\nShell exports: %s\nCMake imports: %s\n' \
    "$prefix" "$build/curl-deps.env" "$build/CurlDependencies.cmake"
