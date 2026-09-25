#!/usr/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${TMPDIR:?TMPDIR must be a writable private directory}"
priv=$(mktemp -d "${TMPDIR%/}/oheco-broker-test.XXXXXX")
server_pid=''
cleanup() {
    rc=$?
    if [ -n "$server_pid" ]; then
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" || true
    fi
    if [ "$rc" -ne 0 ] && [ -f "$priv/broker.log" ]; then
        # Print only this isolated test's service log.
        python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())' "$priv/broker.log"
    fi
    rm -rf "$priv"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$priv/temp" "$priv/home" "$priv/cache" "$priv/feed" "$priv/dotnet-home" "$priv/nuget"
export GOCACHE="$priv/gocache" GOTMPDIR="$priv/temp" TMPDIR="$priv/temp" GOPROXY=off GOSUMDB=off
export DOTNET_CLI_HOME="$priv/dotnet-home" DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false DOTNET_NOLOGO=1 NUGET_PACKAGES="$priv/nuget"
cd "$root"
go test -trimpath -count=1 -timeout=90s ./...
go vet -trimpath ./...
go build -trimpath -o "$priv/oheco-broker" ./cmd/oheco-broker
clang -std=c11 -Wall -Wextra -Werror -pthread -Isdk/c sdk/c/oheco_broker.c examples/c/smoke.c -o "$priv/c-smoke"
clang -std=c11 -Wall -Wextra -Werror -pthread -Isdk/c sdk/c/oheco_broker.c tests/c/options_test.c -o "$priv/c-options"
if [ "$(go env GOOS)" = ohos ]; then
    for binary in "$priv/oheco-broker" "$priv/c-smoke" "$priv/c-options"; do
        binary-sign-tool sign -inFile "$binary" -outFile "$binary.signed" -selfSign 1
        chmod 755 "$binary.signed"
        mv "$binary.signed" "$binary"
    done
fi
HOME="$priv/home" XDG_CACHE_HOME="$priv/cache" "$priv/oheco-broker" >"$priv/broker.log" 2>&1 &
server_pid=$!
endpoint="$priv/home/.oheco/broker/endpoint"
python3 -c 'import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); end=time.monotonic()+10
while not p.exists():
    if time.monotonic()>end: raise SystemExit("broker startup timed out")
    time.sleep(.05)
print("Isolated endpoint:",p.read_text().strip())' "$endpoint"
# A responding duplicate is a successful no-op, not a second listener.
HOME="$priv/home" XDG_CACHE_HOME="$priv/other-cache" "$priv/oheco-broker" >"$priv/duplicate.log" 2>&1
"$priv/c-options"
python3 tests/c/protocol_test.py "$priv/c-smoke"
# HarmonyOS sh has self-aliases and external printf; prefer zsh for output loops.
# shutil.which resolves executables instead of returning an alias declaration.
shell_bin=$(python3 -c 'import shutil; p=shutil.which("zsh") or shutil.which("sh"); assert p; print(p)')
"$priv/c-smoke" suite "$endpoint" "$shell_bin"
python3 tests/lifecycle.py "$priv/oheco-broker" "$priv/c-smoke"
sh examples/dotnet/test.sh "$endpoint"
dotnet_bin=$(command -v dotnet)
"$priv/c-smoke" run "$endpoint" "$dotnet_bin" --version
"$priv/c-smoke" run "$endpoint" "$dotnet_bin" --list-sdks
# Real SDK restore/build through the broker, including an external csc process.
"$priv/c-smoke" run "$endpoint" "$dotnet_bin" build "$root/tests/build-fixture/BuildFixture.csproj" \
    --source "$priv/feed" --artifacts-path "$priv/fixture" --disable-build-servers \
    -p:UseSharedCompilation=false -p:NuGetAudit=false --nologo
"$priv/c-smoke" run "$endpoint" "$dotnet_bin" "$priv/fixture/bin/BuildFixture/debug/BuildFixture.dll"
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=''
if [ -e "$endpoint" ]; then
    printf '%s\n' 'Endpoint was not removed on normal shutdown' >&2
    exit 1
fi
printf '%s\n' 'PASS Go + C + .NET + real dotnet build; endpoint cleaned'
