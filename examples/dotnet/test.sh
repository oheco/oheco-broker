#!/usr/bin/sh
# Invoke from anywhere: sh examples/dotnet/test.sh /explicit/endpoint [--protocol-only|--managed-only]
set -eu
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    printf '%s\n' 'Usage: sh test.sh /explicit/broker/endpoint [--protocol-only|--managed-only]' >&2
    exit 2
fi
: "${TMPDIR:?TMPDIR must identify a writable temporary directory}"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
priv=$(mktemp -d "${TMPDIR%/}/broker-dotnet.XXXXXX")
trap 'rm -rf "$priv"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$priv/feed" "$priv/home" "$priv/packages" "$priv/tmp"
export TMPDIR="$priv/tmp"
export DOTNET_CLI_HOME="$priv/home"
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false
export DOTNET_NOLOGO=1
export NUGET_PACKAGES="$priv/packages"
# Shared parent MSBuild settings isolate BOTH projects' intermediates and outputs.
dotnet build "$script_dir/BrokerSmoke.csproj" \
    --source "$priv/feed" --artifacts-path "$priv/artifacts" \
    --disable-build-servers -p:UseSharedCompilation=false -nr:false \
    -p:NuGetAudit=false --nologo
dotnet "$priv/artifacts/bin/BrokerSmoke/debug/BrokerSmoke.dll" "$@"
# Also validate include-source mode without referencing the SDK assembly.
dotnet build "$script_dir/BrokerSmoke.csproj" \
    --source "$priv/feed" --artifacts-path "$priv/source-artifacts" \
    --disable-build-servers -p:UseSharedCompilation=false -nr:false \
    -p:NuGetAudit=false -p:UseBrokerSource=true --nologo
