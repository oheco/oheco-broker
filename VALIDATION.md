# Native validation — 2026-09-25

## Environment

- HarmonyOS aarch64; builds and execution performed directly on this device, not in Linux/VM/container.
- Go `go1.27.1 ohos/arm64` (`1.27.1-ohos.1`).
- .NET SDK `10.0.401` (`10.0.401-ohos.2`).
- clang `15.0.4`, target `aarch64-unknown-linux-ohos`.
- Native executables self-signed with the installed `binary-sign-tool`.
- No third-party Go modules, NuGet packages or C libraries downloaded.

## Reproduction and results

`sh scripts/build.sh` — PASS. Produces the signed `build/oheco-broker`; version check runs both before and after copying to the user filesystem.

`sh scripts/test.sh` — PASS, final exit code 0. Tests use an isolated temporary HOME/cache/endpoint/service and clean all owned resources. The final output was:

```text
Build succeeded.
    0 Warning(s)
    0 Error(s)
broker-build-fixture: PASS
PASS Go + C + .NET + real dotnet build; endpoint cleaned
```

Covered:

- Go tests and `go vet`: request codec, invalid/truncated input, discovery lock/publish/cleanup, binary stdin/stdout/stderr, nonzero exit, 2.6 MiB on each output stream, arguments/cwd/environment, spawn failure, cancellation escalation, disconnect and service shutdown child cleanup.
- C: strict C11 compile/link with `-Wall -Wextra -Werror -pthread`; malformed discovery/refused connection => UNAVAILABLE; fragmented frames and resuming timed-out partial reads; protocol type/order/size/UTF-8/EXIT rejection; server errors; connection loss; bounded handshake/start deadlines.
- C live SDK: streams, stdin/EOF, Unicode arguments/environment/cwd, large output, draining waits, noncancelling wait timeout, concurrent output/cancel, bounded blocked-input cancellation.
- .NET: dependency-free ProjectReference and include-source builds, zero warnings/errors; discovery/protocol errors, bounded buffer overflow, real broker streams/EOF/events, spawn errors, waits and cancellation.
- Real SDK commands through the C SDK and Go service: `dotnet --version`, `dotnet --list-sdks`, offline restore/build of `tests/build-fixture/BuildFixture.csproj` with build servers disabled and `UseSharedCompilation=false`, then execution of the resulting managed assembly. This exercises child compiler creation on the broker side, not merely a fake CLI or echo server.
- CMake OBJECT integration including explicit `-fPIC`; resulting object successfully linked into a shared module, so it can be embedded in an existing application's native library rather than distributed as a separate SDK `.so`.

## Real shared endpoint check

The built service was also started using the actual HOME (hmdfs). It successfully published the one-line `~/.oheco/broker/endpoint`, executed `dotnet --version` (output `10.0.401`) through that endpoint, and removed the endpoint on shutdown. The pre-existing `endpoint.json` ping-probe file was preserved. No broker execution service remains running from these tests.

Locally delivered signed executable SHA-256:

```text
9b56ee386038207cdf8c6f194dc6e12d7e2c0b9b2cab0f9aad496ce89e410d96  build/oheco-broker
```

This identifies the local deliverable, not a published immutable Release asset. Rebuilding can change build/signature metadata.

## Environment issues addressed during validation

- HarmonyOS `sh` reports an alias from `command -v sh`, and its printf loop is costly. The test harness resolves an actual executable and prefers installed zsh for high-volume shell output fixtures. Production command execution does not invoke a shell implicitly.
- CMake prints a generic unknown-HarmonyOS-platform warning. Its initial libc pthread probe also tests unsupported `pthread_cancel`; its subsequent `libpthread` probe succeeds. The actual SDK uses supported pthread mutex operations and builds/links successfully.
- The binary signer warned about normalizing a GNU_RELRO segment alignment in the C smoke executable; signing succeeded and signed native execution passed.

## Not claimed

- No Godot source/template integration was performed in this repository implementation. Terminal-side SDK tests are not a new Godot HAP cross-sandbox acceptance test.
- No NuGet restore from an external registry was required by the fixture; no arbitrary Godot/NuGet project compatibility guarantee.
- No other device or system version is certified by this single-device result.
- No authentication/security isolation, detached-task recovery or comprehensive descendant containment.
- GitHub Releases/package-catalog publishing are separate from this source repository delivery.
