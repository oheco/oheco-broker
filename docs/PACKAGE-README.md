# oheco-broker 0.5.0 — HarmonyOS arm64

Authenticated peer TCP/UDP mappings with SQLite management, WS/WSS signaling and standalone STUN/TURN. The package includes executable commands and **source SDKs**; it does not distribute prebuilt SDK libraries.

## Commands and runtime

```sh
/path/to/package/bin/oheco-broker --version
/path/to/package/bin/oheco-broker --help
/path/to/package/bin/oheco-broker-server --help
```

`bin/oheco-broker` is a relocatable shell launcher. It starts the signed native ELF at `libexec/oheco-broker` and sets its library search path to the bundled, signed `lib/runtime/libc++_shared.so`. The CLI needs the system C runtime and this packaged C++ runtime; keep the launcher, ELF and runtime directories together when relocating the package, including to paths with spaces.

`bin/oheco-broker-server` is a separate signed ELF for the SQLite management, HTTPS/WSS and UDP STUN/TURN backend. It needs the system C runtime, and does not load the native peer SDK or C++ runtime. Run the platform-matching server executable; a Linux server is built natively from the full source checkout.

Installation does not start a service or configure system startup. Through oheco, use `oheco-broker` and `oheco-broker-server`; `oheco-broker@0.5.0` selects the client version. No arguments show help. The legacy local command service requires explicit `oheco-broker shell serve`.

## Source SDKs

- **C local command SDK:** compile `sdk/c/oheco_broker.c` and include `oheco_broker.h`, or use its CMake OBJECT target. It requires C11, POSIX sockets/poll and pthreads, without third-party libraries.
- **C peer/management SDK:** `sdk/c/remote/` contains the API and engine. Complete pinned dependency sources, licenses and manifests are in `sdk/c/tpr/`; offline builders, probes and CMake resources are in `sdk/c/build/`. With native clang/clang++, CMake, Ninja and Python installed, run `sh sdk/c/build.sh`; HarmonyOS also requires `binary-sign-tool`. This builds for the consumer's target platform from source.
- **Go SDK:** `sdk/go/` wraps the same C engine through cgo. Build the C inputs first and supply their include/link settings. The package includes `go.mod`, `go.sum` and `vendor/` for offline Go dependency consumption. A native Go/C toolchain is required for SDK builds, not for running the supplied commands.
- **.NET SDK:** reference `sdk/dotnet/Oheco.Broker.csproj` or include `BrokerProcess.cs`. It targets .NET 10 without extra NuGet packages and calls the local command service; it is not a remote peer wrapper.

The C and Go peer SDKs retain handles and listening ports across bounded automatic retries, and expose asynchronous manual recovery after retries pause. With both endpoints using mapping v2, live TCP sockets can recover within the configured grace period; UDP drops stale packets. CLI users can request recovery with `SIGUSR1` and observe optional `--state-events`. See `docs/RECONNECT.md` and the SDK READMEs for integration.

A host embedding the remote C SDK must provide its platform's C/C++ runtimes even when SDK dependencies are statically linked; the CLI's private runtime does not automatically configure an unrelated host application. Keep the fixed BoringSSL implementation consistent across peer and curl inputs.

Account credentials refresh automatically with a compatible server. Run `tenant login` once to migrate a legacy profile; version2 profiles store refresh credentials without the account password. Registration requires an account password through interactive input or `--password-stdin`. Routine refresh preserves peers, listening ports and live TCP sockets. The defaults are 24-hour access and 30-day sliding refresh lifetime; expired/revoked refresh authority requires explicit login. Use a separate `--config` with older CLI versions, or explicitly register/login with `--legacy-auth`. See `docs/AUTH-REFRESH.md` for SDK storage hooks and recovery guarantees.

## Use and boundaries

Set `OHECO_BROKER_API` to the actual trusted HTTPS service, register/login with a tenant, and use `tenant serve` / `tenant connect`. Peer passwords are separate from account passwords and are supplied through stdin or interactive input. The broker target allowlist defaults to deny all; mapping listeners default to loopback. Remote HTTPS/WSS certificate and hostname checks stay enabled. TURN is UDP/IPv4 and requires explicit tenant relay permission; UDP delivery is best effort.

The legacy `shell serve` has no authentication: any local process that connects may execute commands as the service user. Use it only on a trusted development device and never expose it through a peer mapping. It writes loopback discovery to `$HOME/.oheco/broker/endpoint`; SDKs do not automatically start it. Managed jobs are canceled on connection/service close; detached startup returns a diagnostic PID and does not provide readiness or reconnection. A lost detached ACK must not trigger an automatic retry.

## Provenance

`BUILDINFO.txt` identifies the exact source commit, toolchain and signed executable/runtime hashes. `SHA256SUMS` accompanies the release archive. Preserve the project `LICENSE`, dependency source licenses and `licenses/` notices; libjuice source and its recorded relay-policy changes are provided under MPL-2.0.

The full repository contains application source, tests and release validation at <https://github.com/oheco/oheco-broker>. Checkout-relative test/example commands require that full source snapshot; SDK builds use the resources included here.
