# oheco-broker 0.2.0 — HarmonyOS arm64

Trusted local-development process broker. **Unauthenticated:** any local process
that can connect may execute commands as the broker user. Not a security boundary,
remote service, sandbox or multi-user production daemon.

## Run

```sh
/path/to/oheco-broker/bin/oheco-broker --version
/path/to/oheco-broker/bin/oheco-broker
```

The broker runs in the foreground and publishes numeric loopback discovery at
`$HOME/.oheco/broker/endpoint`. Run it in a separate terminal, then use either
source SDK below from your application. No configuration file or automatic
background startup is required. Stop the broker normally with Ctrl-C or SIGTERM.
For installation through oheco, the command is `oheco-broker`; the versioned
command is `oheco-broker@0.2.0`. Runtime requirement: HarmonyOS arm64 system libc.
The executable is signed. This directory can be relocated, including to paths
with spaces; SDK sources do not require installation of a binary SDK library.

## Repeated startup

If an existing endpoint completes the broker handshake, a repeated invocation
prints `oheco-broker is already running.` and exits **0** without changing it.
An abstract Unix socket is used only as an atomic singleton lock (not client IPC),
scoped to the canonical HOME and network namespace; it does not depend on private
cache paths. Real startup failures, including an unready occupied guard, remain
nonzero. Stop an already-running 0.1.0 broker before using new v2 capabilities:
upgrading/installing does not replace running processes. Old executables do not
understand the new lock; avoid mixed-version launchers in different cache roots.

## Source SDKs

- **C:** embed `sdk/c/oheco_broker.c` and include `sdk/c/oheco_broker.h`.
  Requires C11, POSIX sockets/poll and pthreads; no third-party dependencies.
  `sdk/c/CMakeLists.txt` supplies an optional CMake OBJECT target. See
  `sdk/c/README.md` for options, diagnostics, ownership and threading.
- **.NET:** reference `sdk/dotnet/Oheco.Broker.csproj` or embed
  `sdk/dotnet/BrokerProcess.cs`. Targets .NET 10, with no third-party packages.
  See `sdk/dotnet/README.md` for managed and detached APIs.
- Wire contract: `protocol/PROTOCOL.md` (managed v1 and detached v2).

Managed commands remain bound to their connection: release/dispose, connection
loss and broker shutdown cancel them. Drain output or use the SDK wait facilities.
Detached startup is an explicit separate v2 API: stdin is disabled, output is
append/create regular log files or the null sink, and the result is only a
diagnostic PID, **not** a wait/cancel handle or readiness guarantee. Relative log
paths use the requested server-side cwd. After successful OS spawn, disconnect
or normal broker exit does not kill a detached process; its shutdown and cleanup
belong to the caller. Terminal application exit or OS force-stop may still remove
it. A lost ACK or startup timeout has an unknown outcome: **never automatically
retry or fall back to managed startup**. An older broker safely rejects v2.

## Contents and provenance

This slim package contains only the signed broker, C/.NET source SDKs and their
documentation, protocol contract, this installed-usage README, MIT `LICENSE`,
`BUILDINFO.txt`, and Go/toolchain notices under `licenses/`. BUILDINFO identifies
the exact source commit, toolchain and signed executable SHA-256.

Go service source, build scripts, examples, tests, validation records and release
history are intentionally not installed. Obtain the complete source snapshot at
the `source_commit` recorded in BUILDINFO from
<https://github.com/oheco/oheco-broker>. Repository-relative example/test commands
in SDK documentation apply to that full checkout, not this slim installation.
