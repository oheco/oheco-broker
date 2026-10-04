# Remote C SDK

This source library provides REST management, authenticated peer TCP/UDP mappings, and bounded connection recovery. The Go remote SDK and CLI use this same C engine. The SDK does not start or install a management server.

Build from the module root with the pinned sources in `sdk/c/tpr`:

```sh
: "${TMPDIR:?set a writable private temporary directory}"
: "${XDG_CACHE_HOME:?set a writable private cache directory}"
sh sdk/c/build.sh --build-dir "$XDG_CACHE_HOME/oheco-broker-sdk"
. "$XDG_CACHE_HOME/oheco-broker-sdk/remote-sdk/remote.env"
```

Use a native C/C++ compiler, CMake, Ninja, Python and Go. HarmonyOS also requires `binary-sign-tool`; build outputs belong in private cache or temporary directories. Applications must supply the platform C/C++ runtimes and keep the pinned BoringSSL implementation consistent across xquic and curl.

The public interfaces are in `ob_api.h` and `ob_remote.h`. Peers and servers borrow their immutable API client; close peer/server/map handles before destroying that API client. Peer passwords are copied into owned memory for repeated PAKE authentication and cleared on final destruction. The application owns its original password storage.

`ob_remote_connect` waits for the first connection. `ob_remote_connect_async` immediately returns a persistent logical handle, so an initial network failure can recover without replacing that handle. Maps keep their local listening ports through transient outages and paused retries. `ob_remote_peer_reconnect` accepts an asynchronous manual request; use the state API or callback to observe completion. Disabling automatic retries still permits manual recovery.

State callbacks run outside SDK mutexes on SDK worker threads. Copy the callback snapshot if needed, and ask an application thread to close handles; do not close or destroy a handle inside its callback. Serialize final destruction with other public operations.

Both authenticated v2 peers can retain an existing TCP socket through a short outage using bounded replay, delivery acknowledgments, and FIN recovery. Both SDK processes and the target socket must remain alive within the configured grace period. UDP discards old queued packets. Explicit authorization revocation remains terminal, and a closed handle cannot be revived.

See the [recovery guide](../../../docs/RECONNECT.md) for policy defaults, C and Go examples, CLI signals, compatibility and authorization boundaries. The full repository contains protocol specifications and native fault-injection tests; source SDK archives contain the guide and complete offline build inputs.
