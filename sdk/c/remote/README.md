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

The public interfaces are in `ob_api.h`, `ob_auth.h` and `ob_remote.h`. Peers and servers borrow their API client; close peer/server/map handles before destroying that API client. Legacy `ob_api_options` and `ob_api_client_create` keep their ABI and immutable bearer behavior. Automatic account refresh is opt-in through `ob_api_client_create_with_auth`: its separate `ob_auth_options` is tagged with `struct_size = sizeof(ob_auth_options)` and `version = 1`, and the same native API client remains alive throughout credential rotation. Peer passwords are copied into owned memory for repeated PAKE authentication and cleared on final destruction. The application owns its original password storage.

`ob_remote_connect` waits for the first connection. `ob_remote_connect_async` immediately returns a persistent logical handle, so an initial network failure can recover without replacing that handle. Maps keep their local listening ports through transient outages and paused retries. `ob_remote_peer_reconnect` accepts an asynchronous manual request; use the state API or callback to observe completion. Disabling automatic retries still permits manual recovery.

State callbacks run outside SDK mutexes on SDK worker threads. Copy the callback snapshot if needed, and ask an application thread to close handles; do not close or destroy a handle inside its callback. Serialize final destruction with other public operations.

Both authenticated v2 peers can retain an existing TCP socket through a short outage using bounded replay, delivery acknowledgments, and FIN recovery. Both SDK processes and the target socket must remain alive within the configured grace period. UDP discards old queued packets. Explicit authorization revocation remains terminal, and a closed handle cannot be revived.

Account refresh has a native proactive timer even while the client is idle or only device/session tokens are in use. Decode an additive `/v1/auth/login` or `/v1/auth/register` response with `ob_auth_credentials_parse`, then copy the credentials into the new constructor's options. `refresh_before_ms = 0` selects ten minutes, clamped for short lifetimes with jitter; refresh has its own bounded transport. With all storage hooks NULL, credentials and an ambiguous pending transaction stay in memory for this client lifetime. The SDK never automatically logs in with a password or writes credential files.

For restart recovery or a shared profile, supply all four `begin`, `prepare`, `commit`, `end` hooks. `begin` loads the same login authority and the exact pending attempt under a caller-owned profile lock; `end` runs after every `begin`, INCLUDING failure. `prepare` must durably record request ID and both candidate secrets before RPC. `commit` must durably publish confirmed credentials before clearing that pending attempt. Failed or lost responses keep the transaction for exact replay. An old receipt with expired access is confirmed first, then the SDK obtains fresh access through its child refresh. A newer generation from the same login authority can be adopted; another authority requires explicit login.

Hooks run outside SDK client/peer/state locks and are serialized per manager. Keep them bounded and cancellation-aware; do not synchronously refresh or destroy this client or its borrowed peers inside a hook. Snapshot inspection is permitted. Destruction cancels refresh, joins the worker and finishes callbacks before callback context may be freed. `ob_auth_manager_snapshot` copies credentials; `ob_auth_manager_refresh` forces/checks a rotation without recreating peers or mappings. Clear caller-owned credential/pending structs when done. Account fallback requests own a copied token; explicit device/session bearers preserve their original scopes. Idempotent GET may retry once after HTTP 401. Managed connection proposals may also retry their exact CAS/request identity under their own idempotence contract; arbitrary mutation RPCs are never automatically replayed.

See the [auth refresh contract](../../../docs/AUTH-REFRESH.md) and [recovery guide](../../../docs/RECONNECT.md) for wire fields, defaults, persistence rules, authorization boundaries and C/Go usage. Source SDK archives contain these guides and complete offline build inputs.
