# Go source SDK — 0.5.0

Import `github.com/oheco/oheco-broker/sdk/go/remote` for management, authenticated peers and TCP/UDP mappings. The package wraps the same C engine through cgo; it does not implement another ICE/TURN/QUIC or cryptographic stack. This is source distribution, without a prebuilt Go or C SDK library.

## Offline native build

Keep `sdk/go/` and its sibling `sdk/c/` in their original layout: cgo's header path is relative to `sdk/go/remote`. Keep the module-root `go.mod`, `go.sum` and `vendor/` supplied in the package. Prepare native Go 1.25+, C/C++ compilers, CMake, Ninja and Python; HarmonyOS also requires `binary-sign-tool`. From the package or checkout root:

```sh
sh sdk/c/build.sh
. "$XDG_CACHE_HOME/oheco-broker/remote-sdk/remote.env"
go build -a -mod=vendor ./sdk/go/remote
```

`remote.env` supplies `CGO_ENABLED`, include paths, static archive link flags, C++ runtime and offline Go proxy settings. With `sdk/c/build.sh --build-dir ABSOLUTE_PATH`, source that build root's `remote-sdk/remote.env` instead. Build on the actual target platform; the host needs its C/C++ runtimes even though the peer dependencies are static. The packaged CLI's private runtime does not automatically configure your application.

For an external application, reference the module at the extracted package root, for example with a local `replace github.com/oheco/oheco-broker => /path/to/package`, and keep the SDK sibling layout. Supply the generated cgo environment when building the application. An application's own offline module/vendor inputs must be prepared separately: Go does not automatically use a dependency module's `vendor/` directory.

Go's build cache does not reliably detect changed external static archives. After rebuilding C inputs, rebuild the Go consumer with `-a` or a fresh private `GOCACHE`; do not reuse stale linked objects. Source `remote.env` for the corresponding native build rather than another platform's cache.

## Ownership and scope

[remote/client.go](remote/client.go) provides `New`, `Request`, `Serve`, `Connect` and `Peer.Map`. Supply the actual trusted API URL, account token and optional CA file through `Options`; peer passwords are separate from account credentials. Close mappings, peers/servers, then the client. The wrapper rejects destroying a client while its peer/server references remain alive.

The SDK does not automatically register/persist account credentials or start a management service. HTTPS/WSS certificate and hostname verification stays enabled. Local mapping listeners do not authenticate software connecting to them; broker target access is explicitly allowlisted. The [.NET SDK](../dotnet/README.md) and [local C command API](../c/oheco_broker.h) cover the separate `shell serve` execution protocol, not this remote peer engine.

## Opt-in account refresh

`remote.New(options)` keeps its immutable token behavior. Use `remote.NewWithAuth(options, remote.AuthOptions{Credentials: credentials, Storage: store, RefreshBefore: 0})` for refresh-v1 accounts. Decode the additive `/v1/auth/login` or `/v1/auth/register` response into `remote.AuthCredentials`; it includes the login authority, generation, both secrets and UTC expiry times. `Options.Token` may be empty or equal the initial access token. This creates one stable C client with a proactive native timer, including idle/device-only traffic, and preserves its peers, mapping handles and TCP connections through account credential rotation.

`AuthOptions.Storage` is optional. Without it, the SDK retains credentials and pending refresh only in memory for the client lifetime. For crash recovery or a shared profile, implement the exact interface:

```go
type AuthStorage interface {
    Begin() (remote.AuthCredentials, *remote.AuthPending, error)
    Prepare(remote.AuthCredentials, remote.AuthPending) error
    Commit(remote.AuthCredentials, remote.AuthPending) error
    End()
}
```

`Begin` takes the caller's profile lock and loads current credentials plus a pending attempt. `End` runs unconditionally after it, including Begin failure, and releases that lock. `Prepare` durably saves the exact request ID and candidate pair before sending refresh. `Commit` durably saves the confirmed generation before clearing pending. Keep secrets in a private application store; the SDK does no filesystem I/O. The same-authority generation can be adopted from another process. Login/logout or a changed API/account/session must prevent stale callbacks from overwriting newer state.

Hooks execute outside SDK client/peer/state locks and are serialized for each manager. They must be bounded and cancellation-aware, and must not synchronously call `RefreshAuth`, `Close`, or close borrowed peers/servers from a hook. `AuthCredentials()` snapshot inspection is safe. The bridge uses `runtime/cgo.Handle`, retained until native cancellation, joined worker shutdown and all callbacks have completed. Close mappings, peers/servers, then the client. `Client.RefreshAuth() error` forces an idempotent credential transaction; `Client.AuthCredentials() (AuthCredentials, error)` returns a copied current snapshot. `StorageError` supports `errors.Is/As` for caller storage errors while its diagnostic stays redacted.

The default ten-minute advance is clamped for short access lifetimes and jittered. Lost replies/failed commits retain pending; exact replay confirms the original deadlines. If that receipt's access token already expired, the SDK then rotates its child refresh before an account request. Password login is never automatic. Explicit device/session bearers keep their original scope; arbitrary mutation requests are never automatically retried. See the [central refresh contract](../../docs/AUTH-REFRESH.md) and [C SDK guide](../c/remote/README.md).

## Connection recovery

`Client.ConnectAsync` returns a persistent peer before initial network setup completes. Both `Peer` and `Server` provide `SetReconnectPolicy`, `GetConnectionInfo` and nonblocking `Reconnect`; a nil error from `Reconnect` means accepted, and callers observe completion through the copied connection snapshot. Existing `Connect` still waits for the initial authenticated connection. Zero `ReconnectPolicy` fields select the C manager's defaults, including eight attempts, an immediate first retry followed by exponential delays starting at one second, a 60-second retry budget, a 120-second TCP grace and 15-second v2 transport detection. `Disabled` pauses automatic retries while preserving manual requests.

The native manager keeps mapping handles and local ports through recoverable failures. Existing TCP continuity requires both SDK processes and the target socket to remain alive within the grace period; context loss closes the old TCP flow rather than replaying it into a newly opened target socket. Explicit revocation is terminal. Poll `GetConnectionInfo` with an application context/ticker; connection state uses polling, while opt-in account storage hooks use the joined cgo callback bridge described above. The [recovery guide](../../docs/RECONNECT.md) covers C/Go usage, CLI SIGUSR1, authenticated v2 negotiation, backend compatibility and credential lifetime.
