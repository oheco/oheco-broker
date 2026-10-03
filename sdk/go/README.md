# Go source SDK — 0.3.0

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
