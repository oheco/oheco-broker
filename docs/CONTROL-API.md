# Go/SQLite control-plane API (v1): REST management + WS/WSS signaling

This is the 0.3.0 REST management and server authorization contract, separate from the local shell service and the peer wire protocol. The server embeds standalone Pion STUN/TURN, not WebRTC, and does not terminate native QUIC or receive peer passwords. Native C peers verify end-to-end authentication before the broker approves a session. See the [validation index](LOCAL-VALIDATION.md) for implementation and release evidence.

## Embedding / CLI adapter

```go
import "github.com/oheco/oheco-broker/internal/control"

s, err := control.New(control.Config{
    ListenAddr: "127.0.0.1:8080", // informational unless Serve is used
    DBPath: "/private/config/broker/control.sqlite",
    AdminToken: adminToken,       // caller-configured secret; never stored in SQLite
    RegistrationPolicy: "open", // or approval / closed
    TURN: control.TURNConfig{
        Enabled: true,
        ListenAddr: "0.0.0.0:3478",
        PublicIP: "203.0.113.10", // use actual externally reachable address
        Realm: "oheco-broker",
    },
})
if err != nil { /* handle */ }
defer s.Close()
// Mount s.Handler() on an HTTP server owned by the adapter, or:
err = s.Serve(ctx)
```

Exported signatures:

```go
func New(Config) (*Server, error)
func (*Server) Handler() http.Handler
func (*Server) Serve(context.Context) error
func (*Server) Close() error
func (*Server) TURNAddr() string           // actual bound UDP endpoint
func (*Server) AdvertisedTURNAddr() string // advertised PublicIP + bound port
```

`New` opens/migrates the database and starts TURN if enabled. It does **not** start an HTTP listener. `Serve` uses `Config.ListenAddr`, HTTP timeouts and context-driven graceful shutdown. For random HTTP ports, the adapter should call `net.Listen` itself and print that listener's actual address. Stop admission on the caller-owned HTTP listener/server before `Server.Close`. HTTP `Shutdown` does not close hijacked WebSockets: `Server.Close` independently stops and joins all WS readers/writers/scope loops **before closing SQLite**, and also closes TURN and flushes usage. No process-global socket/environment settings are modified.

Defaults: account bearer TTL 24 hours, session TTL 10 minutes (maximum configured one hour), broker heartbeat lease 90 seconds, usage persistence flush one second, 128 active sessions per tenant, 256 messages per direction per session, 32 KiB UTF-8 data per message. Configurable fields: `AccountTokenTTL`, `SessionTTL`, `BrokerLease`, `UsageFlushInterval`, `TenantDailyByteQuota` (zero unlimited), `MaxSessionsPerTenant` (maximum 10000), `MaxMessagesPerDirection` (maximum 1024), `MaxMessageBytes` (cannot exceed 32768). Negative limits/durations/quotas are rejected.

Use HTTPS/trusted local termination for HTTP bearer secrecy outside an isolated loopback fixture. Admin bearer comparison is constant-time. Applications must redact Authorization headers, account passwords and temporary TURN passwords from logs. Native peer passwords must **never** be submitted to this API. Browser CORS is deliberately not enabled.

Database files must have private permissions on a permissions-capable filesystem, with no group/other-writable parent directory. `DBPath` is a plain path (or `:memory:` for fixtures), not a SQLite URI/driver DSN: query parameters are rejected so they cannot bypass the checked path or override foreign-key/security settings. On HarmonyOS use an application-private subdirectory of `$XDG_CONFIG_HOME`; HOME/hmdfs cannot enforce 0600 and is rejected for an insecure database file. SQLite uses the vendored `mattn/go-sqlite3` amalgamation (bundled SQLite source/header, cgo, no installed libsqlite dependency), foreign keys, WAL and a 5 s busy timeout. Back up using SQLite's backup/snapshot facilities, not by copying only the live main file while WAL writes continue. A single connection serializes transactions.

## Common wire rules

All routes begin with `/v1`. JSON responses have `Cache-Control: no-store`. Requests use `Authorization: Bearer <opaque-token>`. Tokens contain 256 random bits; only SHA-256 token digests are stored. Tenant and broker IDs are UUIDv4 independent of mutable names. Tenant names are ASCII-case-insensitive unique (SQLite NOCASE; no Unicode normalization); broker names are case-sensitive unique **within a tenant**. Names are 1–64 bytes, trimmed, with no NUL/CR/LF. Passwords are 12–72 bytes (bcrypt's explicit maximum), salted bcrypt cost 12. Clients should generate a cryptographically random 32-hex-character account password when omitted. Names and emails may also be generated client-side.

Strict JSON rejects unknown fields, trailing values, malformed data and bodies over 64 KiB. Empty action endpoints may omit the body. The server never returns an account password, its hash, token digests or admin secret. Registration's server fallback creates an unpredictable password but **does not reveal it**; therefore a client that needs future login must generate and retain its own password. Random fallback email uses `example.invalid`, not a claim to email verification. There is no email delivery/recovery flow in v1.

Error response: `{"error":"safe description"}`. Statuses: 400 invalid body/bounds; 401 missing/invalid/expired/revoked bearer; 403 scope/capability/status denial; 404 absent or foreign-tenant resource; 409 sequence/name/lease/state conflict; 410 expired session if its token still exists; 429 state/credential limit; 503 disabled TURN or closed server. Expired token may produce 401 instead of 410; cleaned expired session may produce 404. Existing REST management and signaling endpoints remain backward-compatible. **Native continuous signaling must use WS/WSS, not REST short-poll or an HTTP polling fallback.** See the [ob-signaling-v1 contract](<WS-SIGNALING.md>) for exact upgrade paths, request/result/push/ACK frames, recovery and lifecycle bounds.

### Public / account endpoints

| Method | Route | Body / response |
|---|---|---|
| POST | `/tenants/register` | Optional `{name,password,email}` → 201 `{tenant,token}`; relay defaults false; approval policy returns pending |
| POST | `/tenants/login` | `{name,password}` → `{tenant,token}`; only active accounts may login |
| POST | `/tenants/logout` | Account bearer; idempotently deletes this account token, including pending/disabled accounts; `{logged_out:true}` |
| GET | `/me` | Account bearer → `{tenant}` |
| PATCH | `/me` | `{name?,email?}` → `{tenant,token}`; returns replacement account token |
| POST | `/me/password` | `{password}` → `{token}`; replacement account token |
| GET | `/me/capabilities` | Account → capability object; alias `/capabilities` |
| GET | `/me/usage` | Account → usage; alias `/usage`; optional `?broker_id=UUID` scoped to owned broker |

Tenant object:

```json
{"id":"uuid","name":"tenant","email":"tenant@example.invalid","status":"active","relay_enabled":false,"created_at":"RFC3339","updated_at":"RFC3339"}
```

Statuses: `active`, `pending`, `disabled`. Policy: `open`, `approval`, `closed`. Policy is persisted; `Config.RegistrationPolicy` initializes a new database only. A pending registration token can read `/me` and `/me/capabilities` (or its alias) to discover status, but cannot mutate accounts or perform broker/session/relay operations. Admin approval enables the account; the client can login afterwards.

User name/email/password updates and admin identity/password/disable updates **atomically** bump the tenant version, delete all old account/device/session tokens and sessions, close existing allocations, and mark brokers offline. User updates return a single replacement account token. Admin resets never reveal a generated password: callers must submit one they generated. Recover a broker UUID using a fresh account login and its `/token` endpoint. Account updates do not change tenant/broker UUIDs.

Capability object includes `status`, `relay_enabled`, `turn_available`, `stun_address`, `turn_address`, `turn_credential_renewal` (provider-specific), `signaling:"ob-signaling-v1"`, `session_ttl_seconds`, `broker_lease_seconds`, message bounds and `tenant_daily_byte_quota`. The advertised STUN endpoint can be used for ordinary Binding discovery even with tenant relay disabled; knowing it does **not** grant relay permission.

### Tenant broker lifecycle

| Method | Route | Authorization / body / response |
|---|---|---|
| POST | `/brokers` | Account; `{name?}` → 201 `{broker,device_token}`; same name in same tenant is 409 |
| GET | `/brokers` | Account → `{brokers:[...]}` |
| GET | `/brokers/{id}` | Account → `{broker}` |
| PATCH | `/brokers/{id}` | Account; `{name}` → `{broker}`; duplicate name 409 |
| DELETE | `/brokers/{id}` | Account; deletes broker, sessions and tokens; closes its allocations → `{deleted:true}` |
| POST | `/brokers/{id}/token` | Account; **offline** broker only → `{device_token}`; clears old sessions/token and renews lease; online conflict 409 |
| POST | `/brokers/{id}/heartbeat` | Matching device bearer; renews lease → `{broker}` |
| POST | `/brokers/{id}/offline` | Matching device bearer; immediately expires lease, removes sessions/caller tokens, closes allocations → `{offline:true}` |
| GET | `/brokers/{id}/sessions` | Matching device bearer and current lease → `{sessions:[...]}` |
| GET | `/brokers/{id}/usage` | Owning account bearer → broker usage |

Broker object: `{id,tenant_id,name,lease_expires_at,online,created_at}`. Device bearer is scoped to exactly one broker, has a one-year maximum token TTL and is invalidated by account/password changes, rotation or broker deletion. Lease expiration does not destroy that device identity: the same token can explicitly heartbeat to reconnect. Existing sessions remain subject to their independent expiry; offline explicitly deletes them. For process restarts, list the tenant's broker by unique name, refuse takeover while it is online, and rotate the offline broker's token instead of creating a new UUID. Heartbeat normally every 30 s for a 90 s lease. Every session operation checks current tenant status, token version, resource scope, session expiry and broker lease.

### Session signaling (native end-to-end transport)

1. Caller authenticates to account and `POST /sessions {"broker_id":"uuid","relay_mode":"auto"}`. Response 201 `{session_id,session_token,expires_at}`. Modes: `auto`, `never`, `force` (default `auto`). Force is rejected unless TURN exists and tenant relay is enabled; peers must actually route only through relay in force mode.
2. Broker connects `GET /ws/brokers/{id}` with its device bearer and subprotocol `ob-signaling-v1`; it receives an initial and event-driven `sessions` snapshot. The old `GET /brokers/{id}/sessions` route remains for existing REST clients only. Session entries: `{session_id,tenant_id,broker_id,relay_mode,peer_authenticated,relay_approved,expires_at}`.
3. Caller uses **session token**, broker uses **device token**, on matching `GET /ws/sessions/{id}?after=N` connections to exchange opaque peer protocol messages, initial/pushed capabilities, approval, TURN, heartbeats and lifecycle RPCs. WS operations explicitly map to the REST business semantics below; they are not arbitrary HTTP/path dispatch. No account bearer is accepted for message polling/writes. A session token cannot access a second session, even within the same tenant.
4. `POST /sessions/{id}/messages {"sequence":1,"data":"opaque protocol data"}` appends to the sender's directional mailbox. Sequences start at 1 independently for caller and broker and must advance exactly by one. Repeating the same sequence+identical data is idempotent 200; changing a used sequence or leaving a gap gives 409. Successful new write returns 201 `{sequence}`. Direction is derived from bearer, never a user-supplied role field.
5. `GET /sessions/{id}/messages?after=0` returns the **other** side only, ascending order, at most 16 entries: `{messages:[{sequence,data}],next}`. Keep `next` as cursor. Empty mailbox returns `messages:[]` and unchanged cursor. Mailboxes are immutable until session removal; no concurrent consumer deletion loses data. UTF-8 `data` is opaque; use base64 for binary payloads. Server does not parse PAKE, address exchange, candidate negotiation or QUIC frames.
6. After its own native PAKE/key confirmation succeeds, broker reports `POST /sessions/{id}/approve {"peer_authenticated":true,"relay":true}` using the device token. Caller cannot approve; false peer authentication is rejected. `relay:false` may approve direct/never sessions; force requires relay true. Response `{session}`. This is a broker's explicit attestation, not independent server verification of peer password knowledge.
7. Only then can **either** side `POST /sessions/{id}/turn` with scoped bearer receive independent temporary `{urls:["turn:host:port?transport=udp"],username,password,expires_at}`. Tenant capability, broker lease, session mode and approval must still permit relay. Credential identity is attributed server-side to immutable tenant/broker/session, without putting those identifiers into a reusable client-supplied claim.
8. `GET /sessions/{id}` (alias `/capabilities`) returns flat status fields: `{session_id,tenant_id,broker_id,relay_mode,peer_authenticated,relay_approved,expires_at,broker_lease_expires_at,lease_seconds,stun_address,turn_address,turn_credential_renewal}`.
9. `POST /sessions/{id}/heartbeat` using either scoped side bearer renews the session and caller token for `SessionTTL`, provided the broker lease remains live. It returns the same status and **does not renew broker lease**. The self-hosted provider advertises `turn_credential_renewal:"session-heartbeat"`: after committing the heartbeat, an approved live relay session also extends its **existing, unexpired** per-side TURN credentials to `min(new session expiry, now + MaxCredentialTTL)` with the **same username/password**. Existing allocations are not restarted, so a healthy forced-relay mapping does not disconnect at the original credential deadline. Renewal rechecks tenant capability, broker lease, session approval and quota; it cannot mint missing credentials or resurrect expired/revoked ones. If heartbeats cease, bounded credential timers still expire and close allocations; reconnect requires a new approved credential/allocation. Send heartbeat well before the shorter of session, broker and credential deadlines. TURN-disabled providers advertise `"none"`.
10. `DELETE /sessions/{id}` by either side deletes caller token and messages, revokes credentials/allocations → `{deleted:true}`.

Both native peers must use explicit WS session heartbeats (push/ACK/ping/pong never renew leases) and fail closed if authorization is rejected or the control server is unavailable longer than the advertised lease. This is essential for already-established **direct** QUIC transport: the control server is not a data-plane middlebox and cannot forcibly intercept its packets. STUN candidate discovery must not leak native passwords. Current native PAKE integration uses the pinned BoringSSL SPAKE2 draft-02 suite, not an assertion of RFC 9382 wire compatibility; the server is protocol-opaque.

### Administration (configured admin bearer only)

| Method | Route | Description |
|---|---|---|
| GET | `/admin/tenants` | `{tenants:[...],next_offset:integer|null}`; `limit`/`offset` pagination, optional `status` (`active`, `pending`, `disabled`) |
| GET | `/admin/tenants/{id}` | `{tenant}` |
| PATCH | `/admin/tenants/{id}` | `{name?,email?,status?,relay_enabled?}` → `{tenant}` |
| POST | `/admin/tenants/{id}/reset-password` | `{password}`; invalidates all old tokens/sessions |
| POST | `/admin/tenants/{id}/approve` | Pending → active |
| POST | `/admin/tenants/{id}/enable` | Set active |
| POST | `/admin/tenants/{id}/disable` | Revoke all tokens/sessions/allocations, set disabled |
| POST | `/admin/tenants/{id}/relay` | `{enabled:true|false}`; live capability toggle |
| GET/PATCH | `/admin/settings` | `registration_policy`: `open`, `approval` or `closed` |
| GET | `/admin/brokers` | `{brokers:[...],next_offset:integer|null}`; `limit`/`offset` pagination, optional `tenant_id=UUID` |
| GET | `/admin/brokers/{id}` | `{broker}` |
| GET | `/admin/usage` | All tenants or `?tenant_id=UUID`; optional owned `&broker_id=UUID` |
| GET | `/admin/info` | Schema, storage, counts, bound TURN endpoint, `quic_termination:false` |

Admin list pagination defaults to `limit=100`, `offset=0`. Limit must be 1–1000; offset must be 0–1000000000. Empty, malformed, repeated, negative or out-of-bound pagination parameters return 400. Keep the same filter and limit and follow `next_offset` until it is `null` to view all records; an empty page returns an empty array and null cursor. Ordering is stable by `(created_at,id)`; offset pagination is not an immutable database snapshot, so concurrent inserts/deletes can shift pages. No unbounded `--all` dump is needed. Tenant `/brokers` still returns all owned brokers (maximum 128).

Enabling relay/approving/enabling status does not silently rotate working bearer secrets. Disabling relay closes existing TURN allocations and invalidates relay approvals; force sessions are removed, while auto/never direct sessions and account/device tokens remain usable. Full tenant disable, identity changes and password resets use full revocation. Every subsequent TURN permission/auth/forwarding operation rechecks capability and session authorization.

## WebSocket signaling and embedder hook

The exact wire contract is [WS-SIGNALING.md](<WS-SIGNALING.md>). `Handler()` serves both scoped upgrades on the existing listener. HTTPS supplies WSS directly; callers must retain normal certificate/hostname verification. Present Origin must match the actual request scheme and host (no arbitrary `X-Forwarded-*` trust); native bearer clients may omit Origin. Cookie values never authenticate a socket, and query secrets/unknown query fields are rejected. Gorilla v1.5.3 is pure Go; no new cgo/QUIC dependency is introduced.

Subscriptions are registered before querying initial state. Every committed session create, signal insert, approval, lifecycle and authorization change wakes scoped subscribers. Wake channels coalesce; directional messages remain durable and immutable in SQLite. The server refetches token expiry, tenant version/status and resource authorization on each RPC, before pushes and at one-second idle intervals; it retains a token digest rather than the raw bearer. Relay-only permission revocation does not disconnect an authenticated direct-session socket.

Bounds: 1024 connections globally, 128 per tenant, four per bearer+resource; 32 outgoing frames / 256 KiB per peer, 32 MiB globally queued plus at most 128 simultaneous network writes and 128 admitted application frames. Incoming application queue is bounded to eight frames per socket. Encoders are also concurrency-bounded. Per-direction delivery window is four messages until cumulative ACK; ACK cannot advance beyond messages actually written on that connection. Overflow closes the socket without dropping durable history. Writes have a two-second deadline; network ping every 15 s and pong timeout 45 s are independent of authorization/lease deadlines. Inherited HTTP deadlines are explicitly cleared after upgrade. Initial broker snapshots are capped at 128 sessions; exceeding that bound is a 429 terminal error, not a truncated snapshot presented as complete.

`Config.BeforeWebSocketRequest func(context.Context, string, string) error` is an optional **embedder-only** fault/admission hook, nil in production adapters and not configurable through HTTP. Its role is `"broker"` for watcher RPCs or `"session"` for either session-side socket, followed by the operation name. It runs after strict-frame/scope validation, with no SQLite transaction held. Socket/server close cancels its context; implementations must obey cancellation. A released delayed request revalidates scope before entering its explicit business handler. This permits isolated lifecycle fixtures to stall/count WS heartbeats without turning HTTP middleware into a generic WebSocket dispatcher.

## TURN, accounting, resource bounds

UDP IPv4 STUN Binding, TURN Allocate/Refresh, CreatePermission, ChannelBind, Send/Data indications and ChannelData are handled by pinned Pion TURN v4.1.3. No QUIC termination. TCP/TLS TURN is **not enabled** in v1; temporary URLs explicitly advertise UDP. Production deployment/NAT/firewall configuration and TLS HTTP are adapter responsibilities, not part of local testing.

TURN config additionally supports `RelayMinPort`/`RelayMaxPort`, `Realm`, `MaxAllocations` (default 512), `MaxAllocationsPerTenant` (64), `MaxCredentials` (4096), `MaxCredentialsPerTenant` (256), `MaxPeersPerAllocation` (32), `MaxChannelsPerAllocation` (64), `SocketBufferBytes` (64 KiB, max 4 MiB), `MaxBytesPerSecond` / `MaxBytesPerSecondPerTenant` (zero unlimited), and `MaxCredentialTTL` (one hour default; clipped to session expiry). Unspecified relay port range uses ephemeral ports.

Peers cannot relay to unspecified, multicast, broadcast, private, link-local or loopback addresses by default. `AllowLoopbackPeers:true` explicitly allows only isolated local loopback fixtures; it does not grant access to all private network ranges. Permissions are bounded. Per-allocation sockets are wrapped to reauthorize traffic and count **actual forwarded opaque payload bytes**, outgoing plus incoming, excluding STUN/TURN framing/control bytes. Thus a payload forwarded twice through two separately attributed relay sockets is counted twice as transport traffic; this is not plaintext application accounting.

Usage response: `{tenant_id,broker_id,unit:"forwarded_payload_bytes",days_1,days_7,days_30,lifetime,window}`. Rolling windows are 24 / 168 / 720 hours, aggregated in UTC **one-minute buckets** (at most one minute boundary approximation). Minute rows older than 31 days are pruned; daily lifetime aggregates remain. Broker history survives broker deletion; tenant aggregate is unaffected. Data is batched in process and transactionally flushed; querying usage and graceful close flush immediately. Abrupt process/power loss may lose the unflushed interval. Tenant daily byte quota includes pending counted bytes and resets at UTC midnight. Per-packet checks may overshoot a configured quota by concurrently admitted datagrams; byte-rate limits are traffic guards, not a billing-grade reservation ledger. Revocation closes existing relay sockets and clears credentials, not merely denying future allocations.

REST bounds: 128 brokers per tenant; 128 active sessions per tenant by default, global 10000 active sessions; 16 retained account login tokens per tenant; bounded immutable mailbox. Admin tenant/broker lists use bounded pages (default 100, maximum 1000) and `next_offset` to make all records accessible; tenant broker lists return all at most 128 owned brokers. The public API does not implement distributed brute-force, signup/IP rate limiting or email verification: use an HTTP admission/rate-limiting layer before exposing open registration publicly. No public readiness claim is made here.

## SQLite storage

Schema version 1 uses UUID TEXT keys, UTC millisecond INTEGER times, integer booleans and parameterized statements. Tables retain tenants, hashed scoped tokens, brokers, sessions, directional messages, settings and daily/minute usage. `(session_id,side,sequence)` is unique; registration/token issuance, revocation, idempotent messages and usage commits are atomic. Never serialize password hashes or token hashes. This implementation uses SQLite; a Workers/D1 adapter is not provided.

## Pinned source inputs

The authoritative module versions are in [go.mod](../go.mod), Go's module content hashes in [go.sum](../go.sum), and compiled source in the standard Go `vendor/` layout. No local modifications were made to vendored Go dependencies; security, attribution and OHOS integration live in the control wrappers. Upstream module zip URLs are `https://proxy.golang.org/<module>/@v/<version>.zip`. SHA-256 below is of the **source zip**, not a replacement for Go's `h1` directory-content checksum. Retained license texts accompany each vendored module. Pion modules, sqlite3 wrapper and mousetrap use MIT; Cobra Apache-2.0; anet, pflag and Go x modules BSD-3-Clause. Gorilla WebSocket uses BSD-2-Clause. SQLite amalgamation itself is public domain.

| Module | Version | Source zip SHA-256 |
|---|---|---|
| github.com/gorilla/websocket | v1.5.3 | `dbbd31dd0f08548c5dc43e4c2f12bbba66abff5252b224b1cd06afbb72783a76` |
| github.com/mattn/go-sqlite3 | v1.14.32 | `c70101000256656bc0b7286807cf177852c753a001a3aa3c55d5373575fb81aa` |
| github.com/pion/logging | v0.2.4 | `b904074dd76009e71b4e4e0e004a2c7862bff0a8690b4f47410c46b172b3830c` |
| github.com/pion/stun/v3 | v3.0.1 | `73cd7253f558ea0694ada3d1ff1a0777bc79b8650e7fbeee56665c548c469352` |
| github.com/pion/turn/v4 | v4.1.3 | `0ab3580dc981b339cbe1acc72164f61ee52023770495025905f83f8e0c3f2791` |
| github.com/spf13/cobra | v1.10.1 | `00955783267c9ced54274df456377a15bc1b658362f93f85dfda0708b54f9a28` |
| golang.org/x/crypto | v0.43.0 | `0b11e4f2ac759849fc2567213e22e7dcb2e1bfe9755aca46c95d8d253f3c610b` |
| golang.org/x/net | v0.45.0 | `995a48eebb670c919eb9fc9d9f60ee85a9f8ae39d606760108a31438e1300348` |
| golang.org/x/text | v0.30.0 | `4953efaff3130e642c94ffb8624f668fb9ccfb780757a7e87f86a2434559d934` |
| golang.org/x/term | v0.36.0 | `b6773eb737a1269579913418c72aa4f3195e2a1f63c6f01080cc7435cbe55eac` |
| github.com/inconshreveable/mousetrap | v1.1.0 | `526674de624d7db108cfe7653ef110ccdfd97bc85026254224815567928ed243` |
| github.com/pion/dtls/v3 | v3.0.7 | `4aa6c70d6eed91fa00919626eb88b6d2235060a73d1daccd685437795dcd50ea` |
| github.com/pion/randutil | v0.1.0 | `35161b7c4ff98bb09fd8055537f9b2499116c19a89b9700b9b1986b7147b6805` |
| github.com/pion/transport/v3 | v3.1.1 | `f8b8a6d15785a54f1a4a5cfabda55f787c78af47b14890967827d42de71d533a` |
| github.com/spf13/pflag | v1.0.9 | `83910188d8735f84a48a80ab78351edac0b569896f2b3a244c696a07da9aa5ed` |
| github.com/wlynxg/anet | v0.0.5 | `5d6e471ccaa553e0cac56e17f8e44499f99ca1a1e37d80d5fdb3c64d4d50d02a` |
| golang.org/x/sys | v0.37.0 | `6c87bb94ec328b6d6234ad02cf2813225fe3bd5f8929fe85775ca06e01cfcc78` |

## Validation

Use the checkout regression entry points in the [validation index](LOCAL-VALIDATION.md). Local fixtures cover REST, SQLite, scoped WS/WSS and actual Pion TURN; native peer behavior is tested separately.
