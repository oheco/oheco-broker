# ob-signaling-v1 WS/WSS signaling contract

This is the 0.4.0 scoped Go server and native SDK signaling contract. The WebSocket subprotocol, frame version and existing operations remain `ob-signaling-v1` / 1. REST account/admin management and the [authenticated peer protocol](<PEER-PROTOCOL.md>) are separate contracts. Implementation and release evidence is indexed in [validation](<LOCAL-VALIDATION.md>).

REST provides account/admin operations, broker registration and issuance/deletion of managed logical connections and transport sessions. Persistent broker notifications, PAKE/ICE mailboxes, approval/capabilities, TURN credential requests, heartbeat/lease renewal and scoped lifecycle operations use WS/WSS; the native SDK must not fall back silently to HTTP polling. HTTPS origins map to WSS, loopback HTTP to WS. The peer PAKE suite, signal envelope, certificate pin/exporter and QUIC ALPN remain compatible; mapping v2 recovery fields are authenticated inside that envelope. See the [control API](<CONTROL-API.md>) for `GET /v1/status`, `/v1/connections/{id}/session`, generation CAS and durable authorization bindings.

## Connections and trust

- `GET /v1/ws/brokers/{id}`: exactly one `Authorization: Bearer <device token>` header, frozen broker scope. Offline device tokens may connect to heartbeat/recover; caller account/session/admin tokens cannot subscribe. No query parameters.
- `GET /v1/ws/sessions/{id}?after=N`: bearer is the matching caller-session token or broker-device token; server derives `client`/`broker` side, never trusts a client-supplied side. Optional `after` defaults to zero and may appear exactly once. It is the last fully processed **opposite-direction** signal sequence, not merely received bytes; it must be an unsigned decimal integer no greater than that session/direction's actual durable history and configured directional limit. Unknown/malformed/repeated query fields are rejected.
- Required WebSocket subprotocol `ob-signaling-v1`; compression is not negotiated. No URL credentials or cookie authentication. Cookie values are ignored, never an alternative to the explicit bearer. Native handles must not send browser cookies/query secrets or follow credential-bearing redirects.
- Normal certificate/hostname verification, origin checking, no ambient proxy/redirect/key logging for SDK handles. A present Origin must have the exact request scheme (`http` or `https`) and matching host/port, with no userinfo/path/query/fragment; absent Origin is allowed for explicit bearer clients. Arbitrary forwarded headers do not establish trust. Loopback WS is local-only; external TLS termination requires an explicit trusted listener policy.
- Each broker watcher and session connection has one C owner thread and one libcurl private handle. One broker watcher plus per-session sockets is deliberate; no competing reads or cross-session bearer reuse. Socket liveness ping/pong is not authorization/lease renewal.
- Connection bounds are 1024 globally, 128 per tenant, four per bearer+resource. Business scope/cursor/admission denials use ordinary HTTP JSON error statuses (400 malformed protocol/query, 401 invalid bearer, 403 bad role/scope/origin, 404 absent resource, 409 unavailable lease, 410 expired session, 429 admission limit, 503 closed server). RFC6455 transport-handshake failures may use Gorilla's ordinary HTTP error text. No 101 success is returned until initial scope/cursor checks pass.

## Frames

All application frames are UTF-8 JSON **text**, maximum **262144 bytes** per complete application message, including its envelope. Version is the integer **1**. Field names are case-sensitive, required fields cannot be omitted, unknown and duplicate keys are rejected, and integer IDs/cursors/sequences use decimal integer syntax (not fractions/exponents/strings) within JSON-safe bounds. Binary/invalid/oversized frames close fail-closed. RFC6455 ping/pong/close frames do not appear as JSON application data.

Request, with exactly these fields:

```json
{"v":1,"type":"request","id":1,"op":"heartbeat","body":null}
```

`id` is 1–9007199254740991, chosen by the client to correlate one result. Use distinct IDs for simultaneously outstanding requests. IDs are correlation values, **not** a server-side deduplication ledger. Reconnect retry safety comes from the business operation, not reuse of an RPC ID.

Result, with exactly these fields:

```json
{"v":1,"type":"result","id":1,"status":200,"body":{}}
```

`status` and `body` preserve the REST business contract, including `{error:"safe description"}` failures. Managed lifecycle errors additionally contain `error_code` and a nonzero current `generation` when known. The top-level result fields remain unchanged. Scoped operations are an explicit allowlist, not arbitrary HTTP/path dispatch. Account/admin operations and managed session issuance are unavailable on these sockets.

| Scope | Operation | Required body | Business response |
|---|---|---|---|
| Broker watcher | `heartbeat` | `null` | 200 `{broker}`; may restore an offline UUID |
| Broker watcher | `offline` | `null` | 200 `{offline:true}`; removes old sessions, then closes old sockets |
| Session, either side | `heartbeat` | `null` | 200 flat capabilities/status; renews session/caller token and eligible existing TURN credentials, **not** broker lease |
| Session, either side | `capabilities` | `null` | 200 flat capabilities/status |
| Session, either side | `send` | exactly `{sequence,data}` | 201 `{sequence}` or idempotent 200 `{sequence,duplicate:true}`; changed retry/gap 409 |
| Session, broker side only | `approve` | exactly `{peer_authenticated,relay}` (booleans) | 200 `{session}`; peer authentication must be true; force requires relay |
| Session, either side | `turn` | `null` | 200 temporary TURN credential object; capability/approval/lease/quota checks apply |
| Session, either side | `delete` | `null` | 200 `{deleted:true}`; removes caller token/mailbox and closes old sockets; a managed session deletion revokes its logical lineage |

`send.sequence` starts at one, advances exactly by one in each independent direction and cannot exceed `MaxMessagesPerDirection`. `data` is an opaque UTF-8 string of at most `MaxMessageBytes` (default/max 32768); use base64 for binary peer envelopes. Approval contains both exact boolean fields. No-body operations require JSON `null`, not `{}` or omission. Strict shape/type/protocol failures close the socket; ordinary business denials return a result. A caller's `approve` denial or permission-specific TURN denial is not by itself proof the socket identity has been revoked: scope is revalidated before deciding to close.

Push frames:

```json
{"v":1,"type":"sessions","body":{"sessions":[]}}
{"v":1,"type":"capabilities","body":{}}
{"v":1,"type":"message","sequence":1,"data":"opaque peer envelope"}
{"v":1,"type":"revoked","status":401,"body":{"error":"authorization unavailable"}}
```

- Broker `sessions` is a fresh snapshot, not an incremental array. Entries retain the REST session object fields; managed sessions add `connection_id` and `generation`, while legacy sessions omit them. The initial snapshot and every committed lifecycle/approval/session-expiry change are pushed without HTTP polling. Maximum snapshot is 128 sessions; an over-limit snapshot yields terminal 429 rather than a misleading truncated list. SDKs deduplicate SIDs, and a newer generation of a managed connection is routed to its existing logical peer rather than implicitly creating a second target context. Session absence from an expiry/replacement snapshot alone is not proof of explicit lineage revocation.
- Session `capabilities` uses the flat REST status object (`session_id`, `broker_id`, `tenant_id`, `relay_mode`, `peer_authenticated`, `relay_approved`, `expires_at`, `broker_lease_expires_at`, `lease_seconds`, STUN/TURN addresses and renewal mode), plus `connection_id`/`generation` when managed. Initial capabilities are pushed before initial mailbox replay. Approval pushes changed capabilities to wake the caller; repeated capabilities RPCs are not needed. Broker/session heartbeat changes also push relevant authorization deadlines.
- `message` contains only the **other** side's committed directional mailbox entries, in ascending sequence. SQLite commit precedes the send success result and subscriber notification. A subscriber may see a committed message before its sender has read the RPC result; that does not justify changing a retry's sequence/data.
- `revoked` identifies an unavailable scope/lease and is followed by close. Known committed revocations wake existing sockets immediately; idle revalidation is bounded to one second. Queued stale pushes are discarded on revocation, but durable history is not deleted by transport cleanup. An already-running network write is bounded by its write deadline. Network failure/queue overflow/server shutdown may close without delivering a final JSON reason.

Receive acknowledgement, with exactly these fields:

```json
{"v":1,"type":"ack","sequence":1}
```

ACK is cumulative **fully consumed** opposite-direction sequence, not a byte receipt. Only session connections accept it. Zero is allowed for an empty consumed prefix; repeated/lower ACKs are harmless and never rewind the cursor. ACK cannot advance beyond messages actually written on this connection (even if later entries already exist in SQLite); it records consumed cursor and does **not** delete idempotency history. There is no ACK result frame. The server sends at most four unacknowledged messages at once; SDK owners must ACK after processing to release further replay. On reconnect, use the last consumed cursor from that owner, not the largest sequence received before failure.

## Managed lifecycle reasons and ordering

A logical connection ID survives individual SIDs. Natural session expiry does not
revoke its original authorization binding or renew any forwarding lease. A new
attempt requires the original account bearer and a new request/token at the known
generation; a replacement SID always starts a fresh mailbox and PAKE exchange.
The old SID's consumed cursor cannot be used as the new SID's cursor.

An unavailable session still uses push type `revoked` followed by close, including
when the *reason* is recoverable transport expiry. Classify its body rather than
the push name alone:

```json
{"v":1,"type":"revoked","status":410,"body":{"error":"session lease expired","error_code":"session_expired","generation":3}}
{"v":1,"type":"revoked","status":409,"body":{"error":"session was replaced","error_code":"session_replaced","generation":4}}
{"v":1,"type":"revoked","status":403,"body":{"error":"connection was explicitly revoked","error_code":"connection_revoked","generation":4}}
```

For an already authenticated managed socket the server freezes its connection ID
along with the SID, tenant, broker, token digest and identity version. On every
revalidation it checks logical authorization **before** ordinary token/session
lookups. Explicit connection revocation and original credential/tenant changes
produce 403 `connection_revoked` or `credential_revoked` before replacement or
natural expiry is considered. A still-authorized lineage whose current SID
changed produces 409 `session_replaced`; a missing/expired current transport row
produces 410 `session_expired`. Only then are ordinary frozen scope/bearer checks
performed. This ordering preserves the cause after SID/token garbage collection.

The database keeps bounded `connection_sessions` history separately from active
session rows. An explicit delete of a retained historical SID can still find and
revoke the logical connection; observing revocation of a still-live session token
persists a tombstone before later natural expiry can hide it. A socket's captured
connection ID permits revalidation even after its SID history was cleaned.
Forgotten history and new upgrades without valid credentials fail closed; these
rules do not authorize a new subscription using a deleted bearer.

410 `session_expired` parks forwarding and permits a fresh attempt only while the
original logical authority and flow grace remain valid. 409 `session_replaced`
retires the old attempt. Terminal 403 revocation cannot be overridden by manual
retry, another login, device rotation or a new grant for a different connection.
Generic 401/403/404 and unrelated 409/410 results do not establish typed recoverable
expiry. WS closure, ping/pong and native reconnect state are not lease grants.

## Race-free replay and bounded lifecycle

The server registers each subscriber **before** reading initial state. A concurrent commit is therefore included in the initial query or leaves a coalesced wake for another catchup. Hooks perform no database queries while holding the hub lock or open SQLite rows. Catchup materializes/finishes rows before nested queries, important because SQLite has `MaxOpenConns(1)`. Messages are read from durable SQLite one at a time through the ACK window; there is no continuously polled REST mailbox and no whole-mailbox RAM copy per connection.

A dropped socket reconnects using the same frozen scope and last consumed cursor, with bounded exponential backoff+jitter. Unacknowledged signal sends reuse identical sequence/data until confirmed; replay duplicates at/below consumed cursor are ignored without feeding PAKE twice. Do not repeat unacknowledged non-idempotent TURN issuance indefinitely: fail/restart setup if its outcome cannot be recovered safely. Heartbeat/approve/delete/offline retain existing business semantics; repeated delete after its bearer/resource removal may return a fatal authorization/not-found status rather than a second success.

On transient disconnect, existing QUIC may continue only through its last successful authorization deadline; transport connection establishment does not extend leases. At lease loss, forwarding stops. Managed typed expiry/replacement parks eligible v2 TCP flows within their original grace and requests a newly authorized transport; old sessions, approvals and TURN credentials are not resurrected. Legacy flows have no such continuity contract. Authorization denial closes scope immediately; a generic error is never converted into a fresh grant merely from its status number.

The broker watcher intentionally does not require an online lease: the same valid device credential can reconnect and explicitly heartbeat to restore the broker UUID. Its SDK state reports the broker control connection; each native peer has a separate data transport and resume handshake. A CONNECTED watcher is not a report that every peer flow recovered. Explicit offline closes existing watcher/session sockets after its success result and revokes managed lineages. A new watcher may reconnect with a still-valid device token for new sessions, but that does not revive those revoked connections. Reconnect policy, including PAUSED and coalesced manual requests, applies to this persistent control handle; see the [recovery guide](<RECONNECT.md>).

Native I/O stops forwarding independently of a blocked WSS/DNS/control join. Short leases must be respected during reconnect and setup. Managed client-peer final close uses a bounded REST logical-connection deletion with its account bearer even if the session token expired. Legacy session/server close uses bounded WS delete/offline with one-shot REST cleanup on failure or absent socket, never continuous polling. Recoverable retirement sends neither lineage deletion nor broker offline. Peers still authenticate directly with the PAKE/privacy protocol: broker approval is an explicit attestation, not independent server knowledge of a peer password.

Server peers retain only a token digest and frozen identity, **not cached authorization or plaintext credentials**. Token expiry/version/status/resource scope is refetched on every RPC, before catchup and at bounded idle ticks. Mutations also check the token and tenant version inside their SQLite transaction, so device rotation cannot race a stale heartbeat. Relay-only permission revocation is distinct from authorization revocation: turning relay off or approving a direct session must not kill a valid direct WS connection.

Each Gorilla connection has one reader and one application writer; concurrent RFC6455 control writes follow Gorilla's documented control-frame API. Compression is disabled. Inherited HTTP deadlines are explicitly cleared on upgrade, then WS deadlines apply: two-second writes, 15-second network ping, 45-second pong timeout. Ping/pong/ACK never renew leases. Per-peer outgoing queue is 32 frames / 262144 bytes, aggregate queued bytes at most 32 MiB; incoming queue is eight frames and globally at most 128 admitted maximum-sized inputs, with 128 bounded network writes and 32 concurrent encoders. Overflow disconnects rather than silently dropping authenticated signal history. These bounds constrain server memory even with slow consumers.

`Server.Close` stops admission, closes hijacked sockets and joins all reader/writer/scope loops **before SQLite closes**; HTTP shutdown alone is insufficient. The optional embedder-only `BeforeWebSocketRequest` hook is nil in production and receives a context canceled on socket/server close; no HTTP request can configure it. Released delayed requests revalidate before mutation. It exists for controlled native lifecycle/counting fixtures, not path dispatch or a bypass of authentication.

## Validation

Regression covers roles/scopes, subprotocol/origin/frame limits, pushes without continuous REST polling, directional replay/ACK/idempotency, dropped connections, lease expiry and joined shutdown. Native paired tests cover trusted WSS plus actual QUIC direct/FORCE TCP/UDP. See the [validation index](LOCAL-VALIDATION.md); operational setup is in [deployment](PRODUCTION-DEPLOYMENT.md).
