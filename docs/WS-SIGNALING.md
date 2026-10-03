# ob-signaling-v1 WS/WSS signaling contract

This is the 0.3.0 scoped Go server and native SDK signaling contract. REST account/admin management and the authenticated peer envelope remain separate contracts. Implementation and release evidence is indexed in [validation](LOCAL-VALIDATION.md).

REST remains for account/admin operations, broker registration and initial session creation. Persistent broker notifications, PAKE/ICE mailboxes, approval/capabilities, TURN credential requests, heartbeat/lease renewal and lifecycle operations use WS/WSS; the native SDK must not fall back silently to HTTP polling. HTTPS origins map to WSS, loopback HTTP to WS. Public control URL/port and existing C API are unchanged. Peer password, authenticated envelope, certificate pin/exporter and QUIC protocol are unchanged.

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

`status` and `body` preserve the existing REST business contract, including `{error:"safe description"}` failures. Scoped operations are an explicit allowlist, not arbitrary HTTP/path dispatch. Account/admin operations are unavailable on these sockets.

| Scope | Operation | Required body | Business response |
|---|---|---|---|
| Broker watcher | `heartbeat` | `null` | 200 `{broker}`; may restore an offline UUID |
| Broker watcher | `offline` | `null` | 200 `{offline:true}`; removes old sessions, then closes old sockets |
| Session, either side | `heartbeat` | `null` | 200 flat capabilities/status; renews session/caller token and eligible existing TURN credentials, **not** broker lease |
| Session, either side | `capabilities` | `null` | 200 flat capabilities/status |
| Session, either side | `send` | exactly `{sequence,data}` | 201 `{sequence}` or idempotent 200 `{sequence,duplicate:true}`; changed retry/gap 409 |
| Session, broker side only | `approve` | exactly `{peer_authenticated,relay}` (booleans) | 200 `{session}`; peer authentication must be true; force requires relay |
| Session, either side | `turn` | `null` | 200 temporary TURN credential object; capability/approval/lease/quota checks apply |
| Session, either side | `delete` | `null` | 200 `{deleted:true}`; removes caller token/mailbox and closes old sockets |

`send.sequence` starts at one, advances exactly by one in each independent direction and cannot exceed `MaxMessagesPerDirection`. `data` is an opaque UTF-8 string of at most `MaxMessageBytes` (default/max 32768); use base64 for binary peer envelopes. Approval contains both exact boolean fields. No-body operations require JSON `null`, not `{}` or omission. Strict shape/type/protocol failures close the socket; ordinary business denials return a result. A caller's `approve` denial or permission-specific TURN denial is not by itself proof the socket identity has been revoked: scope is revalidated before deciding to close.

Push frames:

```json
{"v":1,"type":"sessions","body":{"sessions":[]}}
{"v":1,"type":"capabilities","body":{}}
{"v":1,"type":"message","sequence":1,"data":"opaque peer envelope"}
{"v":1,"type":"revoked","status":401,"body":{"error":"authorization unavailable"}}
```

- Broker `sessions` is a fresh snapshot, not an incremental array. Entries retain the REST session object fields. The initial snapshot and every committed lifecycle/approval/session-expiry change are pushed without HTTP polling. Maximum snapshot is 128 sessions; an over-limit snapshot yields terminal 429 rather than a misleading truncated list. SDKs deduplicate already-owned sessions by immutable ID.
- Session `capabilities` uses the flat REST status object (`session_id`, `broker_id`, `tenant_id`, `relay_mode`, `peer_authenticated`, `relay_approved`, `expires_at`, `broker_lease_expires_at`, `lease_seconds`, STUN/TURN addresses and renewal mode). Initial capabilities are pushed before initial mailbox replay. Approval pushes changed capabilities to wake the caller; repeated capabilities RPCs are not needed. Broker/session heartbeat changes also push relevant authorization deadlines.
- `message` contains only the **other** side's committed directional mailbox entries, in ascending sequence. SQLite commit precedes the send success result and subscriber notification. A subscriber may see a committed message before its sender has read the RPC result; that does not justify changing a retry's sequence/data.
- `revoked` identifies an unavailable scope/lease and is followed by close. Known committed revocations wake existing sockets immediately; idle revalidation is bounded to one second. Queued stale pushes are discarded on revocation, but durable history is not deleted by transport cleanup. An already-running network write is bounded by its write deadline. Network failure/queue overflow/server shutdown may close without delivering a final JSON reason.

Receive acknowledgement, with exactly these fields:

```json
{"v":1,"type":"ack","sequence":1}
```

ACK is cumulative **fully consumed** opposite-direction sequence, not a byte receipt. Only session connections accept it. Zero is allowed for an empty consumed prefix; repeated/lower ACKs are harmless and never rewind the cursor. ACK cannot advance beyond messages actually written on this connection (even if later entries already exist in SQLite); it records consumed cursor and does **not** delete idempotency history. There is no ACK result frame. The server sends at most four unacknowledged messages at once; SDK owners must ACK after processing to release further replay. On reconnect, use the last consumed cursor from that owner, not the largest sequence received before failure.

## Race-free replay and bounded lifecycle

The server registers each subscriber **before** reading initial state. A concurrent commit is therefore included in the initial query or leaves a coalesced wake for another catchup. Hooks perform no database queries while holding the hub lock or open SQLite rows. Catchup materializes/finishes rows before nested queries, important because SQLite has `MaxOpenConns(1)`. Messages are read from durable SQLite one at a time through the ACK window; there is no continuously polled REST mailbox and no whole-mailbox RAM copy per connection.

A dropped socket reconnects using the same frozen scope and last consumed cursor, with bounded exponential backoff+jitter. Unacknowledged signal sends reuse identical sequence/data until confirmed; replay duplicates at/below consumed cursor are ignored without feeding PAKE twice. Do not repeat unacknowledged non-idempotent TURN issuance indefinitely: fail/restart setup if its outcome cannot be recovered safely. Heartbeat/approve/delete/offline retain existing business semantics; repeated delete after its bearer/resource removal may return a fatal authorization/not-found status rather than a second success.

On transient disconnect, existing QUIC may continue only through its last successful authorization deadline; transport connection establishment does not extend leases. Broker persists retrying after lease outage; old forwarding peers die and cannot be resurrected by a new connection. Fatal 401/403/404/410 **scope revalidation**, or 409 expired broker lease for a session socket, closes immediately. Expired sessions/credentials never resurrect. The broker watcher intentionally does not require an online lease: the same device credential can reconnect and explicitly heartbeat to restore the broker UUID. Explicit offline closes existing watcher/session sockets (after its success result); a new watcher may reconnect with the still-valid device token, but removed sessions cannot resume.

Native I/O stops forwarding independently of a blocked WSS/DNS/control join. Short leases must be respected during reconnect and setup. Explicit close attempts a bounded WS lifecycle RPC; REST deletion/offline may be retained solely as one-shot cleanup if no socket exists, never a continuous-poll fallback. Peers still authenticate directly with the unchanged PAKE/privacy protocol: broker approval is an explicit attestation, not independent server knowledge of a peer password.

Server peers retain only a token digest and frozen identity, **not cached authorization or plaintext credentials**. Token expiry/version/status/resource scope is refetched on every RPC, before catchup and at bounded idle ticks. Mutations also check the token and tenant version inside their SQLite transaction, so device rotation cannot race a stale heartbeat. Relay-only permission revocation is distinct from authorization revocation: turning relay off or approving a direct session must not kill a valid direct WS connection.

Each Gorilla connection has one reader and one application writer; concurrent RFC6455 control writes follow Gorilla's documented control-frame API. Compression is disabled. Inherited HTTP deadlines are explicitly cleared on upgrade, then WS deadlines apply: two-second writes, 15-second network ping, 45-second pong timeout. Ping/pong/ACK never renew leases. Per-peer outgoing queue is 32 frames / 262144 bytes, aggregate queued bytes at most 32 MiB; incoming queue is eight frames and globally at most 128 admitted maximum-sized inputs, with 128 bounded network writes and 32 concurrent encoders. Overflow disconnects rather than silently dropping authenticated signal history. These bounds constrain server memory even with slow consumers.

`Server.Close` stops admission, closes hijacked sockets and joins all reader/writer/scope loops **before SQLite closes**; HTTP shutdown alone is insufficient. The optional embedder-only `BeforeWebSocketRequest` hook is nil in production and receives a context canceled on socket/server close; no HTTP request can configure it. Released delayed requests revalidate before mutation. It exists for controlled native lifecycle/counting fixtures, not path dispatch or a bypass of authentication.

## Validation

Regression covers roles/scopes, subprotocol/origin/frame limits, pushes without continuous REST polling, directional replay/ACK/idempotency, dropped connections, lease expiry and joined shutdown. Native paired tests cover trusted WSS plus actual QUIC direct/FORCE TCP/UDP. See the [validation index](LOCAL-VALIDATION.md); operational setup is in [deployment](PRODUCTION-DEPLOYMENT.md).
