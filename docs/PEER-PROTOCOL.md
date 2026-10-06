# Native peer protocol: v1 compatibility and v2 recovery

This is the 0.4.0 native C peer wire and lifecycle contract. Account management
uses the separate REST API; local command execution uses its own binary protocol.
The source API is [ob_remote.h](../sdk/c/remote/ob_remote.h); management HTTP is
provided by `ob_api`. Go wraps this engine through cgo without a Go network callback.

## Trust boundaries

* An **account password** authenticates management requests. An account bearer
  authorizes creating a session; a broker device bearer authorizes the broker's
  heartbeat and mailbox. A session bearer authorizes the caller's mailbox.
* A **peer password** is copied into native memory and is never included in an
  HTTP request, header, URL, log, or persisted by this SDK. Only opaque PAKE
  messages and authenticated signalling envelopes are submitted to the mailbox.
  Both the broker and a reconnectable peer retain their copied password in native
  memory for fresh PAKE on later attempts. Final handle destruction erases that
  copy and the retained recovery secret. The password is not persisted by the SDK.
* Mailbox/control and TURN servers are not trusted with forwarding plaintext.
  They can observe identities, timing, traffic lengths, ICE topology and opaque
  protocol messages, and can deny service. A malicious mailbox cannot replace
  an authenticated ICE description or certificate pin without detection.
* There is no listener identity authentication, second password prompt, shell
  command, post-authentication group, or implicit target access. Anyone who can
  reach a local mapping listener can use its fixed target while the peer remains
  authorized. Default listening address is **127.0.0.1**, not all interfaces.
* The broker target ACL defaults to **deny everything**. Tests explicitly allow
  their own loopback echo ports. Deployments must explicitly choose targets.

## Fixed PAKE suite (not RFC 9382)

Suite identifier:

```
OBP1/BoringSSL-SPAKE2-draft02/Ed25519/SHA512/HKDF-SHA256
```

The implementation uses the unmodified mature BoringSSL `SPAKE2_CTX_new`,
`SPAKE2_generate_msg` and `SPAKE2_process_msg` APIs from `openssl/curve25519.h`
at pinned commit `5e1bfb45c353b2bb36bdf26b006ea8f5566c82d5`. This is BoringSSL's
**draft-irtf-cfrg-spake2-02 implementation**, including its upstream Ed25519
encoding and password-scalar behavior. It is **not RFC 9382**, not SPAKE2+, and
is not claimed interoperable with either. No custom curve arithmetic or password
hash construction is substituted. The fixed suite has no negotiation/downgrade.

Client is SPAKE2 Alice; broker is Bob. Identifiers are exact UTF-8 strings:

```
ob-peer-v1/client/<broker UUID>/<session UUID>
ob-peer-v1/server/<broker UUID>/<session UUID>
```

Each side sends one upstream 32-byte SPAKE2 message as lowercase hex. It then
processes the other side's message into the upstream 64-byte shared key. This
alone does not prove password agreement: **explicit mutual key confirmation is
mandatory** before ICE installation and before broker approval.

The directional signalling keys are HKDF-SHA256(shared key, salt, info), producing
64 bytes: first 32 bytes client-to-broker, last 32 broker-to-client. The salt is
SHA256 of the following concatenation in this exact order:

1. Suite identifier above, including one trailing NUL.
2. Broker UUID, including one trailing NUL.
3. Session UUID, including one trailing NUL.
4. Alice's raw 32-byte SPAKE2 message.
5. Bob's raw 32-byte SPAKE2 message.

HKDF info is `ob-peer-v1 directional signalling`, without trailing NUL. Two-way
`confirm` messages MAC the literal payload `ob-peer-v1 key confirmation`. A
wrong password, reflected role, changed transcript, changed identity or changed
session therefore fails before targets or ICE remote descriptions are accepted.
Online password guesses remain possible and require control-side session/rate
limits. This implementation has not received an independent security audit.

## Signalling envelope and sequence

Persistent signaling follows [ob-signaling-v1](<WS-SIGNALING.md>): the caller or
broker session owner sends a WS `send` RPC with `{sequence,data}` and receives
opposite-direction `message` pushes. REST is retained only for initial account,
device registration and session creation (and one-shot best-effort close cleanup
when no WS exists), never continuous polling. `data` remains an opaque string
containing the unchanged peer envelope:

```
{"v":1,"sid":"<session UUID>","seq":1,"t":"pake","payload":"<hex>"}
{"v":1,"sid":"<session UUID>","seq":2,"t":"confirm",
 "payload":"ob-peer-v1 key confirmation","mac":"<64 lowercase hex>"}
{"v":1,"sid":"<session UUID>","seq":3,"t":"ice",
 "payload":"<exact JSON string>","mac":"<64 lowercase hex>"}
```

Each direction independently starts at 1. The envelope sequence must equal both
the pushed mailbox sequence and the next expected sequence. SID, version, message type,
payload type, strict hex and bounds are checked. Version and sequences use exact
numeric equality rather than cJSON's truncated `valueint`, plus validation of the
original plain unsigned decimal token spelling. Tiny fractions that round to an
integer double, decimal points, exponents, signs and overflow are rejected before
consumption. Sequences are restricted to JSON's safely represented integer range
(through 2^53−1). Ordinary nested business-body floats remain allowed; general
body parsing retains pristine cJSON semantics, not a replacement RFC-8259 parser. Duplicate or unknown
envelope keys are rejected. Before cJSON decoding, actual escaped U+0000 is
rejected in control responses, envelope strings and nested ICE JSON, without
rejecting a genuinely literal escaped backslash followed by `u0000`. This avoids
hidden suffix truncation because cJSON's decoded strings do not retain a length.
Trailing non-whitespace JSON data is also rejected. Skipped, reflected, unexpected
or modified authenticated envelopes fail closed. Reconnect replay at or below the
last semantically consumed cursor is ignored before PAKE/confirmation processing;
it is never fed into the transcript twice. ACK is emitted only after
`ob_decode_signal` validates the expected envelope/MAC and advances the actual
receive sequence; invalid receipt is not acknowledged. Reconnect subscribes with
`after=<consumed cursor>`. A lost send result retries the identical sequence/data,
which is durably idempotent at the control service. A transport recovery attempt
uses a newly authorized session and fresh PAKE transcript; it does not reuse or
silently restart the transcript of the old SID. Uncertain non-idempotent TURN
issuance fails/restarts setup rather than reminting indefinitely.

Except for `pake`, the MAC is HMAC-SHA256 with the directional key over:

```
uint64_be(sequence) || type || NUL || exact UTF-8 payload bytes
```

The key's transcript derivation binds the session ID and identities. MACs are
compared in constant time. JSON formatting inside `payload` is not canonicalized;
it is authenticated exactly as transmitted. Full gathered ICE descriptions are
used rather than unauthenticated/trickled candidates. `juice_set_remote_description`
is never called before the enclosing ICE message's MAC verifies.

The authenticated ICE payload contains `sdp`. Broker additionally includes
`cert_sha256`: SHA256 of its exact DER leaf certificate, lowercase hex. Both sides
verify PAKE confirmation before the broker submits
WS `approve {peer_authenticated:true,relay:<bool>}`. TURN credentials
are requested only after approval and control-side tenant relay authorization.

### Authenticated mapping negotiation and retained context

0.4.0 sends `mapping_version:2` inside the MAC-authenticated ICE JSON. A received
value must be 1 or 2; absence selects legacy v1. Version 2 is used only with a
peer advertising 2. The PAKE suite, envelope version, QUIC version and ALPN
`ob-peer-v1` retain their existing values. An unauthenticated capability, mailbox
field or TLS hint cannot select mapping v2. The legacy v1 wire is described below;
compatibility by protocol selection does not by itself assert that every older
binary has passed the current native acceptance suite.

A managed connection obtains its logical `connection_id` and monotonically
advancing backend `generation` from the [control API](<CONTROL-API.md>). Every
attempt has a fresh SID, PAKE shared key, ICE agent, QUIC connection and channel
proof. Local SDK attempt counters/generations are status information; the backend
generation below is the one used in the cryptographic binding.

The 32-byte candidate recovery key is HKDF-SHA256 with:

```text
IKM  = this attempt's upstream SPAKE2 shared key
salt = exact UTF-8 connection UUID bytes, without a trailing NUL
info = "ob-peer-v2 logical recovery context", without a trailing NUL
L    = 32
```

The first authenticated connection establishes that key. A live logical peer
retains it in memory across transport attempts; deriving a new PAKE candidate
does not overwrite a successfully retained context. If a newly authenticated
connection has no matching retained context, old established flows are closed
and the fresh candidate becomes the context for new flows. A backend connection
record cannot reconstruct this native secret or its sockets after process loss.

When a key exists, each side adds `resume_proof` as 64 lowercase hex characters
to its authenticated ICE JSON. For sender role byte 0 (client) or 1 (broker),
the raw 32-byte value is HMAC-SHA256(retained key, concatenation):

```text
"ob-peer-v2 authenticated reattachment" || NUL || role_byte ||
broker_uuid || NUL || connection_uuid || NUL || session_uuid || NUL ||
backend_generation:u64_be || SHA256(this attempt's SPAKE2 shared key)
```

This binds the retained context to the broker, logical ID, new SID/generation,
fresh PAKE exchange and direction. Verification uses the opposite role and a
constant-time comparison; missing or mismatched proof means retained context is
unavailable. Fresh PAKE/key confirmation and the new QUIC certificate/exporter
proof remain mandatory. No existing TCP stream is rebound and no business
payload is forwarded merely because a resume proof, managed ID or fresh TLS
connection was received.

## ICE transport and relay policy

Each peer owns one libjuice 1.7.4 agent. STUN gathering and UDP TURN allocations
are performed by libjuice, not custom STUN packets. The SDK accepts `turn:` URLs
with UDP transport. `turns:` and TURN-over-TCP URLs are not supported by this
native transport (both mapping versions), and forced relay fails rather than falling back silently.

* `never`: no TURN credentials/servers are installed.
* `auto`: TURN credentials are installed when permitted and usable; direct ICE
  remains available. Missing relay authorization does not prevent direct ICE.
* `force`: the SDK offers only relay candidates and filters the MAC-verified
  remote description to component-1 UDP relay candidates before installation;
  an offer with no usable relay fails. Candidate type is a fixed token field,
  not a substring or a later extension. Embedded CR that libjuice would remove
  before interpreting candidate prefixes is rejected. The pinned libjuice
  dependency has a narrow `juice_config_t.relay_only` extension that disallows
  non-relayed local candidate pairs, including peer-reflexive/ICE-TCP bypass,
  and guards application send/receive against direct nomination. The SDK also
  checks the actual selected **local** UDP candidate is a relay before accepting
  or writing any QUIC packet. A remote peer-reflexive label does not cause a
  false rejection when the local transport is physically TURN-relayed. A remote
  `typ relay` assertion alone is not accepted as physical-relay proof. No
  application packet is allowed over host-only ICE as a fallback.

The libjuice relay policy patch remains the **one irreducible upstream source
patch** in this dependency cleanup; it is not described as pristine. Public
`juice_get_selected_candidates` reports a real selected pair, and a selected
local relay maps to libjuice's TURN ChannelData send entry. However the getter
locks and releases the pair separately from `juice_send`, which loads the send
entry again. A controlled agent can accept a later, higher-priority nomination;
remote peer-reflexive candidates can be direct even after relay-only SDP
installation. A check-then-send gate alone therefore cannot provide the previous
atomic physical-relay guarantee under a hostile peer. Remote `typ relay` is also
an authenticated peer assertion, not independent proof of a TURN allocation.
Replacing this patch would require a separately bounded mature TURN transport
adapter/dependency, not a disguised copy of patched libjuice or home-grown TURN.
The SDK does not silently weaken paid FORCE into best-effort/direct fallback.

A stable synthetic loopback sockaddr pair identifies each association to xquic;
it does **not** identify the TURN server as the authenticated peer. The libjuice
receive callback copies bounded UDP packets into a mutex-protected queue. Only
that peer's owned engine thread drains the queue into
`xqc_engine_packet_process`, runs `xqc_engine_finish_recv`, and services the
scheduled `xqc_engine_main_logic` deadline (1ms timer quantum, application socket
polling at most 10ms). Application writes also pump pending engine work; stream
read/write/close callbacks defer processing/reclamation to the owned tick so
xquic's synchronous send reentrancy cannot duplicate control frames or free their
contexts mid-call. xquic's write callback uses `juice_send`. No synchronous HTTP
request runs on this thread.

## QUIC TLS and channel proof

Broker is always QUIC server; caller is always QUIC client. ALPN is `ob-peer-v1`,
QUIC version is v1. SDK application packet encryption is mandatory. Both local
configurations use `no_crypto_flag=0`, no restored session ticket or previous
transport parameters, and no application 0-RTT. **xquic 1.9.7 is unmodified**;
there is no `XQC_DISALLOW_NO_CRYPTO` build flag or SDK compile-time dependency on
that former patch. Instead both roles' SDK handshake callback obtains the
actual authenticated peer transport parameters using public `xqc_conn_get_ssl`
and BoringSSL `SSL_get_peer_quic_transport_params`. An SDK-owned parser traverses
the complete RFC 9000 sections 16/18 TLV sequence and checks xquic 1.9.7's private
`no_crypto` ID `0x1000`. Absent or exactly zero is accepted; **any nonzero value**,
malformed value, duplicate private parameter, truncated TLV, or missing parameters
fails closed before `tls_ready`, exporter proof, OPEN, DATAGRAM, or public ready.
Unknown parameters are skipped by their actual lengths, not searched for byte
patterns. No private xquic header or codec is used by production policy.

Checking `SSL_get_current_cipher` would be insufficient: TLS may still negotiate
AES while upstream xquic switches its application packet protection to null
crypto. The SDK gate is an application boundary, not a change to xquic's internal
TP adoption: upstream may adopt null protection and send transport-only packets
before notifying the completed handshake. Such a connection is stopped without
sending SDK proof/OPEN/DATAGRAM or exposing a ready peer. Exporter-proof creation
independently rechecks the same authenticated peer parameters. The private ID is
a pinned-version dependency and must be rechecked when upgrading xquic. Each
association gets a fresh self-signed P-256 certificate, used solely with a
PAKE-authenticated fingerprint, not public-PKI hostname authentication.

The xquic certificate callback hashes actual DER certificate bytes and compares
them with the authenticated pin. The handshake callback additionally verifies
`SSL_get_peer_certificate` against that pin, regardless of whether upstream's
chain verification callback was needed. It does not simply accept arbitrary
self-signed certificates. Self-signed-chain allowance does not replace pinning.

Certificate and private key are created using BoringSSL in a `mkdtemp` 0700
directory under `$TMPDIR`; files are exclusive 0600 creations. A runtime directory
permission check rejects a filesystem that cannot provide that privacy. There is
no insecure `/tmp` fallback and no credential file under HOME. Files are removed
when the peer is destroyed, including failed setup paths.

After the TLS handshake, the first client bidirectional stream (ID 0) carries a
mutual 32-byte proof. The TLS exporter is:

```
SSL_export_keying_material(..., 32, "EXPORTER-ob-peer-v1",
                           session_uuid_bytes, use_context=1)
```

For sender role byte 0 (client) or 1 (broker), proof is HMAC-SHA256 using the
64-byte SPAKE2 key over:

```
"EXPORTER-ob-peer-v1" || NUL || role_byte || certificate_sha256 || exporter
```

A broker validates the client proof and replies with its own proof. Client
validates the reply. No OPEN or DATAGRAM is accepted until this proof finishes.
The API's connect call returns only then. No session ticket or previous transport
parameters are restored; application **0-RTT is disabled** and pre-proof data is
rejected. TURN sees QUIC ciphertext, not OPEN hostnames or socket payloads.

## Reliable mapping stream wire format

All multibyte integers are big endian. Every new stream begins with:

```
"OBM1" || kind:u8 || protocol:u8 || payload_size:u16 || flow_id:u64 || payload
```

* PROOF kind 1: protocol=0, flow_id=0, payload_size=32. Client first stream ID 0
  and broker reply use the channel proofs above. Each sending direction then FINs.
* OPEN kind 2: protocol=1 TCP or 2 UDP; payload is target port:u16 plus a bounded,
  non-NUL hostname (maximum 253 bytes). Flow ID is a nonzero client-owned odd ID;
  duplicates or invalid role ownership are rejected.
* ACK kind 3: same protocol and flow ID; payload_size=4; result:u32, zero for
  success and positive absolute native error code otherwise.

OPEN/ACK and PROOF keep this encoding in both negotiated versions. The broker
validates target ACL and connects the selected address before ACK success.
Failed OPEN produces an error ACK and closes the accepted local socket. Mapping
creation itself only binds the local listener, so it cannot predict per-connection
DNS/connect failures.

**Legacy v1 TCP:** one accepted socket corresponds to one bidirectional QUIC
stream; after ACK success it carries raw bytes with no per-data framing. Both
socket directions use bounded 64KiB buffers and nonblocking I/O, QUIC
backpressure, directional QUIC FIN/`shutdown(SHUT_WR)`, and RESET on errors or
closure. Existing v1 TCP flows end when their transport is lost; a reconnect can
retain mapping handles/listeners for new business connections, but cannot
transparently resume the old v1 byte stream.

ACL entries are exact DNS names, numeric IPv4/IPv6 addresses, or numeric CIDRs,
with inclusive port range and TCP/UDP protocol. No glob or shell syntax exists.
DNS is resolved once on bounded dedicated resolver workers. An exact DNS rule
explicitly authorizes that name's chosen answer; numeric/CIDR rules can authorize
only matching resolved addresses. The selected sockaddr, not the original
hostname, is passed to connect: there is no authorize-then-resolve-again race.

## Mapping v2 TCP delivery and recovery

After a successful TCP OPEN/ACK, each direction carries OBM2 delivery frames on
the bidirectional QUIC stream. The header is exactly 24 bytes; all integers are
unsigned and big endian:

```text
"OBM2" || kind:u8 || flags:u8 || payload_size:u16 || flow_id:u64 || offset:u64
        || exactly payload_size bytes
```

Offsets count logical TCP bytes separately in each direction and survive a
transport replacement. The flow ID must equal that stream's retained logical
flow. Unknown kinds/flags, length/offset overflow, gaps and inconsistent FIN
state are rejected.

| Kind | Flags / size | Offset and meaning |
|---|---|---|
| DATA = 1 | flags=0; size 1–16384 | First byte offset, followed by exactly that many socket bytes. |
| ACK = 2 | size=0; only flag bit 0 allowed | Cumulative bytes accepted by successful `send` calls to the real receiving TCP socket; bit 0 additionally confirms its write side was shut down at this final offset. |
| FIN = 3 | flags=0; size=0 | Immutable final byte offset for the sending TCP direction. |

ACK acknowledges delivery to the local TCP socket, rather than QUIC receipt or
application-level processing. The sender retains unacknowledged bytes even after
QUIC has received them. ACK may not exceed bytes actually submitted or the
retained transmit range; a FIN ACK must match the sender's recorded socket EOF
and final offset. Repeated older cumulative ACKs do not rewind delivery.

The receiver accepts DATA at its next offset or validates replay against its
retained receive range. Already committed bytes are discarded without being sent
to the target again; overlapping uncommitted bytes must match. FIN must name the
next received byte offset, and repeat FINs must agree. `shutdown(SHUT_WR)` occurs
only when all bytes through that offset have been committed to the real socket;
its ACK then records the applied FIN. Reads in the opposite direction continue.
A bare QUIC FIN is not an application FIN in v2 and is rejected. Transport
retirement itself does not half-close an established retained TCP socket.

### OBM1 RESUME / RESUME_ACK

Once the new QUIC channel proof succeeds, the client opens a fresh stream for the
same flow ID with OBM1 kind **4 (RESUME)**, protocol=1, payload_size=40. The broker
replies with kind **5 (RESUME_ACK)**, the same protocol/ID and exactly 40 bytes.
Both use the common 16-byte OBM1 header above. Payload layout is:

| Byte offset | Type | Meaning from the sender's perspective |
|---|---|---|
| 0 | u32 | Result: zero for success; RESUME requests use zero; failed ACK uses the positive absolute native error code. |
| 4 | u32 | Flags: bit 0 = local socket read EOF/final transmit offset known; bit 1 = received FIN already applied to local socket; all other bits zero. |
| 8 | u64 | `rx_commit`: opposite-direction bytes committed to the real socket. |
| 16 | u64 | `tx_base`: first retained, unacknowledged transmit byte. |
| 24 | u64 | `tx_next`: end of retained transmit bytes. |
| 32 | u64 | `tx_final`: immutable transmit final offset when flag bit 0 is set; zero otherwise. |

Each side checks the opposite snapshot against its retained ranges: remote
`tx_base <= local rx_commit <= remote tx_next`, and local
`tx_base <= remote rx_commit <= local tx_next`. Acknowledgement also cannot exceed
bytes previously submitted. If transmit EOF is set, `tx_final == tx_next`;
otherwise `tx_final == 0`. Applied-FIN flags must agree with the other side's
known EOF/final offset, and an already observed FIN cannot change.

A successful snapshot trims acknowledged transmit bytes, discards incomplete
receive frames, restores receive parsing at `rx_commit`, and replays the remaining
transmit range on the new stream. The broker rebinds only an existing suspended
v2 TCP flow with its original live target socket and unexpired grace deadline.
It does not issue another target `connect` for a retained flow. Missing context,
invalid offsets or expired grace yield an error ACK/closure. New business
connections use new OPENs; an old business stream is never silently replayed into
a new target connection.

The client waits for RESUME_ACK before resuming ordinary delivery. The broker
keeps its original recovery deadline until a subsequent valid OBM2 frame proves
that the client received the ACK; an attempt that dies during the ACK exchange
cannot erase the flow or renew its deadline just because the new stream was
partly established. Pending local OPENs that never established a target can be
issued as fresh OPENs after readiness.

### Resource and lifetime boundaries

Each TCP flow retains at most a **64KiB transmit replay buffer and 64KiB receive
buffer**. Mapping heap allocations, including flow/control state, resolver work
and UDP buffers, share a hard **16MiB per-peer tracked budget**. Ordinary payload
allocation leaves a control reserve of
`(effective max_flows + 2) * sizeof(flow context)` inside that budget so recovery
parsers/proof contexts remain possible when business buffers fill it. This is a
reserve within the limit, not additional memory or a new public capacity promise.
Transient incoming parsers do not consume the logical-flow count, but remain
counted and memory bounded. The default 128-flow setting is an admission ceiling;
actual admitted TCP capacity can be lower under the byte budget and resolver
usage. The native stress fixture verifies recovery of all 125 flows actually
admitted in that build, without changing their targets or sockets.

A flow's grace deadline starts at the recoverable outage and survives failed
attempts, backoff and PAUSED. A manual reconnect can renew the attempt budget,
**not an existing flow's grace deadline**. Uncommitted receive bytes may be
forgotten because the sender retains them; committed byte counters and directional
FIN state remain. Final close, revocation, context loss or grace expiry closes the
old sockets. A retained secret does not preserve TCP across process termination.

## Unreliable UDP mapping wire format

A UDP flow is isolated by mapping plus local source IP/port, with a separate
connected remote UDP socket. A reliable OPEN/ACK stream establishes and owns the
flow, but **UDP payloads only use RFC 9221 QUIC DATAGRAM**, never reliable streams.
This preserves independent responses to each original local source.

Each DATAGRAM is:

```
"OBD1" || flow_id:u64 || packet_id:u64 || total:u16 || offset:u16 || size:u16
       || reserved_zero:u16 || exactly size payload bytes
```

Fragments are fixed at 512 payload bytes except the last fragment; offsets must
be multiples of 512 and lengths must match total/offset exactly. Payloads through
65507 bytes are supported (maximum 128 fragments). QUIC DATAGRAM MSS must be at
least 540 bytes; otherwise a queued UDP packet is dropped, never converted into
reliable data. Zero-length UDP is represented by total=offset=size=0, and is
forwarded as an actual zero-length socket datagram.

Each flow permits four queued outgoing packets and four bounded in-progress
reassemblies, subject to the global peer memory cap. Queued packets expire after
1 second; incomplete reassemblies expire after 2 seconds. Out-of-order fragments
are accepted, exact duplicates ignored, inconsistent duplicates rejected, and a
64-packet window prevents duplicate completed delivery. Loss of one fragment
loses the packet. The lost-DATAGRAM callback returns zero and neither the SDK nor
xquic is configured to request reliable retransmission. Congestion/backpressure
or local UDP socket EAGAIN may drop a datagram, consistent with UDP semantics.
Idle UDP flows expire after 60 seconds by default (configurable). On transport
loss, UDP flows, queued packets and partial reassemblies are discarded; local UDP
mapping handles/ports remain, and datagrams received during the outage are drained
and dropped. A new authenticated transport creates fresh UDP flows for new traffic.
UDP is never replayed using the TCP resume mechanism. Elapsed-time checks guard
`now >= timestamp` before unsigned subtraction: a newly accepted flow or fragment
may have been timestamped after the current tick's cached clock.

## Lifetimes, leases and bounds

Public server/peer/map handles are opaque. Options, peer password and ACL strings
are copied. `ob_api_client` must outlive every handle using it. Caller must
serialize a close with other operations on that same handle. Maps must be closed
before explicit peer destruction; a peer owns any maps still remaining at final
cleanup. Recoverable disconnect preserves listeners and eligible v2 TCP sockets;
terminal revocation closes forwarding sockets while leaving map handles valid
for their subsequent explicit close.

The broker has a separate persistent WS heartbeat/snapshot-listener worker;
every peer has its own WS control/setup worker and an owned native I/O thread.
Each WS socket/private curl handle has exactly one C owner; there are no competing
reads and no session-bearer cross-scope reuse. Initial and approval capabilities
are pushed, not repeatedly requested; durable mailbox pushes replace GET polling.
Session capabilities pushes and heartbeat results carry session/broker expiries,
converted to a conservative monotonic deadline capped at 120 seconds. The initial
lease is explicitly marked unset until a validated capability arrives, rather
than interpreting a transient zero as revocation. A previously set expired lease
can never be renewed by a delayed reply. The engine independently stops forwarding
at that deadline even if WSS, DNS, connect or a control RPC is stalled. Setup
pumps WS receive and due heartbeats during PAKE, approval and ICE waits, and
continues receiving/heartbeating after ready. WS PING/PONG is liveness only, never
a lease grant.
Successful heartbeats refresh leases; server disable/token/account changes revoke
them. Transport errors alone never extend authority. Heartbeat scheduling uses at
most one third of the remaining lease, capped at 10 seconds. Default control
leases are broker 90 seconds and session 10 minutes, refreshed approximately every
10 seconds. Forwarding stops at the last valid lease even during blocked control
I/O; retaining a TCP socket grants no authority to read or forward business bytes.

For a managed connection, typed 410 `session_expired` retires the expired attempt,
parks forwarding and permits fresh-session issuance under the original still-live
account/device/tenant binding. Typed 409 `session_replaced` retires a superseded
SID. Neither resurrects the old session, its approval or its TURN credential.
Explicit 403 `connection_revoked` / `credential_revoked` is terminal; missing or
invalid authorization and unrelated status errors must not be guessed to be
recoverable expiry. The backend retains the necessary lineage/history after
transport cleanup and gives revocation priority over expiry. Legacy sessions
retain their fail-closed authorization behavior and cannot supply managed-context
continuity. The offline mutation is sent only for explicit server caller close.

### Persistent handles and reconnect policy

Recoverable ICE, QUIC or control failure retires the transport while preserving
public peer/map handles, local listeners and ports. The engine owner suspends
mapping I/O before destroying the old QUIC connection; the coordinator waits for
that barrier and completion of old ICE callbacks before replacing an attempt.
Retained v2 TCP sockets and byte/FIN state stay within their original grace.
Successful fresh authentication is followed by individual RESUME exchanges.
Public CONNECTED therefore denotes the new authenticated transport; an old flow
may still be resuming or may have failed separately.

States are CONNECTING, CONNECTED, RECONNECTING, RETRY_WAIT, PAUSED, FAILED and
CLOSED. Default automatic policy allows 8 attempts in a 60-second outage budget,
first recovery attempt immediately and subsequent exponential delay from 1 to
15 seconds with 0–25% jitter. TCP grace is 120 seconds. A stable 30-second
connection resets the failure budget. Mapping v2 detects QUIC idle loss after
15 seconds by default and both roles send owner-scheduled PING at one third of
that timeout, capped at 5 seconds; legacy v1 retains its 90-second timeout.
Automatic-policy exhaustion parks the handle in PAUSED. Manual requests are
nonblocking and coalesced, can start a new attempt budget, and do not rebuild an
already healthy connection. With automatic reconnect disabled, a manual request
permits that one attempt rather than enabling subsequent automatic retries. They cannot
reset an unrestored flow's deadline or revive a terminally closed/revoked handle.

The server's state snapshot describes its broker **control connection**. Each
logical peer independently authenticates and restores its data transport; a
CONNECTED server snapshot does not prove all peer flows are ready. C state
callbacks run outside SDK locks on an SDK worker and must hand close/destruction
to the application thread. Go polls copied snapshots through the same C engine.
See the [recovery guide](<RECONNECT.md>) for APIs and CLI SIGUSR1 behavior.

For the self-hosted control/TURN provider, capability
`turn_credential_renewal: session-heartbeat` means successful authenticated
session heartbeats renew the lease of the already issued username/password while
that session is active and approved; expired credentials cannot be resurrected.
The native SDK does not rotate ICE agents or redistribute new descriptions for
providers without this contract: such providers require peer restart before
credential expiry. Credential TTL must cover initial ICE gathering and the
heartbeat interval (at most 10 seconds); extremely short provider TTLs can safely
fail setup rather than cause an unauthenticated/direct fallback. A future Workers
provider is not implemented or claimed by this local native work.

Explicit managed client-peer close uses a bounded REST deletion of its logical
connection with a current account bearer from the original stable login authority
(or its original legacy bearer), so an already-expired session token
cannot prevent final closure. Legacy peer close sends WS `delete`; explicit
server close sends WS `offline` and revokes its sessions/lineages. Cleanup has a
300 ms best-effort operation budget. If a WS close RPC fails or times out, its
owner disconnects that socket and may make one bounded idempotent REST cleanup
attempt. These lifecycle calls are not continuous signaling fallback. Recoverable
attempt retirement does not send logical connection deletion or broker offline.

The native I/O thread independently checks explicit stop and authorization
deadlines before HTTP/DNS joins. Terminal stop closes listeners, accepted sockets
and targets immediately, retaining public mapping handles for later caller close.
Recoverable lease expiry stops forwarding and parks eligible sockets within their
grace; fresh authorization is required before resumption. Expensive cleanup is
not used as the forwarding revocation mechanism. Cleanup stops workers, joins them,
destroys ICE and engine, closes listeners/target sockets, removes temporary key
files and erases secrets. WS upgrade attempts are capped at 1500 ms and the
remaining setup/lease deadline, with stop-aware curl progress cancellation;
socket receive/send waits inspect cancellation at bounded intervals. A pending
control operation may delay final join to its bounded timeout, but cannot delay
native I/O lease shutdown or run QUIC logic on another thread.

Defaults: 16 peers per server, 32 maps and 128 flows per peer. Accepted hard caps:
128 peers, 128 maps and 512 flows. Each peer bounds its pending ICE receive queue
to 256 packets of at most 2048 bytes, mapping allocation budget to 16MiB, QUIC send
queue to 1024 packets, an approximately 1MiB initial aggregate QUIC receive
window growing only to the dependency's 16MiB maximum, and a 64KiB initial window
for locally initiated streams. Receive-rate control is configured at 16MiB/s to
avoid upstream's otherwise enormous sum-of-stream-windows connection limit.
Proof has one extra flow allowance. New work exceeding limits is refused/dropped rather than growing
without bound. Resolver work is independently bounded. These are implementation
limits, not an assertion of total process memory independent of dependency state.

## Build and validation

The SDK is distributed as source with its complete pinned inputs and offline resources. Build with `sh sdk/c/build.sh`; see [native dependencies](NATIVE-DEPENDENCIES.md) for C/C++ runtime requirements and [validation](LOCAL-VALIDATION.md) for checkout regression and release scope.
