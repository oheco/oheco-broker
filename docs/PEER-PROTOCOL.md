# Native peer protocol v1

This is the 0.3.0 native C peer wire and lifecycle contract. Account management
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
  The broker retains its peer password for future sessions; an individual peer
  erases its copy immediately after PAKE processing.
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
which is durably idempotent at the control service. The native v1 setup does not
silently restart a failed PAKE transcript. Uncertain non-idempotent TURN issuance
fails/restarts setup rather than reminting indefinitely.

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

## ICE transport and relay policy

Each peer owns one libjuice 1.7.4 agent. STUN gathering and UDP TURN allocations
are performed by libjuice, not custom STUN packets. The SDK accepts `turn:` URLs
with UDP transport. `turns:` and TURN-over-TCP URLs are not supported by this
native v1 transport and forced relay fails rather than falling back silently.

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

One local accepted TCP socket corresponds to one bidirectional QUIC stream. The
broker validates target ACL and connects the selected address before ACK success.
Only after success are raw TCP bytes forwarded; no per-data framing is added.
Both socket directions use bounded 64KiB buffers and nonblocking I/O, with QUIC
backpressure, directional FIN/`shutdown(SHUT_WR)`, and RESET on errors/closure.
Failed OPEN produces an error ACK and closes the accepted local socket; it is not
reported as a successful usable target. Mapping creation itself only binds the
local listener, so it cannot predict per-connection DNS/connect failures.

ACL entries are exact DNS names, numeric IPv4/IPv6 addresses, or numeric CIDRs,
with inclusive port range and TCP/UDP protocol. No glob or shell syntax exists.
DNS is resolved once on bounded dedicated resolver workers. An exact DNS rule
explicitly authorizes that name's chosen answer; numeric/CIDR rules can authorize
only matching resolved addresses. The selected sockaddr, not the original
hostname, is passed to connect: there is no authorize-then-resolve-again race.

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
Idle UDP flows expire after 60 seconds by default (configurable). Elapsed-time
checks guard `now >= timestamp` before unsigned subtraction: a newly accepted
flow or fragment may have been timestamped after the current tick's cached clock.

## Lifetimes, leases and bounds

Public server/peer/map handles are opaque. Options, peer password and ACL strings
are copied. `ob_api_client` must outlive every handle using it. Caller must
serialize a close with other operations on that same handle. Maps must be closed
before explicit peer destruction; a peer owns any maps still remaining at final
cleanup. Asynchronous disconnect/revocation closes forwarding sockets but leaves
map handles valid for their subsequent explicit close.

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
Unauthorized/missing sessions fail immediately. Successful heartbeats refresh
leases; server disable/token/account changes revoke them. Transport errors alone
never extend authority. Heartbeat scheduling uses at most one third of the
remaining lease, capped at 10 seconds. During transient network/5xx outages the
broker closes expired peers but keeps its control worker and device identity
alive, with bounded exponential retry and jitter; successful reconnect permits
new sessions, never resurrection of old forwarding sockets. Authentication
401/403/404/410 is fatal. The offline mutation is sent only for explicit caller close.
Default control leases are broker 90 seconds, session 10 minutes, refreshed
approximately every 10 seconds.

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

Explicit peer close sends WS `delete`; explicit server close sends WS `offline`
and invalidates sessions. These RPCs have a 300 ms best-effort budget. If a close
RPC fails/times out, its owner disconnects the now-unusable socket; one bounded
300 ms idempotent REST cleanup attempt is permitted, as when no WS existed
initially. There is no continuous REST fallback. The native I/O thread independently
checks explicit server stop and authorization deadlines, immediately closes all
listeners, accepted sockets and target sockets before HTTP/DNS joins, and retains
public mapping handles for later caller close. Expensive cleanup is not used as
the forwarding revocation mechanism. Cleanup stops workers, joins them,
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
