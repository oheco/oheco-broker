# oheco-broker protocols v1 and v2 (service 0.2.0)

Status: implementation contract. No JSON, authentication, TLS, compression or third-party codec. Trusted local development ONLY: any local process able to connect can execute commands as the broker user. Discovery is not authenticated.

## Discovery and connection

Default discovery file: `$HOME/.oheco/broker/endpoint`. Applications may supply an explicit path. The file is at most 64 bytes and contains exactly `127.0.0.1:<decimal port>` with optional trailing LF or CRLF; port 1..65535. No DNS, other addresses, embedded whitespace, extra lines or NUL. Read/format/connect failures are UNAVAILABLE. Connect timeout: 3 seconds. Client sends the 8 bytes `OHECOB1\n`, server replies identically; handshake deadline 3 seconds. Invalid/failed handshake is PROTOCOL, not UNAVAILABLE. One connection = one command. Never automatically retry START. No task IDs or reconnect.

## Framing

Header: u8 type, u32 big-endian payload length; then exactly that many bytes. Maximum payload: 1,048,576 bytes. Integers below are big endian. A string is u32 byte length followed by strict UTF-8 bytes; embedded NUL is forbidden. Arrays start with u32 element count (maximum 4096). Reject unknown types, invalid lengths, trailing payload bytes and out-of-order messages. Stream bytes are arbitrary binary, not UTF-8 text.

| Type | Name | Direction | Payload |
|---|---|---|---|
| 1 | START | C→S | string executable, string cwd, u32 argc + argument strings, u32 envc + (string key, string value) pairs, u8 stdin_enabled (0 or 1) |
| 2 | STARTED | S→C | empty |
| 3 | STDIN | C→S | 1..65536 raw bytes |
| 4 | STDIN_EOF | C→S | empty |
| 5 | STDOUT | S→C | 1..65536 raw bytes |
| 6 | STDERR | S→C | 1..65536 raw bytes |
| 7 | CANCEL | C→S | empty |
| 8 | EXIT | S→C | u32 reason, i32 exit_code, u32 signal |
| 9 | ERROR | S→C | u32 error_code, string message |

Executable must be nonempty. cwd empty means service startup cwd. Names without slash resolve using the effective PATH (broker environment with overrides). Relative executables/relative PATH entries resolve from the requested cwd. Environment keys must be nonempty, contain neither '=' nor NUL; duplicates are invalid. Environment inherits broker environment, overrides only; no deletion operation in v1. stdin_enabled=0 starts with null stdin. Otherwise EOF must be explicitly sent; repeated EOF or data after EOF is a protocol error. An early target stdin closure may discard later input while stdout/stderr continue normally (like a broken pipe, not a launch failure).

STARTED means OS process startup succeeded, not that the command will succeed. No output may precede STARTED. ERROR before STARTED terminates the request. After STARTED, STDOUT/STDERR may interleave, but each stream keeps its own order. EXIT is sent only after output has been drained; no separate output EOF frames. ERROR is terminal, including after STARTED (for example resource/I/O failure); no EXIT follows it. Client may send input/control only after STARTED. CANCEL is idempotent while active. Client EOF/disconnect cancels its task; do not half-close the TCP connection for stdin EOF.

EXIT reasons: 0 normal (exit_code is 0..255, signal 0), 1 signal (exit_code -1, signal >0), 2 cancelled (actual exit_code if normal, otherwise -1 and actual signal). Nonzero command exit is a normal result, not an SDK exception. CANCEL requests SIGTERM for process group, then SIGKILL after a fixed 2-second grace. Service shutdown cancels tasks. Process groups do not contain descendants that deliberately detach. Remaining same-group helpers are cleaned up when a managed command finishes. Bounded output drain prevents detached helpers holding pipes from hanging forever; inability to finish output is an I/O error, never silently successful truncation.

## SDK errors (same numeric values in C and .NET)

0 OK; 1 UNAVAILABLE; 2 PROTOCOL; 3 SPAWN_FAILED; 4 CONNECTION_LOST; 5 INVALID_ARGUMENT; 6 TIMEOUT; 7 IO; 8 LIMIT.

UNAVAILABLE includes missing/unreadable/empty/malformed discovery file and ALL connect failures. Local caller parameter errors use INVALID_ARGUMENT. After sending START, unexpected connection loss is CONNECTION_LOST and outcome may be unknown. Bad protocol bytes use PROTOCOL. Server startup errors use SPAWN_FAILED. A wait timeout/cancelled wait does not cancel the remote command. Preserve optional stage, native error and message diagnostics without changing these classifications. Resource release closes the connection; if the task is still running, this causes server cancellation. These rules apply to managed START; detached startup uses the separate v2 exchange below.

## Managed request limits and semantics

Server caps concurrent connections (32), startup deadline (3 seconds per handshake/start phase), frame sizes and stdin buffering. Slow readers have a bounded socket write deadline (10 seconds); failure closes connection and cancels work. C event consumers must continuously drain events; wait convenience APIs drain/discard unconsumed output rather than deadlock. .NET pumps both streams continuously into bounded buffers, and reports a limit error if consumers fail to drain them; no silent drop or unbounded memory. Default .NET nonredirected output is drained/discarded. Event callbacks should not block.

For managed START, network startup deadlines close the connection and cancel late startup. They cannot forcibly interrupt a blocked operating-system filesystem/exec syscall; if process creation returns after cancellation, the service kills and reaps that child without acknowledging it. Avoid unavailable network mounts for executables/cwd; service shutdown can be delayed by an uninterruptible OS syscall.

Protocol v1 is an intentionally small tool-execution subset, not local Process/waitpid compatibility, a sandbox or a remote host protocol.

## v2: detached startup (0.2.0)

Managed SDK calls continue to use `OHECOB1\n`, unchanged and compatible with 0.1.0. Only the new detached API uses the 8-byte greeting `OHECOB2\n`; the server echoes it. A 0.1.0 server closes/refuses this greeting: SDK returns PROTOCOL without sending START and without any managed-mode fallback. 0.2.0 accepts both greetings. v2 also accepts ordinary START unchanged, but v1 rejects the following new messages.

| Type | Name | Direction | Payload |
|---|---|---|---|
| 10 | START_DETACHED | C→S | complete START payload (stdin_enabled MUST be 0), followed by string stdout_file, string stderr_file |
| 11 | DETACHED_STARTED | S→C | u32 PID, in 1..2147483647 |

All framing/string/count limits and ERROR codes remain unchanged. Max payload includes both log paths. Paths are UTF-8/NUL-free; empty means `/dev/null`. Relative log paths resolve from the effective requested working directory. Nonempty outputs must be regular files (not pipes/devices), opened append/create; same stdout/stderr file is supported. No automatic directory creation. New files request mode 0600, but shared filesystems may not enforce it: sensitive logs belong in accessible private directories. Existing file permissions are not changed. stdin is `/dev/null`.

The reply is either a terminal ERROR or one DETACHED_STARTED and connection closure. There are no STDOUT/STDERR/EXIT frames or Wait/Cancel handles for this API. PID is diagnostic, not a local child/waitpid handle or a promise of readiness/liveness. Once OS process creation succeeds, it is committed: client disconnect, failure to deliver the acknowledgement, and normal broker exit do not cancel the detached process. Failure/timeout after attempting START_DETACHED has an unknown outcome; never automatically retry. Pre-spawn cancellation/timeouts may prevent startup, but a successful late OS spawn must still obey committed detached semantics.

The server uses a new POSIX session, no inherited socket/stdin/output pipes, and reaps direct children asynchronously while alive. It does not wait for or kill detached processes on shutdown. Up to 64 currently tracked direct detached children per service instance; excess startup requests return LIMIT. This is a memory bound, not containment of daemonized grandchildren. Stopping a detached service is its own protocol or the user's terminal responsibility, not a broker PID-kill API. Closing/killing the terminal application or OS force-stop may still remove its descendants and is NOT guaranteed to preserve detached services.

Source APIs: C `oheco_broker_spawn_detached(endpoint_file, options, stdout_file, stderr_file, uint32_t *pid, diagnostic)` (stdin_enabled must be 0); .NET static `BrokerProcess.SpawnDetached[Async](BrokerProcessStartInfo, stdoutFile, stderrFile, ...)` returns diagnostic PID as int and requires all RedirectStandard* flags false. Separate methods preserve existing managed Dispose/cancel semantics and expose no misleading remote Process handle.
