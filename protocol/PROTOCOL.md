# oheco-broker protocol v1

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

UNAVAILABLE includes missing/unreadable/empty/malformed discovery file and ALL connect failures. Local caller parameter errors use INVALID_ARGUMENT. After sending START, unexpected connection loss is CONNECTION_LOST and outcome may be unknown. Bad protocol bytes use PROTOCOL. Server startup errors use SPAWN_FAILED. A wait timeout/cancelled wait does not cancel the remote command. Preserve optional stage, native error and message diagnostics without changing these classifications. Resource release closes the connection; if the task is still running, this causes server cancellation. This minimal SDK deliberately does not support detached jobs.

## Limits and semantics

Server caps concurrent connections (32), startup deadline (3 seconds per handshake/start phase), frame sizes and stdin buffering. Slow readers have a bounded socket write deadline (10 seconds); failure closes connection and cancels work. C event consumers must continuously drain events; wait convenience APIs drain/discard unconsumed output rather than deadlock. .NET pumps both streams continuously into bounded buffers, and reports a limit error if consumers fail to drain them; no silent drop or unbounded memory. Default .NET nonredirected output is drained/discarded. Event callbacks should not block.

Network startup deadlines close the connection and cancel late startup. They cannot forcibly interrupt a blocked operating-system filesystem/exec syscall; if process creation returns after cancellation, the service kills and reaps that child without acknowledging it. Avoid unavailable network mounts for executables/cwd; service shutdown can be delayed by an uninterruptible OS syscall.

Protocol v1 is an intentionally small tool-execution subset, not local Process/waitpid compatibility, a sandbox or a remote host protocol.
