# Embedded C SDK

Compile `oheco_broker.c` directly into your application, including
`oheco_broker.h`. Requires C11, POSIX sockets/poll, monotonic clock and pthreads;
no third-party dependency, JSON, TLS, background pump, installed `.a` or `.so`.
This is the trusted-local-development protocol in `../../protocol/PROTOCOL.md`,
not an authenticated service or a security boundary.

```sh
clang -std=c11 -Wall -Wextra -Werror -pthread -Isdk/c \
  sdk/c/oheco_broker.c examples/c/smoke.c -o "$TMPDIR/broker-smoke"
```

Alternatively, `add_subdirectory(path/to/sdk/c)` and
`target_link_libraries(your_app PRIVATE oheco_broker_c)` use the optional CMake
OBJECT target (no separately installed SDK library). Set
`OHECO_BROKER_C_SMOKE=ON` to also build `oheco-broker-c-smoke` **in the full
source checkout only**. CMake 3.16+.

The installed 0.2.0 package is slim: it includes `sdk/c/`, `sdk/dotnet/`, the
protocol contract and licenses, but not Go source, scripts, examples or tests.
Embed the two C files directly or use the CMake OBJECT target normally from an
installed SDK. The optional smoke target stays OFF by default and reports an
explicit full-checkout requirement if enabled without examples. Build/smoke/test
commands in this document are repository-root commands; obtain the full checkout
at the installed `BUILDINFO.txt` source commit to use them.

## API and ownership

1. Zero-initialize `oheco_broker_options`, set `executable`, `args`/`argc` (arguments
   **excluding argv[0]**), optional cwd, environment overrides, `stdin_enabled`.
   String pointers are borrowed only during the startup call; strings must be
   NUL-terminated strict UTF-8. Invalid Unicode, duplicate environment keys,
   empty executable/keys, `=` in keys and invalid counts are rejected locally.
   Strings cannot represent embedded NUL. Empty cwd uses broker startup cwd.
2. `oheco_broker_start(endpoint_file, &options, &process, &diagnostic)` reads the explicit
   discovery path; NULL selects `$HOME/.oheco/broker/endpoint`. It connects only
   to numeric IPv4 loopback and returns only after STARTED. It never retries
   START. On failure the output process is NULL and transport is closed.
3. If enabled, use `oheco_broker_write_stdin` and `oheco_broker_close_stdin` (protocol EOF, **not**
   TCP half-close). Empty writes are no-ops while stdin remains open. Repeated
   EOF/data after EOF is INVALID_ARGUMENT. Disabled stdin is already closed.
   The broker may discard input if the child closes stdin early.
4. Repeatedly call `oheco_broker_read_event`, consuming arbitrary binary STDOUT/STDERR
   bytes and finally EXIT. Event data is borrowed until the next read, wait or
   release on that process. An EXIT result is cached and repeatable. Nonzero
   exit is an ordinary successful SDK result; inspect `exit_code`/`reason`.
5. `oheco_broker_wait` consumes and discards unread stream events until EXIT. It does not
   buffer output and cannot deadlock just because output exceeds a pipe buffer.
6. `oheco_broker_cancel` requests cancellation without waiting for EXIT. Read/wait for
   final completion. The server applies its TERM/KILL grace period. Repeated
   cancel is idempotent while active; after locally observed EXIT it is a no-op.
7. `oheco_broker_release` closes/frees the object. Closing an active connection causes
   server-side cancellation for managed jobs. NULL release is harmless.

`oheco_broker_diagnostic` is optional caller-owned per-call storage. Numeric `oheco_broker_error`
values exactly match the protocol (OK=0 through LIMIT=8). All discovery and
connect failures, including timeouts/refused ports, are UNAVAILABLE. Invalid or
failed/timed-out handshake is PROTOCOL. After START, transport loss is
CONNECTION_LOST and the remote outcome may be unknown. Server ERROR codes are
preserved. Public error constants are `OHECO_BROKER_OK` and
`OHECO_BROKER_ERR_UNAVAILABLE`, `OHECO_BROKER_ERR_PROTOCOL`,
`OHECO_BROKER_ERR_SPAWN_FAILED`, `OHECO_BROKER_ERR_CONNECTION_LOST`,
`OHECO_BROKER_ERR_INVALID_ARGUMENT`, `OHECO_BROKER_ERR_TIMEOUT`,
`OHECO_BROKER_ERR_IO`, `OHECO_BROKER_ERR_LIMIT`, in numeric order 0..8.
The header also retains concise `ob_*`/`OB_*` aliases.
Malformed frames/UTF-8/EXIT metadata are PROTOCOL. Allocation failure
is IO and oversized encoded START is LIMIT. Diagnostic native codes are errno
or pthread error values when available; message text is not a stable API.

## Detached startup (0.2.0)

```c
uint32_t pid = 0;
oheco_broker_options options = {0};
options.executable = "/path/to/service";
/* options.stdin_enabled must remain 0. */
oheco_broker_error error = oheco_broker_spawn_detached(
    endpoint_file, &options, "service.out", "service.err", &pid, &diagnostic);
```

This separate source API (`ob_spawn_detached` is the short spelling) requires a
non-NULL PID output pointer; it is set to zero on failure. It returns only after
one valid DETACHED_STARTED ACK, with a diagnostic PID in 1..2147483647, then
closes the transport immediately. It returns **no process handle**: no wait,
output stream, cancel or release operation is available. A PID is not a local
child/waitpid handle, a readiness check, or a guarantee the process is still alive.
All options and paths are borrowed for the call and use the same strict UTF-8,
environment/count validation and 1 MiB total payload limit as managed startup.

`stdin_enabled` must be zero (otherwise INVALID_ARGUMENT); remote stdin is the
null device. NULL/empty stdout/stderr paths select the null sink. Nonempty paths
are sent unchanged to the server, which resolves relative paths against the
effective requested cwd, **not the client's cwd**. The server opens regular
files append/create, allows a shared stdout/stderr file, and does not create
parent directories. New files request 0600; existing modes are unchanged and
shared filesystems may not enforce permissions. Put sensitive logs in private
paths accessible to the broker.

Managed `oheco_broker_start` still uses wire v1 unchanged. Only detached startup
uses `OHECOB2\n` and type 10 START_DETACHED; it accepts only type 11 with exactly
a four-byte valid PID or terminal ERROR. Old v1 servers reject the greeting as
PROTOCOL **before any START is sent**. There is no version downgrade, managed
fallback, reconnect or automatic retry. Discovery/connect failures remain exactly
UNAVAILABLE, failed handshakes PROTOCOL, and valid server ERROR codes are preserved.
The connect, greeting, and START send/ACK phases each have a 3-second deadline.
Once START is attempted, connection loss or timeout means **unknown outcome**:
do not retry, since a service might already be running. A timeout closes the
transport but does not promise cancellation of detached startup.

The backend launches detached processes in a new POSIX session, without broker
socket or stream-pipe inheritance. Once OS process creation succeeds, the child
is committed: disconnect, ACK delivery failure and normal broker shutdown do
not kill it. While alive, the broker asynchronously reaps direct children; it
neither waits for nor kills detached services at shutdown. Its limit of 64 tracked
direct detached children per instance is a memory bound (excess returns LIMIT),
not containment of daemonized grandchildren. Terminal application termination
or OS force-stop can still remove descendants; survival is not guaranteed.
Stopping a detached service is the caller's responsibility using that service's
own shutdown protocol or terminal controls, not a broker PID-kill API.

## Threads, deadlines and backpressure

- For each process allow **one event reader OR waiter**, one stdin producer,
  and one cancellation caller concurrently. Reader and writer can operate in
  different threads; cancel may run concurrently with both. Different process
  objects are independent. No SDK function is async-signal-safe. Do not invoke
  release concurrently with any call. The caller owns thread joins and objects.
- The writer mutex protects complete frames, so CANCEL never splits a STDIN
  frame. A cancel request atomically prevents further stdin frames; a frame
  already in progress gets only the remainder of that write's finite 3-second
  budget. A stopped multi-frame write returns IO (partial input possible).
  Cancellation then acquires the writer and has at most another 3 seconds to
  send its frame. This bounds the protocol I/O rather than waiting indefinitely
  behind a blocked child. These are monotonic I/O deadlines, not hard real-time
  scheduling guarantees.
- Connect, handshake, and START send/response each have a separate total
  **3-second** deadline. START timeout is TIMEOUT and closes the connection
  because no process handle can be safely returned. Do not automatically retry:
  a command may have started. Any failed stdin/control frame closes the
  connection to avoid resuming corrupted framing. Write timeout is TIMEOUT,
  unlike a read/wait timeout it is terminal and disconnect cancels the task.
- `oheco_broker_read_event`/`oheco_broker_wait` timeout: -1 waits indefinitely, 0 polls, positive
  values give the total call budget in milliseconds. TIMEOUT does **not**
  cancel the command. Partial frame headers/payloads survive across calls.
  An immediate read may return an already-buffered complete event at timeout 0.
  Wait checks its budget between discarded events, not once per new event.
- Continuously consume output, using a reader thread while supplying potentially
  large stdin. Writing all stdin before reading can hit bounded backpressure.
  No unbounded SDK output queue exists: one validated incoming frame (at most
  1 MiB for ERROR; 64 KiB for stream data) plus the bounded START allocation.
  The service can disconnect clients that fail to drain within its deadline.
- Sockets are nonblocking and close-on-exec. Sends suppress SIGPIPE with
  `MSG_NOSIGNAL` where available; the POSIX fallback masks/consumes only newly
  generated SIGPIPE in the sending thread, leaving global dispositions alone.
  The SDK never installs a process-wide signal handler.

## External-service smoke

The smoke executable does not start or stop a broker. On HarmonyOS, sign a
native executable before running it, e.g.
`binary-sign-tool sign -selfSign 1 -inFile "$TMPDIR/broker-smoke" -outFile "$TMPDIR/broker-smoke.signed"`.
Use an isolated temporary build directory and remove it after testing.

```sh
broker-smoke discovery /a/missing/or/malformed/endpoint
broker-smoke suite /path/to/endpoint /usr/bin/zsh
broker-smoke run /path/to/endpoint /usr/bin/zsh -c 'printf hello; exit 7'
broker-smoke run - /usr/bin/zsh -c 'printf default-discovery'
broker-smoke detached /path/to/endpoint /usr/bin/zsh service.out service.err -c 'printf hello; printf error >&2'
broker-smoke detached /path/to/endpoint /path/to/service '' '' --service-argument
```

`detached ENDPOINT EXEC OUTFILE ERRFILE [ARG...]` prints only the decimal PID
and exits after ACK. `-` as endpoint selects default discovery; `''` as a log
path selects the null sink. The smoke never kills detached processes; the parent
integration test owns their cleanup. To test lifetime, launch a long-running
service with isolated absolute log paths, retain its PID, verify it after the
CLI exits and after normal broker shutdown, then stop it explicitly in test
cleanup. Use a unique service identity and guard against PID reuse.

`run` forwards stdout/stderr and returns the ordinary child exit code (128 for
signal/cancelled). `suite` requires a shell supporting ordinary sh syntax and
`TMPDIR` visible on the same filesystem as the service. It checks invalid
UTF-8/discovery, stdout/stderr, nonzero exit, stdin/EOF, Unicode args/env/cwd,
262144 output bytes byte-for-byte, wait draining >pipe stderr, noncancelling
wait timeout, concurrent cancel/reader, and bounded cancel during blocked stdin.
It creates and removes its Unicode cwd under TMPDIR. Supply the service's
usable shell explicitly; no assumption about `/bin/sh` on HarmonyOS. The
blocked-input check also accepts the service's documented bounded-input LIMIT
or disconnect rather than requiring every oversized write to be accepted.

For isolated adversarial transport checks (no broker required):

```sh
python3 tests/c/protocol_test.py /path/to/signed/broker-smoke
```

This Python standard-library-only fixture runner checks malformed discovery,
refused connect, fragmented binary events, resumable partial header/payload
read timeouts, protocol type/order/size/UTF-8/EXIT rejection, terminal server
errors, connection loss and actual 3-second handshake/START response deadlines.
Detached fixtures additionally check exact v2 request encoding, Unicode/empty
log paths and args, fragmented greetings/ACKs, PID bounds, malformed/out-of-order
ACK/ERROR, disconnect and partial-ACK deadlines. They reject any managed fallback
or retry connection, require client closure after ACK without waiting for server
EOF, and verify old v1 greeting rejection sends no START.
All fixture sockets/files are transient. It uses the smoke's internal `resume`
mode for partial-frame timeout tests.

`tests/c/options_test.c` checks detached local option/path validation (including
NULL log paths, forbidden stdin, UTF-8 and combined payload bounds) without a
broker. Compile/link with `sdk/c/oheco_broker.c`, the same flags as smoke, then
sign/run on HarmonyOS. Use a private temporary directory and trap cleanup for
both test executables; no new runtime dependencies are needed.

Validated natively on HarmonyOS aarch64 using clang 15.0.4: direct source
`-std=c11 -Wall -Wextra -Werror -pthread` compilation/link, optional CMake
OBJECT + smoke build, signed fixture execution, and the full external Go-broker
suite. CMake emitted its generic unknown-HarmonyOS-platform warning but built
and linked successfully. No binaries are checked into the source SDK.
