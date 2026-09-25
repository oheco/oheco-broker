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
`OHECO_BROKER_C_SMOKE=ON` to also build `oheco-broker-c-smoke`. CMake 3.16+.

## API and ownership

1. Zero-initialize `oheco_broker_options`, set `executable`, `args`/`argc` (arguments
   **excluding argv[0]**), optional cwd, environment overrides, `stdin_enabled`.
   String pointers are borrowed only during `oheco_broker_start`; strings must be
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
   server-side cancellation; no detached jobs. NULL release is harmless.

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
```

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
All fixture sockets/files are transient. It uses the smoke's internal `resume`
mode for partial-frame timeout tests.

Validated natively on HarmonyOS aarch64 using clang 15.0.4: direct source
`-std=c11 -Wall -Wextra -Werror -pthread` compilation/link, optional CMake
OBJECT + smoke build, signed fixture execution, and the full external Go-broker
suite. CMake emitted its generic unknown-HarmonyOS-platform warning but built
and linked successfully. No binaries are checked into the source SDK.
