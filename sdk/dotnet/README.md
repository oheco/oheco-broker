# Oheco.Broker — pure C# SDK (.NET 10)

`BrokerProcess.cs` implements [protocol v1](../../protocol/PROTOCOL.md) directly with managed sockets. No C SDK, P/Invoke, native helper, JSON, NuGet package, DNS, or automatic retry is used. The local broker itself must already be running. This is trusted-local-development tooling, not an authenticated or sandboxed execution service.

## Reference or include source

```xml
<ItemGroup>
  <ProjectReference Include="/path/to/oheco-broker/sdk/dotnet/Oheco.Broker.csproj" />
</ItemGroup>
```

Alternatively, compile the one source file into a `net10.0` application (do **not** also reference the project):

```xml
<ItemGroup>
  <Compile Include="/path/to/oheco-broker/sdk/dotnet/BrokerProcess.cs"
           Link="Oheco.Broker/BrokerProcess.cs" />
</ItemGroup>
```

The file has explicit usings and nullable settings; there are no additional source or generated-file requirements.

## Process usage

```csharp
using Oheco.Broker;

var info = new BrokerProcessStartInfo {
    EndpointFile = "/explicit/path/to/endpoint", // omitted: $HOME/.oheco/broker/endpoint
    FileName = "/usr/bin/sh",
    WorkingDirectory = "/desired/directory",
    RedirectStandardOutput = true,
    RedirectStandardError = true
};
info.ArgumentList.Add("-c");
info.ArgumentList.Add("printf '%s\\n' \"$GREETING\"; printf 'diagnostic\\n' >&2");
info.Environment["GREETING"] = "hello with spaces";
using var process = new BrokerProcess(info);
await process.StartAsync();
// Read both concurrently. ReadToEndAsync is appropriate only for known-small output;
// its caller-owned strings are not bounded by the SDK. For large output, copy each
// reader's BaseStream to an appropriate sink or read it incrementally.
Task<string> stdout = process.StandardOutput.ReadToEndAsync();
Task<string> stderr = process.StandardError.ReadToEndAsync();
await process.WaitForExitAsync();
Console.WriteLine(await stdout);
Console.Error.WriteLine(await stderr);
Console.WriteLine($"{process.ExitReason}: code={process.ExitCode}, signal={process.ExitSignal}");
```

- `Start()` returns `true` after STARTED, or throws. `StartAsync(CancellationToken)` is its asynchronous counterpart. One start attempt per instance; no reuse or reconnect. Do not mutate `StartInfo` during/after start.
- `FileName` is an executable, **not** a shell command line; each `ArgumentList` element is transmitted intact. Use an explicit shell only when desired. Empty cwd means broker startup cwd. Environment inherits from the **broker**, with overrides only (no deletion).
- Redirect flags default to false. Nonredirected stdout/stderr are continuously drained and discarded, not inherited from the SDK caller. Nonredirected stdin is null. Text streams use UTF-8 without an emitted BOM; output text decoding replaces invalid UTF-8. For arbitrary bytes use the stream's `BaseStream`, without mixing binary and text reads/writes.
- `StandardInput` is a `StreamWriter`, with `AutoFlush=true`; stdout/stderr are `StreamReader`s. For redirected stdin, dispose the writer or call `CloseStandardInput[Async]()` to flush and send **STDIN_EOF**, never TCP half-close. EOF is explicit: a program waiting for stdin will keep running until you send it. Early target stdin closure may discard later bytes according to the protocol.
- `BeginOutputReadLine()` / `BeginErrorReadLine()` activate `OutputDataReceived` / `ErrorDataReceived`. Attach handlers before beginning. Each event contains `Data`, with `null` at EOF; final unterminated lines are emitted. CR, LF, and CRLF are recognized. Events preserve order within each stream but the two streams run independently. A callback must not block or synchronously wait for process completion.
- Reader access and events on the **same** stream are mutually exclusive, including reader access before `Begin*`. No cancel/restart event reader API exists. Use one consumer per stream and one stdin writer; concurrent writes are not a supported `StreamWriter` use.
- The independent receive pump never waits for a stream reader or callback. Each redirected stream has a fixed ring buffer (`OutputBufferBytes`, default 1 MiB, range 64 KiB–16 MiB). A full ring fails with `Limit` and closes the connection, cancelling active work; bytes are **never silently dropped**. Event line accumulation is separately bounded (`MaxEventLineCharacters`, default 65536, range 1–1048576). Callback exceptions become `Io`. Unread data already buffered remains readable before its terminal error. Caller-created strings, collections, sinks and event handlers are the caller's memory responsibility.
- Drain **both** redirected streams while waiting. `WaitForExit[Async]` does not discard their buffered output and cannot make an unconsumed large output succeed. It waits for EXIT and for any started event readers to finish. An indefinitely blocked callback can indefinitely delay this wait, but does not block the receive pump; cancellable waits remain cancellable.
- `WaitForExitAsync(token)` cancellation stops only that wait; it does **not** cancel remote execution or the pumps. `WaitForExit(milliseconds)` similarly returns `false` without cancelling; `-1` means infinite. Call another wait later.
- `Cancel[Async]()` requests protocol CANCEL. `Kill[Async]()` is only an alias: both request process-group SIGTERM followed by SIGKILL after the broker's fixed **two-second** grace. There is no immediate-kill, arbitrary-signal, configurable grace, or detached-job API. Repeated cancellation is harmless.
- `HasExited` means an actual validated EXIT was received, not merely a lost connection. `ExitCode`, `ExitSignal` (`uint`) and `ExitReason` are available only then. Nonzero command exit is a normal result. No PID, shell-execute, window, encoding-selection, credential, process-tree containment or full `System.Diagnostics.Process` compatibility is claimed.
- **Dispose closes the connection and therefore asks the server to cancel any still-active command.** It does not detach or wait for cancellation. It does not flush pending stdin. For a known result, cancel if needed, drain, wait, then dispose. Detached descendants are outside process-group guarantees.

## Failures and deadlines

`BrokerException.Code` (also exposed as `ErrorCode`) values match the shared contract exactly: `Ok=0`, `Unavailable=1`, `Protocol=2`, `SpawnFailed=3`, `ConnectionLost=4`, `InvalidArgument=5`, `Timeout=6`, `Io=7`, `Limit=8`. `Stage`, `NativeError` (when available), `Message`, and `InnerException` provide diagnostics.

All endpoint read/parse and connect failures are `Unavailable`. The endpoint format is exactly the contract, including its 64-byte bound. Default discovery honors the `HOME` environment variable before falling back to the runtime user-profile path. A metadata precheck rejects directories and zero-length special files (including ordinary FIFOs) before opening. As a pure managed client, it cannot prevent a malicious concurrent replacement of the endpoint path with a special file; discovery must remain in a trusted directory. Connect and handshake each have a three-second deadline. A bad/failed handshake is `Protocol`. Oversized START payloads are `Limit`. START has a three-second deadline; expiration produces `Timeout` with `OutcomeUnknown=true`, closes the connection and may leave the launch/result uncertain. Caller cancellation during START also closes the connection; cancellation during connect/handshake keeps those phases' required error classification. Never retry START automatically.

After attempting START, transport loss is `ConnectionLost` (`OutcomeUnknown=true`); do not infer that the command did not run. Corrupt types, lengths, ordering, UTF-8 error messages, error codes and EXIT combinations are `Protocol`, not transport loss. Server ERROR values are preserved. Outbound input/control writes have a ten-second deadline; failure closes the connection and is `ConnectionLost`. There is no runtime-duration limit: the caller controls wait cancellation and explicit CANCEL.

## Offline native validation

The console project uses `ProjectReference` by default and no test framework/packages. The script also compiles it with `-p:UseBrokerSource=true`, validating the standalone include-source option. From the repository root, with the service already running:

```sh
sh examples/dotnet/test.sh /explicit/path/to/endpoint
```

The script restores **only from an empty temporary local feed**, using installed SDK reference packs. It sets MSBuild `--artifacts-path` from the parent script so both referenced projects' obj/bin are under a private `$TMPDIR` directory, not the repository. It also isolates CLI/package caches and suppresses first-run certificate generation. Temporary files are cleaned on exit; no global NuGet configuration is created or modified.

For SDK-only malformed-wire/error tests without a running broker, still pass an explicit endpoint argument and add `--protocol-only`. The fake brokers use ephemeral loopback ports and temporary endpoint files. The full smoke covers argv/env/cwd, nonzero exit, stdin EOF, concurrent stdout/stderr, event EOF, spawn failure, cancellation of waits, and CANCEL. Test commands assume `/usr/bin/sh`, `/usr/bin/cat`, and `/usr/bin/sleep` exist on the broker host.
