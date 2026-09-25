using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Oheco.Broker;

if (args.Length >= 5 && args[0] == "--detached")
{
    var info = Info(args[2], args[1]);
    foreach (string arg in args.Skip(5)) info.ArgumentList.Add(arg);
    try
    {
        Console.WriteLine(await BrokerProcess.SpawnDetachedAsync(info, args[3], args[4]));
        return 0;
    }
    catch (BrokerException ex)
    {
        Console.Error.WriteLine($"{ex.Code}: {ex.Message}; stage={ex.Stage}; outcomeUnknown={ex.OutcomeUnknown}");
        return 1;
    }
}
if (args.Length is < 1 or > 2 || (args.Length == 2 && args[1] is not ("--protocol-only" or "--managed-only")) || args[0] == "--detached")
{
    Console.Error.WriteLine("Usage: dotnet BrokerSmoke.dll ENDPOINT [--protocol-only|--managed-only]\n       dotnet BrokerSmoke.dll --detached ENDPOINT EXE OUT ERR [ARGS...]");
    return 2;
}
string endpoint = args[0];
string temporaryRoot = Environment.GetEnvironmentVariable("TMPDIR") ?? throw new Exception("TMPDIR must be set.");
string scratch = Path.Combine(temporaryRoot, "broker-dotnet-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(scratch);
try
{
    await Error(BrokerErrorCode.Unavailable, async () =>
    {
        using var p = new BrokerProcess(Info("/usr/bin/sh", Path.Combine(scratch, "missing")));
        await p.StartAsync();
    });
    string invalidEndpoint = Path.Combine(scratch, "endpoint");
    foreach (string invalid in new[] { "", "localhost:42", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:12\n\n", "127.0.0.1:1\0", new string('x', 65) })
    {
        await File.WriteAllTextAsync(invalidEndpoint, invalid);
        await Error(BrokerErrorCode.Unavailable, async () =>
        {
            using var p = new BrokerProcess(Info("/usr/bin/sh", invalidEndpoint));
            await p.StartAsync();
        });
    }
    await Error(BrokerErrorCode.InvalidArgument, async () =>
    {
        using var p = new BrokerProcess(Info("", endpoint));
        await p.StartAsync();
    });
    await Error(BrokerErrorCode.Limit, async () =>
    {
        var info = Info("/usr/bin/sh", endpoint);
        info.ArgumentList.Add(new string('x', 1048576));
        using var p = new BrokerProcess(info);
        await p.StartAsync();
    });
    await Fake(BrokerErrorCode.Protocol, async stream =>
    {
        byte[] magic = new byte[8]; await stream.ReadExactlyAsync(magic);
        await stream.WriteAsync("WRONG!!\n"u8.ToArray());
    });
    await Fake(BrokerErrorCode.ConnectionLost, async stream => { await HandshakeStart(stream); });
    await Fake(BrokerErrorCode.Protocol, async stream =>
    {
        await HandshakeStart(stream);
        await Frame(stream, 11, Number(42)); // detached acknowledgement is invalid in v1
    });
    await Fake(BrokerErrorCode.Protocol, async stream =>
    {
        await HandshakeStart(stream);
        await Frame(stream, 5, new byte[] { 42 }); // output before STARTED
    });
    await Fake(BrokerErrorCode.Protocol, async stream =>
    {
        await HandshakeStart(stream);
        await Frame(stream, 2, []);
        await Frame(stream, 8, Exit(0, -1, 0));
    });
    await Fake(BrokerErrorCode.Protocol, async stream =>
    {
        await HandshakeStart(stream);
        await Frame(stream, 2, []);
        await stream.WriteAsync(new byte[] { 5, 0, 1, 0, 1 }); // oversized output frame
    });
    await Fake(BrokerErrorCode.Protocol, async stream =>
    {
        await HandshakeStart(stream);
        await Frame(stream, 9, new byte[] { 0, 0, 0, 3, 0, 0, 0, 1, 0xff });
    });
    await Fake(BrokerErrorCode.Limit, async stream =>
    {
        await HandshakeStart(stream);
        await Frame(stream, 2, []);
        await Frame(stream, 5, new byte[65536]);
        await Frame(stream, 5, new byte[1]);
    }, redirected: true);
    Console.WriteLine("PASS discovery/API/protocol/connection-loss/buffer-limit tests");
    await DetachedTests(scratch);
    Console.WriteLine("PASS detached v2 encoding/PID/errors/deadlines/no-fallback/no-control tests");
    if (args.Length == 2 && args[1] == "--protocol-only") return 0;

    // Nonzero process exit is a result, not an exception. Arguments preserve spaces.
    var usage = Info("/usr/bin/sh", endpoint);
    usage.ArgumentList.Add("-c");
    usage.ArgumentList.Add("printf '%s|%s|%s' \"$1\" \"$BROKER_SMOKE_VALUE\" \"$PWD\"; printf 'stderr\\n' >&2; exit 7");
    usage.ArgumentList.Add("smoke"); usage.ArgumentList.Add("argument with spaces");
    usage.WorkingDirectory = scratch;
    usage.Environment["BROKER_SMOKE_VALUE"] = "value with spaces";
    usage.RedirectStandardOutput = usage.RedirectStandardError = true;
    using (var p = new BrokerProcess(usage))
    {
        await p.StartAsync();
        Task<string> stdout = p.StandardOutput.ReadToEndAsync();
        Task<string> stderr = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Check(await stdout == $"argument with spaces|value with spaces|{scratch}", "argv/environment/cwd/stdout");
        Check(await stderr == "stderr\n", "stderr");
        Check(p.HasExited && p.ExitCode == 7 && p.ExitReason == BrokerExitReason.Normal && p.ExitSignal == 0, "exit result");
    }
    var echo = Info("/usr/bin/cat", endpoint);
    echo.RedirectStandardInput = echo.RedirectStandardOutput = true;
    using (var p = new BrokerProcess(echo))
    {
        p.Start();
        Task<string> stdout = p.StandardOutput.ReadToEndAsync();
        await p.StandardInput.WriteAsync("stdin EOF without TCP half-close\n");
        await p.CloseStandardInputAsync();
        await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Check(await stdout == "stdin EOF without TCP half-close\n" && p.ExitCode == 0, "stdin EOF");
    }
    var events = Info("/usr/bin/sh", endpoint);
    events.ArgumentList.Add("-c"); events.ArgumentList.Add("printf 'one\\ntwo\\n'; printf 'err\\n' >&2");
    events.RedirectStandardOutput = events.RedirectStandardError = true;
    using (var p = new BrokerProcess(events))
    {
        var lines = new List<string?>(); var errors = new List<string?>();
        p.OutputDataReceived += (_, e) => lines.Add(e.Data);
        p.ErrorDataReceived += (_, e) => errors.Add(e.Data);
        await p.StartAsync(); p.BeginOutputReadLine(); p.BeginErrorReadLine();
        await Error(BrokerErrorCode.InvalidArgument, () => { _ = p.StandardOutput; return Task.CompletedTask; });
        await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Check(lines.SequenceEqual(new string?[] { "one", "two", null }), "stdout events/EOF");
        Check(errors.SequenceEqual(new string?[] { "err", null }), "stderr events/EOF");
    }
    await Error(BrokerErrorCode.SpawnFailed, async () =>
    {
        using var p = new BrokerProcess(Info("/nonexistent/oheco-broker-command", endpoint));
        await p.StartAsync();
    });
    var sleeper = Info("/usr/bin/sleep", endpoint); sleeper.ArgumentList.Add("30");
    using (var p = new BrokerProcess(sleeper))
    {
        await p.StartAsync();
        using var cancelWait = new CancellationTokenSource(TimeSpan.FromMilliseconds(30));
        try { await p.WaitForExitAsync(cancelWait.Token); throw new Exception("Wait did not cancel."); }
        catch (OperationCanceledException) when (cancelWait.IsCancellationRequested) { }
        Check(!p.HasExited && !p.WaitForExit(20), "wait cancellation/timeout does not cancel process");
        await p.KillAsync(); // CANCEL alias: TERM then fixed 2s escalation, not immediate KILL.
        await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8));
        Check(p.ExitReason == BrokerExitReason.Cancelled, "cancel result");
    }
    Console.WriteLine("PASS real broker argv/environment/cwd, streams, EOF, events, spawn error, wait cancellation, CANCEL");
    if (args.Length == 2 && args[1] == "--managed-only") return 0;
    var detached = Info("/usr/bin/sh", endpoint);
    detached.WorkingDirectory = scratch;
    detached.ArgumentList.Add("-c");
    detached.ArgumentList.Add("printf 'stdout\\n'; printf 'stderr\\n' >&2; if IFS= read -r line; then printf 'unexpected stdin\\n'; else printf 'stdin EOF\\n'; fi; exec /usr/bin/sleep 30");
    string detachedLog = Path.Combine(scratch, "detached.log");
    await File.WriteAllTextAsync(detachedLog, "seed\n");
    int detachedPid = await BrokerProcess.SpawnDetachedAsync(detached, "detached.log", "detached.log");
    using (var local = System.Diagnostics.Process.GetProcessById(detachedPid))
    {
        try
        {
            string expectedLog = "seed\nstdout\nstderr\nstdin EOF\n";
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (await File.ReadAllTextAsync(detachedLog) != expectedLog)
                await Task.Delay(20, deadline.Token);
            Check(!local.HasExited, "detached process survives SDK connection close");
            string status = await File.ReadAllTextAsync($"/proc/{detachedPid}/stat");
            Check(status[status.LastIndexOf(')') + 2] != 'Z', "detached process is not a zombie");
            Check(await File.ReadAllTextAsync(detachedLog) == expectedLog, "detached cwd/append/shared log/null stdin");
        }
        finally
        {
            // Only test-owned, same-terminal process cleanup. This is NOT an SDK
            // remote PID-kill/wait API and must not stop the supplied broker.
            if (!local.HasExited) local.Kill();
            await local.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        }
    }
    Console.WriteLine("PASS real detached launch survives SDK close, diagnostic PID alive, append/shared logs, cwd, null stdin");
    return 0;
}
finally { Directory.Delete(scratch, true); }

static BrokerProcessStartInfo Info(string file, string endpoint) => new() { FileName = file, EndpointFile = endpoint };
static void Check(bool condition, string name) { if (!condition) throw new Exception("FAIL " + name); }
static async Task Error(BrokerErrorCode expected, Func<Task> run)
{
    try { await run(); }
    catch (BrokerException ex) when (ex.ErrorCode == expected) { return; }
    throw new Exception("Expected broker error " + expected);
}
static byte[] Exit(uint reason, int code, uint signal)
{
    byte[] bytes = new byte[12];
    BinaryPrimitives.WriteUInt32BigEndian(bytes, reason);
    BinaryPrimitives.WriteInt32BigEndian(bytes.AsSpan(4), code);
    BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(8), signal);
    return bytes;
}
static async Task Frame(NetworkStream stream, byte type, byte[] payload)
{
    byte[] header = new byte[5]; header[0] = type;
    BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(1), (uint)payload.Length);
    await stream.WriteAsync(header); await stream.WriteAsync(payload);
}
static async Task HandshakeStart(NetworkStream stream)
{
    byte[] magic = new byte[8]; await stream.ReadExactlyAsync(magic);
    Check(magic.AsSpan().SequenceEqual("OHECOB1\n"u8), "handshake request");
    await stream.WriteAsync(magic);
    byte[] header = new byte[5]; await stream.ReadExactlyAsync(header);
    Check(header[0] == 1, "START request");
    int count = checked((int)BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1)));
    Check(count <= 1048576, "START length");
    await stream.ReadExactlyAsync(new byte[count]);
}
static async Task DetachedTests(string scratch)
{
    string missing = Path.Combine(scratch, "missing-detached");
    await Error(BrokerErrorCode.Unavailable, () => BrokerProcess.SpawnDetachedAsync(Info("unused", missing)));
    string invalid = Path.Combine(scratch, "bad-detached-endpoint");
    await File.WriteAllTextAsync(invalid, "localhost:42");
    await Error(BrokerErrorCode.Unavailable, () => BrokerProcess.SpawnDetachedAsync(Info("unused", invalid)));
    using (var refused = new TcpListener(IPAddress.Loopback, 0))
    {
        refused.Start();
        await File.WriteAllTextAsync(invalid, "127.0.0.1:" + ((IPEndPoint)refused.LocalEndpoint).Port);
        refused.Stop();
        await Error(BrokerErrorCode.Unavailable, () => BrokerProcess.SpawnDetachedAsync(Info("unused", invalid)));
    }
    await Error(BrokerErrorCode.InvalidArgument, () => BrokerProcess.SpawnDetachedAsync(null!));
    for (int flag = 0; flag < 3; flag++)
    {
        var info = Info("unused", missing);
        info.RedirectStandardInput = flag == 0;
        info.RedirectStandardOutput = flag == 1;
        info.RedirectStandardError = flag == 2;
        await Error(BrokerErrorCode.InvalidArgument, () => BrokerProcess.SpawnDetachedAsync(info));
    }
    foreach (string path in new[] { "bad\0path", "bad\ud800path" })
    {
        await Error(BrokerErrorCode.InvalidArgument, () => BrokerProcess.SpawnDetachedAsync(Info("unused", missing), path));
        await Error(BrokerErrorCode.InvalidArgument, () => BrokerProcess.SpawnDetachedAsync(Info("unused", missing), null, path));
    }
    // Neither path alone exceeds 1 MiB; the complete combined payload does.
    await Error(BrokerErrorCode.Limit, () => BrokerProcess.SpawnDetachedAsync(Info("unused", missing),
        new string('x', 524288), new string('y', 524288)));
    foreach (uint pid in new uint[] { 1, int.MaxValue })
        await FakeDetached(null, s => Frame(s, 11, Number(pid)), expectedPid: (int)pid, sync: pid == 1);
    await FakeDetached(null, s => Frame(s, 11, Number(42)), expectedPid: 42, nullLogs: true);
    foreach (uint pid in new uint[] { 0, 0x80000000, uint.MaxValue })
        await FakeDetached(BrokerErrorCode.Protocol, s => Frame(s, 11, Number(pid)));
    foreach (uint length in new uint[] { 0, 3, 5, 1048577, uint.MaxValue })
        await FakeDetached(BrokerErrorCode.Protocol, s => Header(s, 11, length));
    foreach (byte type in new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 10, 255 })
        await FakeDetached(BrokerErrorCode.Protocol, s => Frame(s, type, []));
    // Empty response, partial header and partial PID are transport loss, not bad bytes.
    await FakeDetached(BrokerErrorCode.ConnectionLost, _ => Task.CompletedTask, outcomeUnknown: true);
    await FakeDetached(BrokerErrorCode.ConnectionLost, s => s.WriteAsync(new byte[] { 11, 0 }).AsTask(), outcomeUnknown: true);
    await FakeDetached(BrokerErrorCode.ConnectionLost, async s =>
    {
        await Header(s, 11, 4); await s.WriteAsync(new byte[] { 0, 0 });
    }, outcomeUnknown: true);
    foreach (BrokerErrorCode code in Enum.GetValues<BrokerErrorCode>().Where(c => c != BrokerErrorCode.Ok))
        await FakeDetached(code, s => Frame(s, 9, [.. Number((uint)code), .. Number(0)]),
            outcomeUnknown: code is BrokerErrorCode.ConnectionLost or BrokerErrorCode.Timeout);
    foreach (byte[] payload in new byte[][]
    {
        [.. Number(0), .. Number(0)], [.. Number(9), .. Number(0)],
        [.. Number(3), .. Number(2), 65], [.. Number(3), .. Number(0), 65],
        [.. Number(3), .. Number(1), 0], [.. Number(3), .. Number(1), 255]
    })
        await FakeDetached(BrokerErrorCode.Protocol, s => Frame(s, 9, payload));
    await FakeDetached(BrokerErrorCode.Protocol, s => Header(s, 9, 7));
    // Old v1 server closes at v2 greeting, or echoes v1: never send START or reconnect.
    await FakeDetached(BrokerErrorCode.Protocol, _ => Task.CompletedTask, handshake: false);
    await FakeDetached(BrokerErrorCode.Protocol, s => s.WriteAsync("OHECOB1\n"u8.ToArray()).AsTask(), handshake: false);
    // Actual three-second handshake/start deadlines, not just caller cancellation.
    await FakeDetached(BrokerErrorCode.Protocol, s => ExpectClosed(s), handshake: false);
    await FakeDetached(BrokerErrorCode.Timeout, s => ExpectClosed(s), outcomeUnknown: true);
    await FakeDetached(BrokerErrorCode.Timeout, s => ExpectClosed(s), outcomeUnknown: true, cancelStart: true);
}
static byte[] Number(uint value)
{
    byte[] bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes;
}
static Task Header(NetworkStream stream, byte type, uint length) => stream.WriteAsync((byte[])[type, .. Number(length)]).AsTask();
static async Task ExpectClosed(NetworkStream stream)
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(6));
    Check(await stream.ReadAsync(new byte[1], deadline.Token) == 0, "no detached START/control after rejection/terminal result");
}
static async Task FakeDetached(BrokerErrorCode? expected, Func<NetworkStream, Task> server,
    bool handshake = true, bool outcomeUnknown = false, int expectedPid = 0, bool sync = false,
    bool nullLogs = false, bool cancelStart = false)
{
    string path = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR")!, "broker-detached-" + Guid.NewGuid().ToString("N"));
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    using var cancellation = new CancellationTokenSource();
    listener.Start();
    await File.WriteAllTextAsync(path, "127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port);
    var info = Info("unused", path);
    info.WorkingDirectory = "cwd with spaces";
    info.ArgumentList.Add("argument λ"); info.Environment["KEY"] = "value with spaces";
    string? stdout = nullLogs ? null : "out λ.log", stderr = nullLogs ? "" : "err.log";
    Task serving = Task.Run(async () =>
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        using var client = await listener.AcceptTcpClientAsync(deadline.Token);
        NetworkStream stream = client.GetStream();
        byte[] magic = new byte[8]; await stream.ReadExactlyAsync(magic, deadline.Token);
        Check(magic.AsSpan().SequenceEqual("OHECOB2\n"u8), "detached v2 greeting");
        if (handshake)
        {
            await stream.WriteAsync(magic);
            byte[] header = new byte[5]; await stream.ReadExactlyAsync(header, deadline.Token);
            Check(header[0] == 10, "START_DETACHED type");
            int count = checked((int)BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1)));
            Check(count <= 1048576, "START_DETACHED limit");
            byte[] payload = new byte[count]; await stream.ReadExactlyAsync(payload, deadline.Token);
            using var expectedPayload = new MemoryStream();
            void Text(string text)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(text);
                expectedPayload.Write(Number((uint)bytes.Length)); expectedPayload.Write(bytes);
            }
            Text(info.FileName); Text(info.WorkingDirectory);
            expectedPayload.Write(Number(1)); Text(info.ArgumentList[0]);
            expectedPayload.Write(Number(1)); Text("KEY"); Text(info.Environment["KEY"]);
            expectedPayload.WriteByte(0); Text(stdout ?? ""); Text(stderr ?? "");
            Check(payload.AsSpan().SequenceEqual(expectedPayload.ToArray()), "complete START + stdin0 + two UTF-8 paths");
            if (cancelStart) cancellation.Cancel();
        }
        await server(stream);
        client.Client.Shutdown(SocketShutdown.Send);
        await ExpectClosed(stream);
    });
    try
    {
        try
        {
            int pid = sync ? BrokerProcess.SpawnDetached(info, stdout, stderr, cancellation.Token)
                : await BrokerProcess.SpawnDetachedAsync(info, stdout, stderr, cancellation.Token);
            Check(expected == null && pid == expectedPid, "detached diagnostic PID");
        }
        catch (BrokerException ex) when (ex.Code == expected)
        {
            Check(ex.OutcomeUnknown == outcomeUnknown, "detached OutcomeUnknown " + ex.Code);
        }
        await serving.WaitAsync(TimeSpan.FromSeconds(10));
        Check(!listener.Pending(), "no detached fallback/retry connection");
    }
    finally { listener.Stop(); File.Delete(path); }
}

static async Task Fake(BrokerErrorCode expected, Func<NetworkStream, Task> server, bool redirected = false)
{
    string path = Path.Combine(Environment.GetEnvironmentVariable("TMPDIR")!, "broker-fake-" + Guid.NewGuid().ToString("N"));
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    await File.WriteAllTextAsync(path, "127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port + "\n");
    Task serving = Task.Run(async () =>
    {
        using var client = await listener.AcceptTcpClientAsync();
        await server(client.GetStream());
    });
    try
    {
        await Error(expected, async () =>
        {
            var info = Info("unused", path); info.RedirectStandardOutput = redirected; info.OutputBufferBytes = 65536;
            using var p = new BrokerProcess(info);
            await p.StartAsync(); await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
        });
        await serving.WaitAsync(TimeSpan.FromSeconds(5));
    }
    finally { listener.Stop(); File.Delete(path); }
}
