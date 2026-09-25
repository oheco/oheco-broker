using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Oheco.Broker;

if (args.Length is < 1 or > 2 || (args.Length == 2 && args[1] != "--protocol-only"))
{
    Console.Error.WriteLine("Usage: dotnet BrokerSmoke.dll /explicit/broker/endpoint [--protocol-only]");
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
    if (args.Length == 2) return 0;

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
