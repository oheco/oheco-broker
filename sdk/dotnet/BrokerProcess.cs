// Pure managed v1 command / v2 detached client. This file can also be included as source.
#nullable enable
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Oheco.Broker;

public enum BrokerErrorCode
{
    Ok = 0, Unavailable = 1, Protocol = 2, SpawnFailed = 3,
    ConnectionLost = 4, InvalidArgument = 5, Timeout = 6, Io = 7, Limit = 8
}

public sealed class BrokerException : Exception
{
    public BrokerErrorCode ErrorCode { get; }
    public BrokerErrorCode Code => ErrorCode;
    public string? Stage { get; }
    public int? NativeError { get; }
    public bool OutcomeUnknown => ErrorCode == BrokerErrorCode.ConnectionLost ||
        (ErrorCode == BrokerErrorCode.Timeout && Stage == "start");
    public BrokerException(BrokerErrorCode code, string message, string? stage = null,
        Exception? inner = null, int? nativeError = null) : base(message, inner)
    { ErrorCode = code; Stage = stage; NativeError = nativeError; }
}

public enum BrokerExitReason { Normal = 0, Signal = 1, Cancelled = 2 }

public sealed class BrokerProcessStartInfo
{
    public string FileName { get; set; } = "";
    public IList<string> ArgumentList { get; } = new List<string>();
    public string WorkingDirectory { get; set; } = "";
    // Inherits broker environment. Overrides only; removal is not supported.
    public IDictionary<string, string> Environment { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
    public string? EndpointFile { get; set; }
    public bool RedirectStandardInput { get; set; }
    public bool RedirectStandardOutput { get; set; }
    public bool RedirectStandardError { get; set; }
    // A slow consumer fails the task with LIMIT rather than dropping bytes.
    public int OutputBufferBytes { get; set; } = 1024 * 1024;
    public int MaxEventLineCharacters { get; set; } = 65536;
}

public sealed class BrokerDataReceivedEventArgs : EventArgs
{
    public string? Data { get; }
    internal BrokerDataReceivedEventArgs(string? data) => Data = data;
}

/// <summary>
/// One command per instance; not a System.Diagnostics.Process replacement.
/// Dispose closes TCP: the broker cancels a still-active command (TERM, then KILL
/// after two seconds). Wait cancellation only stops waiting, not the command.
/// </summary>
public sealed class BrokerProcess : IDisposable
{
    private const int MaxFrame = 1048576;
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("OHECOB1\n");
    private static readonly byte[] DetachedMagic = Encoding.ASCII.GetBytes("OHECOB2\n");
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly object sync = new();
    private readonly SemaphoreSlim sendLock = new(1, 1);
    private readonly CancellationTokenSource lifetime = new();
    private readonly TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TcpClient? client;
    private NetworkStream? wire;
    private BoundedReadStream? outputBuffer, errorBuffer;
    private StreamReader? output, error;
    private StreamWriter? input;
    private Task? outputEvents, errorEvents;
    private int outputMode, errorMode;
    private int eventLineLimit;
    private bool attempted, started, terminal, disposed, inputEof, inputEnabled, exited;
    private int exitCode;
    private uint exitSignal;
    private BrokerExitReason exitReason;

    public BrokerProcessStartInfo StartInfo { get; }
    public event EventHandler<BrokerDataReceivedEventArgs>? OutputDataReceived;
    public event EventHandler<BrokerDataReceivedEventArgs>? ErrorDataReceived;
    public BrokerProcess() : this(new BrokerProcessStartInfo()) { }
    public BrokerProcess(BrokerProcessStartInfo startInfo) => StartInfo = startInfo ?? throw Invalid("StartInfo is null.");

    public StreamWriter StandardInput
    {
        get { lock (sync) { RequireStarted(); return input ?? throw Invalid("Standard input is not redirected."); } }
    }
    public StreamReader StandardOutput => GetReader(false);
    public StreamReader StandardError => GetReader(true);
    private StreamReader GetReader(bool stderr)
    {
        lock (sync)
        {
            RequireStarted();
            StreamReader reader = (stderr ? error : output) ?? throw Invalid("Stream is not redirected.");
            if ((stderr ? errorMode : outputMode) == 2) throw Invalid("Cannot combine events and reader access on one stream.");
            if (stderr) errorMode = 1; else outputMode = 1;
            return reader;
        }
    }
    public bool HasExited { get { lock (sync) { RequireStarted(); return exited; } } }
    public int ExitCode { get { lock (sync) { RequireExit(); return exitCode; } } }
    public uint ExitSignal { get { lock (sync) { RequireExit(); return exitSignal; } } }
    public BrokerExitReason ExitReason { get { lock (sync) { RequireExit(); return exitReason; } } }

    public bool Start() { StartAsync().GetAwaiter().GetResult(); return true; }

    /// <summary>Starts a detached command and returns only its diagnostic PID, not a wait/cancel handle.</summary>
    public static int SpawnDetached(BrokerProcessStartInfo info, string? stdoutFile = null,
        string? stderrFile = null, CancellationToken cancellationToken = default) =>
        SpawnDetachedAsync(info, stdoutFile, stderrFile, cancellationToken).GetAwaiter().GetResult();

    /// <summary>
    /// Uses v2 without fallback or retry. All redirect flags must be false. Log files
    /// are appended; null/empty paths mean /dev/null. A failed acknowledgement may
    /// leave a running command; closing this connection never kills a committed spawn.
    /// </summary>
    public static async Task<int> SpawnDetachedAsync(BrokerProcessStartInfo info, string? stdoutFile = null,
        string? stderrFile = null, CancellationToken cancellationToken = default)
    {
        // Reuse the managed client's private encoding and startup transport, but never
        // expose an instance, activate streams, or send input/CANCEL for detached work.
        using var request = new BrokerProcess(info);
        byte[] payload;
        try { payload = request.EncodeStart(true, stdoutFile, stderrFile); }
        catch (Exception ex) when (ex is not BrokerException)
        { throw Wrap(BrokerErrorCode.InvalidArgument, "arguments", ex); }
        byte[] reply = await request.StartRequestAsync(payload, true, cancellationToken).ConfigureAwait(false);
        uint pid = BinaryPrimitives.ReadUInt32BigEndian(reply);
        if (pid is 0 or > int.MaxValue) throw Protocol("Invalid detached PID.");
        return (int)pid;
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        lock (sync)
        {
            if (disposed || attempted) throw Invalid("An instance can start exactly once, and cannot start after Dispose.");
            attempted = true;
        }
        bool acknowledged = false;
        try
        {
            byte[] payload = EncodeStart();
            inputEnabled = StartInfo.RedirectStandardInput;
            eventLineLimit = StartInfo.MaxEventLineCharacters;
            if (StartInfo.RedirectStandardOutput)
            {
                outputBuffer = new BoundedReadStream(StartInfo.OutputBufferBytes);
                output = new StreamReader(outputBuffer, Encoding.UTF8, false, 4096);
            }
            if (StartInfo.RedirectStandardError)
            {
                errorBuffer = new BoundedReadStream(StartInfo.OutputBufferBytes);
                error = new StreamReader(errorBuffer, Encoding.UTF8, false, 4096);
            }
            await StartRequestAsync(payload, false, cancellationToken).ConfigureAwait(false);
            acknowledged = true;
            lock (sync)
            {
                if (disposed) throw new ObjectDisposedException(nameof(BrokerProcess));
                started = true;
                if (inputEnabled) input = new StreamWriter(new InputStream(this), new UTF8Encoding(false), 4096) { AutoFlush = true };
            }
            // The receive pump never invokes callbacks or waits for stream consumers.
            _ = Task.Run(PumpAsync);
        }
        catch (Exception exception)
        {
            Exception mapped = exception is BrokerException or OperationCanceledException
                ? exception : Wrap(acknowledged ? BrokerErrorCode.ConnectionLost : BrokerErrorCode.InvalidArgument,
                    acknowledged ? "start" : "arguments", exception);
            Fail(mapped);
            client?.Dispose();
            throw mapped;
        }
    }

    private async Task<byte[]> StartRequestAsync(byte[] payload, bool detached, CancellationToken cancellationToken)
    {
        bool sentStart = false;
        string stage = "endpoint";
        try
        {
            int port = ReadEndpoint(StartInfo.EndpointFile);
            client = new TcpClient(AddressFamily.InterNetwork) { NoDelay = true };
            stage = "connect";
            using (var deadline = Deadline(cancellationToken, 3))
                await client.ConnectAsync(IPAddress.Loopback, port, deadline.Token).ConfigureAwait(false);
            wire = client.GetStream();
            stage = "handshake";
            byte[] magic = detached ? DetachedMagic : Magic;
            using (var deadline = Deadline(cancellationToken, 3))
            {
                await wire.WriteAsync(magic, deadline.Token).ConfigureAwait(false);
                byte[] reply = new byte[magic.Length];
                await ReadExactlyAsync(reply, deadline.Token).ConfigureAwait(false);
                if (!reply.AsSpan().SequenceEqual(magic)) throw Protocol("Invalid handshake.");
            }
            stage = "start";
            using (var deadline = Deadline(cancellationToken, 3))
            {
                // Any attempted START write can have an unknown outcome; never retry.
                sentStart = true;
                await WriteFrameAsync(detached ? (byte)10 : (byte)1, payload, deadline.Token).ConfigureAwait(false);
                var frame = await ReadFrameAsync(deadline.Token, detached).ConfigureAwait(false);
                if (frame.Type == 9) throw ParseError(frame.Payload, "start");
                if (frame.Type != (detached ? 11 : 2)) throw Protocol("Unexpected startup reply.");
                return frame.Payload;
            }
        }
        catch (Exception exception)
        {
            client?.Dispose();
            if (exception is BrokerException) throw;
            if (stage is "endpoint" or "connect") throw Wrap(BrokerErrorCode.Unavailable, stage, exception);
            if (stage == "handshake") throw Wrap(BrokerErrorCode.Protocol, stage, exception);
            // Preserve managed cancellation behavior; detached cancellation must also
            // expose that a committed spawn cannot be undone by closing this socket.
            if (!detached && exception is OperationCanceledException && cancellationToken.IsCancellationRequested) throw;
            if (exception is OperationCanceledException && sentStart) throw Wrap(BrokerErrorCode.Timeout, stage, exception);
            throw Wrap(sentStart ? BrokerErrorCode.ConnectionLost : BrokerErrorCode.InvalidArgument, stage, exception);
        }
    }

    public void BeginOutputReadLine() => BeginEvents(false);
    public void BeginErrorReadLine() => BeginEvents(true);
    private void BeginEvents(bool stderr)
    {
        lock (sync)
        {
            RequireStarted();
            StreamReader reader = (stderr ? error : output) ?? throw Invalid("Stream is not redirected.");
            if ((stderr ? errorMode : outputMode) != 0) throw Invalid("Stream already has a reader or event consumer.");
            if (stderr) { errorMode = 2; errorEvents = Task.Run(() => ReadEventsAsync(reader, true)); }
            else { outputMode = 2; outputEvents = Task.Run(() => ReadEventsAsync(reader, false)); }
        }
    }
    private async Task ReadEventsAsync(StreamReader reader, bool stderr)
    {
        try
        {
            var line = new StringBuilder();
            char[] chunk = new char[2048];
            bool previousCr = false;
            while (true)
            {
                int count = await reader.ReadAsync(chunk.AsMemory(), lifetime.Token).ConfigureAwait(false);
                if (count == 0) break;
                for (int i = 0; i < count; i++)
                {
                    char ch = chunk[i];
                    if (ch == '\n' && previousCr) { previousCr = false; continue; }
                    previousCr = ch == '\r';
                    if (ch is '\n' or '\r') { Raise(stderr, line.ToString()); line.Clear(); }
                    else
                    {
                        if (line.Length == eventLineLimit) throw new BrokerException(BrokerErrorCode.Limit, "Event line exceeded MaxEventLineCharacters.", "output");
                        line.Append(ch);
                    }
                }
            }
            if (line.Length != 0) Raise(stderr, line.ToString());
            Raise(stderr, null);
        }
        catch (Exception ex)
        {
            Exception mapped = ex is BrokerException ? ex : Wrap(BrokerErrorCode.Io, "event", ex);
            Fail(mapped);
            throw mapped;
        }
    }
    private void Raise(bool stderr, string? text)
    {
        var handler = stderr ? ErrorDataReceived : OutputDataReceived;
        handler?.Invoke(this, new BrokerDataReceivedEventArgs(text));
    }

    public async Task WaitForExitAsync(CancellationToken cancellationToken = default)
    {
        lock (sync) RequireStarted();
        await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        Task? stdoutTask, stderrTask;
        lock (sync) { stdoutTask = outputEvents; stderrTask = errorEvents; }
        if (stdoutTask != null) await stdoutTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (stderrTask != null) await stderrTask.WaitAsync(cancellationToken).ConfigureAwait(false);
    }
    public void WaitForExit() => WaitForExitAsync().GetAwaiter().GetResult();
    public bool WaitForExit(int milliseconds)
    {
        if (milliseconds < -1) throw Invalid("Timeout must be -1 or nonnegative.");
        using var cancel = new CancellationTokenSource();
        if (milliseconds >= 0) cancel.CancelAfter(milliseconds);
        try { WaitForExitAsync(cancel.Token).GetAwaiter().GetResult(); return true; }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested) { return false; }
    }

    public void Cancel() => CancelAsync().GetAwaiter().GetResult();
    public Task CancelAsync() => SendControlAsync(7, ReadOnlyMemory<byte>.Empty);
    // This is a CANCEL alias, not an immediate SIGKILL or arbitrary signal API.
    public void Kill() => Cancel();
    public Task KillAsync() => CancelAsync();
    // Disposing StandardInput also sends explicit STDIN_EOF. Do not half-close TCP.
    public void CloseStandardInput() => StandardInput.Dispose();
    public async Task CloseStandardInputAsync() => await StandardInput.DisposeAsync().ConfigureAwait(false);

    private async Task SendControlAsync(byte type, ReadOnlyMemory<byte> bytes)
    {
        await sendLock.WaitAsync().ConfigureAwait(false);
        try
        {
            lock (sync)
            {
                RequireStarted();
                if (terminal) { if (type == 7 || type == 4) return; throw Invalid("The command has finished."); }
                if (type != 7)
                {
                    if (!inputEnabled) throw Invalid("Standard input is not redirected.");
                    if (inputEof) { if (type == 4) return; throw Invalid("Standard input has been closed."); }
                    if (type == 4) inputEof = true;
                }
            }
            using var deadline = Deadline(default, 10);
            try { await WriteFrameAsync(type, bytes, deadline.Token).ConfigureAwait(false); }
            catch (Exception ex)
            {
                var mapped = Wrap(BrokerErrorCode.ConnectionLost, "send", ex);
                Fail(mapped);
                throw mapped;
            }
        }
        finally { sendLock.Release(); }
    }

    private async Task PumpAsync()
    {
        try
        {
            while (true)
            {
                var frame = await ReadFrameAsync(lifetime.Token).ConfigureAwait(false);
                switch (frame.Type)
                {
                    case 5: outputBuffer?.Append(frame.Payload); break;
                    case 6: errorBuffer?.Append(frame.Payload); break;
                    case 8:
                        ParseExit(frame.Payload);
                        lock (sync) { if (terminal) return; exited = true; terminal = true; }
                        outputBuffer?.Complete(null);
                        errorBuffer?.Complete(null);
                        client?.Dispose();
                        completion.TrySetResult();
                        return;
                    case 9: throw ParseError(frame.Payload, "running");
                    default: throw Protocol("Unexpected frame after STARTED.");
                }
            }
        }
        catch (Exception ex) { Fail(ex is BrokerException ? ex : Wrap(BrokerErrorCode.ConnectionLost, "receive", ex)); }
    }

    private void ParseExit(byte[] payload)
    {
        uint reason = BinaryPrimitives.ReadUInt32BigEndian(payload);
        int code = BinaryPrimitives.ReadInt32BigEndian(payload.AsSpan(4));
        uint signal = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(8));
        bool normal = code is >= 0 and <= 255 && signal == 0;
        bool signaled = code == -1 && signal > 0;
        if (reason > 2 || (reason == 0 && !normal) || (reason == 1 && !signaled) ||
            (reason == 2 && !normal && !signaled)) throw Protocol("Invalid EXIT result.");
        lock (sync) { exitReason = (BrokerExitReason)reason; exitCode = code; exitSignal = signal; }
    }
    private static BrokerException ParseError(byte[] payload, string stage)
    {
        uint code = BinaryPrimitives.ReadUInt32BigEndian(payload);
        uint length = BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(4));
        if (code is < 1 or > 8 || length != payload.Length - 8) throw Protocol("Invalid ERROR payload.");
        try
        {
            string message = StrictUtf8.GetString(payload, 8, (int)length);
            if (message.Contains('\0')) throw Protocol("NUL in ERROR message.");
            return new BrokerException((BrokerErrorCode)code, message, stage);
        }
        catch (DecoderFallbackException ex) { throw new BrokerException(BrokerErrorCode.Protocol, "Invalid UTF-8 in ERROR.", stage, ex); }
    }

    private async Task<(byte Type, byte[] Payload)> ReadFrameAsync(CancellationToken token, bool detached = false)
    {
        byte[] header = new byte[5];
        await ReadExactlyAsync(header, token).ConfigureAwait(false);
        byte type = header[0];
        uint length = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1));
        bool valid = type switch
        {
            2 => !detached && length == 0,
            5 or 6 => !detached && length is >= 1 and <= 65536,
            8 => !detached && length == 12,
            9 => length is >= 8 and <= MaxFrame,
            11 => detached && length == 4,
            _ => false
        };
        if (!valid) throw Protocol("Invalid frame type or length.");
        byte[] payload = new byte[(int)length];
        await ReadExactlyAsync(payload, token).ConfigureAwait(false);
        return (type, payload);
    }
    private async Task ReadExactlyAsync(Memory<byte> bytes, CancellationToken token)
    {
        while (!bytes.IsEmpty)
        {
            int count = await wire!.ReadAsync(bytes, token).ConfigureAwait(false);
            if (count == 0) throw new EndOfStreamException("Broker closed the connection before a terminal result.");
            bytes = bytes[count..];
        }
    }
    private async Task WriteFrameAsync(byte type, ReadOnlyMemory<byte> payload, CancellationToken token)
    {
        byte[] header = new byte[5];
        header[0] = type;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(1), (uint)payload.Length);
        await wire!.WriteAsync(header, token).ConfigureAwait(false);
        if (!payload.IsEmpty) await wire.WriteAsync(payload, token).ConfigureAwait(false);
    }

    private byte[] EncodeStart(bool detached = false, string? stdoutFile = null, string? stderrFile = null)
    {
        if (detached)
        {
            if (StartInfo.RedirectStandardInput || StartInfo.RedirectStandardOutput || StartInfo.RedirectStandardError)
                throw Invalid("Detached startup requires all RedirectStandard* flags false.");
        }
        else
        {
            if (StartInfo.OutputBufferBytes is < 65536 or > 16 * 1024 * 1024) throw Invalid("OutputBufferBytes must be 65536..16777216.");
            if (StartInfo.MaxEventLineCharacters is < 1 or > 1048576) throw Invalid("MaxEventLineCharacters must be 1..1048576.");
        }
        if (string.IsNullOrEmpty(StartInfo.FileName)) throw Invalid("FileName is empty.");
        if (StartInfo.ArgumentList.Count > 4096 || StartInfo.Environment.Count > 4096) throw Invalid("Too many arguments or environment overrides.");
        using var buffer = new MemoryStream();
        void Number(uint value)
        {
            if (buffer.Length > MaxFrame - 4) throw new BrokerException(BrokerErrorCode.Limit, "START payload exceeds the protocol limit.", "arguments");
            Span<byte> bytes = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
            buffer.Write(bytes);
        }
        void Text(string value)
        {
            if (value == null || value.Contains('\0')) throw Invalid("Strings must be non-null and NUL-free.");
            int count = StrictUtf8.GetByteCount(value);
            if (count > MaxFrame - buffer.Length - 4) throw new BrokerException(BrokerErrorCode.Limit, "START payload exceeds the protocol limit.", "arguments");
            Number((uint)count);
            buffer.Write(StrictUtf8.GetBytes(value));
        }
        Text(StartInfo.FileName);
        Text(StartInfo.WorkingDirectory);
        Number((uint)StartInfo.ArgumentList.Count);
        foreach (string arg in StartInfo.ArgumentList) Text(arg);
        Number((uint)StartInfo.Environment.Count);
        foreach (var pair in StartInfo.Environment)
        {
            if (string.IsNullOrEmpty(pair.Key) || pair.Key.Contains('=')) throw Invalid("Invalid environment key.");
            Text(pair.Key); Text(pair.Value);
        }
        if (buffer.Length >= MaxFrame) throw new BrokerException(BrokerErrorCode.Limit, "START payload exceeds the protocol limit.", "arguments");
        buffer.WriteByte(StartInfo.RedirectStandardInput ? (byte)1 : (byte)0);
        if (detached) { Text(stdoutFile ?? ""); Text(stderrFile ?? ""); }
        return buffer.ToArray();
    }
    private static int ReadEndpoint(string? path)
    {
        try
        {
            path ??= Path.Combine(System.Environment.GetEnvironmentVariable("HOME") ??
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile), ".oheco", "broker", "endpoint");
            // Reject directories and ordinary special files (including zero-length FIFOs)
            // before opening. Managed APIs cannot eliminate a hostile path-replacement race.
            var metadata = new FileInfo(path);
            if ((metadata.Attributes & FileAttributes.Directory) != 0 || metadata.Length is < 1 or > 64)
                throw new FormatException("Endpoint must be a 1..64-byte file.");
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            byte[] bytes = new byte[65];
            int total = 0, count;
            while (total < bytes.Length && (count = file.Read(bytes, total, bytes.Length - total)) != 0) total += count;
            if (total is 0 or > 64) throw new FormatException("Endpoint is empty or too long.");
            if (bytes[total - 1] == 10) { total--; if (total > 0 && bytes[total - 1] == 13) total--; }
            ReadOnlySpan<byte> prefix = "127.0.0.1:"u8;
            if (total <= prefix.Length || !bytes.AsSpan(0, prefix.Length).SequenceEqual(prefix)) throw new FormatException("Invalid endpoint address.");
            int port = 0;
            for (int i = prefix.Length; i < total; i++)
            {
                if (bytes[i] < '0' || bytes[i] > '9') throw new FormatException("Invalid endpoint port.");
                port = checked(port * 10 + bytes[i] - '0');
                if (port > 65535) throw new FormatException("Invalid endpoint port.");
            }
            if (port == 0) throw new FormatException("Invalid endpoint port.");
            return port;
        }
        catch (Exception ex) { throw Wrap(BrokerErrorCode.Unavailable, "endpoint", ex); }
    }
    private CancellationTokenSource Deadline(CancellationToken caller, int seconds)
    {
        var result = CancellationTokenSource.CreateLinkedTokenSource(caller, lifetime.Token);
        result.CancelAfter(TimeSpan.FromSeconds(seconds));
        return result;
    }
    private void RequireStarted()
    {
        if (disposed || !started) throw Invalid("Process has not started or has been disposed.");
    }
    private void RequireExit() { RequireStarted(); if (!exited) throw Invalid("No EXIT result is available."); }
    private static BrokerException Invalid(string message) => new(BrokerErrorCode.InvalidArgument, message, "api");
    private static BrokerException Protocol(string message) => new(BrokerErrorCode.Protocol, message, "protocol");
    private static BrokerException Wrap(BrokerErrorCode code, string stage, Exception ex) =>
        new(code, ex.Message, stage, ex, ex is SocketException socket ? socket.NativeErrorCode : null);
    private void Fail(Exception error)
    {
        lock (sync) { if (terminal) return; terminal = true; }
        lifetime.Cancel();
        client?.Dispose();
        outputBuffer?.Complete(error);
        errorBuffer?.Complete(error);
        completion.TrySetException(error);
        // Observe the fault even if callers only use stream readers or Start fails.
        _ = completion.Task.Exception;
    }
    public void Dispose()
    {
        lock (sync) { if (disposed) return; disposed = true; }
        Fail(new BrokerException(BrokerErrorCode.ConnectionLost, "Disposed: closing the connection cancels an active broker task; no result is known.", "dispose"));
        lifetime.Cancel();
        client?.Dispose();
        // Do not flush StandardInput here: resource release must not block on I/O.
    }

    private sealed class InputStream : Stream
    {
        private readonly BrokerProcess owner;
        private bool closed;
        internal InputStream(BrokerProcess owner) => this.owner = owner;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => !closed;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (closed) throw new ObjectDisposedException(nameof(InputStream));
            while (!buffer.IsEmpty)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int count = Math.Min(65536, buffer.Length);
                await owner.SendControlAsync(3, buffer[..count]).ConfigureAwait(false);
                buffer = buffer[count..];
            }
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing && !closed) { closed = true; owner.SendControlAsync(4, ReadOnlyMemory<byte>.Empty).GetAwaiter().GetResult(); }
            base.Dispose(disposing);
        }
        public override async ValueTask DisposeAsync()
        {
            if (!closed) { closed = true; await owner.SendControlAsync(4, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false); }
            GC.SuppressFinalize(this);
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    // A fixed ring per redirected stream. The receiver never blocks behind consumers.
    private sealed class BoundedReadStream : Stream
    {
        private readonly byte[] ring;
        private readonly object gate = new();
        private TaskCompletionSource changed = NewSignal();
        private int head, size;
        private bool complete;
        private Exception? failure;
        internal BoundedReadStream(int capacity) => ring = new byte[capacity];
        private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal void Append(byte[] bytes)
        {
            lock (gate)
            {
                if (complete) throw new BrokerException(BrokerErrorCode.Io, "Output reader was closed before output finished.", "output");
                if (bytes.Length > ring.Length - size) throw new BrokerException(BrokerErrorCode.Limit, "Output buffer full; continuously drain both redirected streams.", "output");
                int tail = (head + size) % ring.Length;
                int first = Math.Min(bytes.Length, ring.Length - tail);
                bytes.AsSpan(0, first).CopyTo(ring.AsSpan(tail));
                bytes.AsSpan(first).CopyTo(ring);
                size += bytes.Length;
                Pulse();
            }
        }
        internal void Complete(Exception? error)
        {
            lock (gate) { if (complete) return; complete = true; failure = error; Pulse(); }
        }
        private void Pulse() { var previous = changed; changed = NewSignal(); previous.TrySetResult(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length == 0) return 0;
            while (true)
            {
                Task wait;
                lock (gate)
                {
                    if (size != 0)
                    {
                        int count = Math.Min(buffer.Length, Math.Min(size, ring.Length - head));
                        ring.AsMemory(head, count).CopyTo(buffer);
                        head = (head + count) % ring.Length; size -= count;
                        return count;
                    }
                    if (failure != null) throw failure;
                    if (complete) return 0;
                    wait = changed.Task;
                }
                await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        protected override void Dispose(bool disposing)
        {
            if (disposing) Complete(new BrokerException(BrokerErrorCode.Io, "Output reader disposed.", "output"));
            base.Dispose(disposing);
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
