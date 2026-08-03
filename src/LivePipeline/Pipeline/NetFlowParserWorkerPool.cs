using System.Buffers;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFlowAnalizer.LivePipeline.Models;
using NetFlowAnalizer.LivePipeline.Parsers;

namespace NetFlowAnalizer.LivePipeline.Pipeline;

/// <summary>
/// BackgroundService #2 — N parallel parser workers.
///
/// Each worker:
///   1. Reads RawPacketBuffer from Channel 1 (raw packets).
///   2. Calls LiveNetFlowV9Parser.TryParseRecords into a worker-local
///      InboundFlowRecord[] rented once for the worker's entire lifetime.
///   3. Writes each InboundFlowRecord to Channel 2 (parsed records).
///   4. Returns the byte[] buffer to ArrayPool in finally (no leaks on parse error).
///
/// Worker-local record buffer:
///   ArrayPool<InboundFlowRecord>.Rent is called ONCE per worker, outside the
///   per-packet loop. The same array is reused for every packet the worker
///   processes, eliminating per-packet pool churn on Channel 2's hot path.
/// </summary>
public sealed class NetFlowParserWorkerPool : BackgroundService
{
    private readonly PipelineChannels                 _channels;
    private readonly PipelineOptions                  _opts;
    private readonly ILogger<NetFlowParserWorkerPool> _log;
    private readonly LiveNetFlowV9Parser              _parser;

    public NetFlowParserWorkerPool(
        PipelineChannels                   channels,
        IOptions<PipelineOptions>          options,
        ILogger<NetFlowParserWorkerPool>   logger,
        LiveNetFlowV9Parser                parser)
    {
        _channels = channels;
        _opts     = options.Value;
        _log      = logger;
        _parser   = parser;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation("[ParserPool] Starting {Count} worker(s)", _opts.ParserWorkerCount);

        var workers = Enumerable
            .Range(0, _opts.ParserWorkerCount)
            .Select(id => Task.Run(() => RunWorkerAsync(id, stoppingToken), stoppingToken))
            .ToArray();

        try
        {
            await Task.WhenAll(workers).ConfigureAwait(false);
        }
        finally
        {
            _channels.ParsedRecords.Writer.Complete();
            _log.LogInformation("[ParserPool] All workers stopped.");
        }
    }

    // ── Worker loop ───────────────────────────────────────────────────────────

    private async Task RunWorkerAsync(int workerId, CancellationToken ct)
    {
        var reader = _channels.RawPackets.Reader;
        var writer = _channels.ParsedRecords.Writer;

        // Rent the record output buffer ONCE for this worker's lifetime.
        // All packets processed by this worker share the same array —
        // zero ArrayPool traffic in the per-packet hot path.
        var recordBuf = ArrayPool<InboundFlowRecord>.Shared
            .Rent(LiveNetFlowV9Parser.MaxRecordsPerPacket);

        _log.LogDebug("[ParserPool] Worker {Id} started", workerId);

        try
        {
            await foreach (var buffer in reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                try
                {
                    await ParseAndDispatchAsync(buffer, recordBuf, writer, ct)
                        .ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log.LogWarning(ex,
                        "[ParserPool] Worker {Id}: parse error, packet dropped", workerId);
                }
                finally
                {
                    // Return the byte[] to the pool here — after TryParseRecords has
                    // finished reading from buffer.Span, so the memory is safe to reuse.
                    ArrayPool<byte>.Shared.Return(buffer.Array);
                }
            }
        }
        finally
        {
            // Return the record buffer once, when the worker exits.
            ArrayPool<InboundFlowRecord>.Shared.Return(recordBuf);
            _log.LogDebug("[ParserPool] Worker {Id} finished", workerId);
        }
    }

    // ── Per-packet parse + dispatch ───────────────────────────────────────────

    private async ValueTask ParseAndDispatchAsync(
        RawPacketBuffer                  buffer,
        InboundFlowRecord[]              recordBuf,
        ChannelWriter<InboundFlowRecord> writer,
        CancellationToken                ct)
    {
        int count = _parser.TryParseRecords(
            buffer.Span,
            buffer.TimestampUtcTicks,
            recordBuf.AsSpan());

        for (int i = 0; i < count; i++)
            await writer.WriteAsync(recordBuf[i], ct).ConfigureAwait(false);
    }
}
