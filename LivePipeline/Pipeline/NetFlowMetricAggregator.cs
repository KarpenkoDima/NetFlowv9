using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFlowAnalizer.LivePipeline.Aggregation;
using NetFlowAnalizer.LivePipeline.Models;
using NetFlowAnalizer.LivePipeline.WebSocket;

namespace NetFlowAnalizer.LivePipeline.Pipeline;

/// <summary>
/// Фоновый сервис — третье звено конвейера.
///
/// Работает в двух параллельных задачах:
///   1. AccumulateLoopAsync  — непрерывно читает InboundFlowRecord из Channel 2
///                             и добавляет данные в текущий MetricBucket.
///   2. FlushLoopAsync       — раз в MetricFlushIntervalMs делает SnapshotAndReset
///                             у бакета, сериализует срез в JSON и публикует
///                             через IMetricsWebSocketHub.
///
/// Потокобезопасность:
///   — MetricBucket использует Interlocked, поэтому AccumulateLoop и FlushLoop
///     могут работать конкурентно без lock.
///   — _currentBucket — поле, обновляется через Volatile.Read/Write.
/// </summary>
public sealed class NetFlowMetricAggregator : BackgroundService
{
    private readonly PipelineChannels                   _channels;
    private readonly IMetricsWebSocketHub               _hub;
    private readonly PipelineOptions                    _opts;
    private readonly ILogger<NetFlowMetricAggregator>   _log;

    // Текущий бакет (секундный).  FlushLoop меняет ссылку атомарно.
    private MetricBucket _currentBucket = new();

    public NetFlowMetricAggregator(
        PipelineChannels                     channels,
        IMetricsWebSocketHub                 hub,
        IOptions<PipelineOptions>            options,
        ILogger<NetFlowMetricAggregator>     logger)
    {
        _channels = channels;
        _hub      = hub;
        _opts     = options.Value;
        _log      = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation(
            "[Aggregator] Started. Flush interval: {Ms} ms", _opts.MetricFlushIntervalMs);

        // Запускаем обе петли параллельно; при отмене они выходят сами
        await Task.WhenAll(
            AccumulateLoopAsync(stoppingToken),
            FlushLoopAsync(stoppingToken)
        ).ConfigureAwait(false);

        _log.LogInformation("[Aggregator] Stopped.");
    }

    // ── Петля аккумуляции ─────────────────────────────────────────────────────

    private async Task AccumulateLoopAsync(CancellationToken ct)
    {
        var reader = _channels.ParsedRecords.Reader;

        await foreach (var record in reader.ReadAllAsync(ct).ConfigureAwait(false))
        {
            // Читаем ссылку на бакет атомарно (FlushLoop может её менять)
            var bucket = Volatile.Read(ref _currentBucket);
            bucket.Add(in record);
        }
    }

    // ── Петля публикации ──────────────────────────────────────────────────────

    private async Task FlushLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(
            TimeSpan.FromMilliseconds(_opts.MetricFlushIntervalMs));

        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            var now    = DateTimeOffset.UtcNow;

            // Атомарно подменяем бакет — AccumulateLoop сразу переходит
            // на новый; старый снимаем без риска гонки.
            var old    = Interlocked.Exchange(ref _currentBucket, new MetricBucket());
            var snap   = old.SnapshotAndReset() with { Timestamp = now };

            // Сериализуем в UTF-8 напрямую — без промежуточной string
            var payload = SerializeSnapshot(snap);

            if (_hub is not null)
                await _hub.BroadcastAsync(payload, ct).ConfigureAwait(false);

            _log.LogDebug(
                "[Aggregator] Tick {Ts}: flows={F} bps={B:N0} pps={P:N0}",
                now, snap.FlowCount, snap.BitsPerSecond, snap.PacketsPerSec);
        }
    }

    // ── Сериализация ──────────────────────────────────────────────────────────

    private static ReadOnlyMemory<byte> SerializeSnapshot(MetricSnapshot snap)
    {
        // ArrayBufferWriter<byte> — pre-allocated, zero-copy path в Utf8JsonWriter
        var buffer = new System.Buffers.ArrayBufferWriter<byte>(256);

        using var writer = new Utf8JsonWriter(buffer);
        writer.WriteStartObject();
        writer.WriteString ("timestamp",     snap.Timestamp);
        writer.WriteNumber ("flows",         snap.FlowCount);
        writer.WriteNumber ("bytes",         snap.Bytes);
        writer.WriteNumber ("packets",       snap.Packets);
        writer.WriteNumber ("bitsPerSecond", snap.BitsPerSecond);
        writer.WriteNumber ("packetsPerSec", snap.PacketsPerSec);
        writer.WriteEndObject();
        writer.Flush();

        return buffer.WrittenMemory;
    }
}
