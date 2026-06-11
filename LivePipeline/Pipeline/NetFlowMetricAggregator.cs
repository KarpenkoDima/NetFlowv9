using System.Buffers;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFlowAnalizer.LivePipeline.Aggregation;
using NetFlowAnalizer.LivePipeline.Models;
using NetFlowAnalizer.LivePipeline.WebSocket;
using ClickHouse.Driver.ADO;
using NetFlowAnalizer.LivePipeline.Persistence;

namespace NetFlowAnalizer.LivePipeline.Pipeline;

/// <summary>
/// Фоновый сервис — третье (финальное) звено конвейера.
///
/// Архитектура:
///   AccumulateLoopAsync  ── единственный consumer Channel&lt;InboundFlowRecord&gt;.
///                           Пишет в текущий MetricBucket (uint-ключи, Interlocked).
///   FlushLoopAsync       ── раз в MetricFlushIntervalMs (PeriodicTimer):
///                           1. Атомарно подменяет бакет (Interlocked.Exchange).
///                           2. Вызывает TakeSnapshot() → выполняет Top-10 min-heap.
///                           3. Сериализует в UTF-8 JSON через Source Generation.
///                           4. Рассылает payload через IMetricsWebSocketHub.
///
/// Zero-Allocation гарантии:
///   — Строки IP создаются ТОЛЬКО для финальных 10 записей в TakeSnapshot().
///   — Min-heap использует stackalloc (10 × 12 байт на стеке).
///   — Сериализация через MetricJsonContext (source gen, без рефлексии).
///   — ArrayBufferWriter переиспользуется через поле (один экземпляр на Aggregator).
/// </summary>
public sealed class NetFlowMetricAggregator : BackgroundService
{
    private readonly PipelineChannels                 _channels;
    private readonly IMetricsWebSocketHub             _hub;
    private readonly PipelineOptions                  _opts;
    private readonly ILogger<NetFlowMetricAggregator> _log;

    // Переиспользуемый буфер сериализации — сбрасывается перед каждым тиком.
    // Начальная ёмкость 4 КБ покрывает типичный срез с 10 IP и 5 протоколами.
    private readonly ArrayBufferWriter<byte> _serializeBuffer = new(initialCapacity: 4096);

    // ── Текущий бакет: FlushLoop меняет ссылку атомарно ─────────────────────
    private MetricBucket _currentBucket = new();

    private readonly IClickHouseConnectionFactory _chConnectionFactory;
    private readonly ClickHouseOptions            _chOpts;
    private MinuteTrendAccumulator?               _trendAccumulator;

    public NetFlowMetricAggregator(
        PipelineChannels                   channels,
        IMetricsWebSocketHub               hub,
        IOptions<PipelineOptions>          options,
        IOptions<ClickHouseOptions>        clickHouseOptions,
        IClickHouseConnectionFactory       chConnectionFactory,
        ILogger<NetFlowMetricAggregator>   logger)
    {
        _channels             = channels;
        _hub                  = hub;
        _opts                 = options.Value;
        _chOpts               = clickHouseOptions.Value;
        _chConnectionFactory  = chConnectionFactory;
        _log                  = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation(
            "[Aggregator] Started. Flush interval: {Ms} ms", _opts.MetricFlushIntervalMs);

        await Task.WhenAll(
            AccumulateLoopAsync(stoppingToken),
            FlushLoopAsync(stoppingToken)
        ).ConfigureAwait(false);

        _log.LogInformation("[Aggregator] Stopped.");
    }

    // ── Петля аккумуляции ─────────────────────────────────────────────────────
    // Единственный consumer Channel 2 → детерминированно не параллелен сам себе.
    // Тем не менее FlushLoop может конкурентно обращаться к бакету через
    // ConcurrentDictionary, поэтому MetricBucket гарантирует thread safety.

    private async Task AccumulateLoopAsync(CancellationToken ct)
    {
        var reader = _channels.ParsedRecords.Reader;
        var persistWriter = _channels.RawFlowsForPersistence.Writer;

        await foreach (var record in reader.ReadAllAsync(ct).ConfigureAwait(false))
        {
            // Volatile.Read: гарантирует, что после Interlocked.Exchange в FlushLoop
            // мы увидим свежую ссылку на новый бакет.
            Volatile.Read(ref _currentBucket).Add(in record);

            // Best-effort фан-аут на персист: DropWrite — никогда не блокирует.
            persistWriter.TryWrite(record);
        }
    }

    // ── Петля публикации ──────────────────────────────────────────────────────

    private async Task FlushLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(
            TimeSpan.FromMilliseconds(_opts.MetricFlushIntervalMs));

        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            var now = DateTimeOffset.UtcNow;

            // 1. Атомарно подменяем бакет.
            //    AccumulateLoop при следующем Volatile.Read увидит новый бакет.
            var retired = Interlocked.Exchange(ref _currentBucket, new MetricBucket());

            // 2. Извлекаем снимок с top-10 min-heap (stackalloc, без LINQ).
            var snapshot = retired.TakeSnapshot(now);

            // 2b. Минутный rollup для flows_trends_1m.
            _trendAccumulator ??= new MinuteTrendAccumulator(now);
            var completedMinute = _trendAccumulator.AddSnapshotAndMaybeRoll(
                now,
                snapshot.TotalFlows,
                snapshot.TotalBytes,
                snapshot.TotalPackets,
                snapshot.BitsPerSecond,
                snapshot.PacketsPerSec);

            if (completedMinute is { } row)
            {
                // Fire-and-forget: не блокируем публикацию live-снимка записью в CH.
                _ = WriteTrendRowAsync(row, ct);
            }

            // 3. Сериализуем в UTF-8 JSON через Source Generation (без рефлексии).
            ReadOnlyMemory<byte> payload = SerializeSnapshot(snapshot);

            // 4. Рассылаем подключённым клиентам.
            await _hub.BroadcastAsync(payload, ct).ConfigureAwait(false);

            _log.LogDebug(
                "[Aggregator] {Ts:HH:mm:ss} | flows={F:N0} | bps={B:N0} | pps={P:N0} | " +
                "topSrc={SrcCount} | topDst={DstCount} | proto={ProtoCount}",
                now,
                snapshot.TotalFlows,
                snapshot.BitsPerSecond,
                snapshot.PacketsPerSec,
                snapshot.TopSrcIPs.Length,
                snapshot.TopDstIPs.Length,
                snapshot.Protocols.Length);
        }
    }

    // ── Сериализация ──────────────────────────────────────────────────────────

    private ReadOnlyMemory<byte> SerializeSnapshot(MetricSnapshot snapshot)
    {
        // Сбрасываем переиспользуемый буфер (не выделяет новый массив, если ёмкость достаточна)
        _serializeBuffer.ResetWrittenCount();

        // Utf8JsonWriter пишет напрямую в ArrayBufferWriter — нет промежуточной string
        using var writer = new Utf8JsonWriter(
            _serializeBuffer,
            new JsonWriterOptions { SkipValidation = true });

        // Source Generation: нет рефлексии, код сгенерирован компилятором
        JsonSerializer.Serialize(writer, snapshot, MetricJsonContext.Default.MetricSnapshot);

        return _serializeBuffer.WrittenMemory;
    }

    // ── Минутные тренды (flows_trends_1m) ───────────────────────────────────────

    private async Task WriteTrendRowAsync(TrendRow row, CancellationToken ct)
    {
        try
        {
            await using var connection = await _chConnectionFactory
                .CreateOpenConnectionAsync(ct)
                .ConfigureAwait(false);

            await using var command = connection.CreateCommand();
            command.CommandText =
                $"INSERT INTO {_chOpts.TrendsTableName} " +
                "(Timestamp, TotalFlows, TotalBytes, TotalPackets, BitsPerSecond, PacketsPerSec) " +
                "VALUES (@ts, @flows, @bytes, @packets, @bps, @pps)";

            AddParameter(command, "@ts", row.Timestamp.UtcDateTime);
            AddParameter(command, "@flows", row.TotalFlows);
            AddParameter(command, "@bytes", row.TotalBytes);
            AddParameter(command, "@packets", row.TotalPackets);
            AddParameter(command, "@bps", row.BitsPerSecond);
            AddParameter(command, "@pps", row.PacketsPerSec);

            await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex,
                "[Aggregator] Failed to write 1-minute trend row for {Minute:HH:mm}", row.Timestamp);
        }
    }

    private static void AddParameter(System.Data.Common.DbCommand command, string name, object value)
    {
        var p = command.CreateParameter();
        p.ParameterName = name;
        p.Value = value;
        command.Parameters.Add(p);
    }
}
