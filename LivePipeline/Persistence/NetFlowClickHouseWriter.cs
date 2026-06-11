using ClickHouse.Driver.Copy;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFlowAnalizer.LivePipeline.Models;
using NetFlowAnalizer.LivePipeline.Pipeline;

namespace NetFlowAnalizer.LivePipeline.Persistence;

/// <summary>
/// Фоновый сервис — best-effort персист сырых flow-записей в ClickHouse (flows_raw).
///
/// Читает Channel 3 (RawFlowsForPersistence), копит записи в переиспользуемый
/// буфер и сбрасывает батч в ClickHouse, когда выполняется ОДНО из условий:
///   - буфер достиг ClickHouseOptions.BatchSize;
///   - с последнего флаша прошло ClickHouseOptions.FlushInterval (PeriodicTimer).
///
/// Backpressure: Channel 3 настроен с FullMode=DropWrite — если этот сервис
/// отстаёт (например, ClickHouse недоступен), новые записи в Channel 3 молча
/// отбрасываются производителем (Aggregator), а НЕ здесь. Этот сервис
/// дополнительно отслеживает собственные потери при retry-исчерпании.
///
/// Ошибки flush: до 3 повторов с экспоненциальной задержкой (1s, 2s, 4s,
/// максимум 30s между попытками, общий бюджет ретраев — 2 минуты). После
/// исчерпания — батч отбрасывается, инкрементируется счётчик потерь,
/// который логируется раз в минуту, если > 0.
/// </summary>
public sealed class NetFlowClickHouseWriter : BackgroundService
{
    private static readonly TimeSpan[] RetryDelays =
    [
        TimeSpan.FromSeconds(1),
        TimeSpan.FromSeconds(2),
        TimeSpan.FromSeconds(4),
        TimeSpan.FromSeconds(8),
        TimeSpan.FromSeconds(16),
        TimeSpan.FromSeconds(30),
    ];

    private static readonly TimeSpan MaxRetryBudget = TimeSpan.FromMinutes(2);

    // Порядок столбцов должен совпадать с порядком значений в массиве,
    // формируемом в ConsumeLoopAsync (buffer.Add([...])).
    private static readonly string[] ColumnNames =
    [
        "Timestamp", "SrcIp", "DstIp", "SrcPort", "DstPort", "Protocol", "Bytes", "Packets",
    ];

    private readonly PipelineChannels                   _channels;
    private readonly IClickHouseConnectionFactory       _connectionFactory;
    private readonly ClickHouseOptions                  _opts;
    private readonly ILogger<NetFlowClickHouseWriter>   _log;

    private long _droppedCount;

    public NetFlowClickHouseWriter(
        PipelineChannels                 channels,
        IClickHouseConnectionFactory     connectionFactory,
        IOptions<ClickHouseOptions>      options,
        ILogger<NetFlowClickHouseWriter> logger)
    {
        _channels          = channels;
        _connectionFactory = connectionFactory;
        _opts              = options.Value;
        _log               = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation(
            "[ClickHouseWriter] Started. BatchSize={BatchSize} FlushInterval={FlushInterval}",
            _opts.BatchSize, _opts.FlushInterval);

        await Task.WhenAll(
            ConsumeLoopAsync(stoppingToken),
            ReportDroppedLoopAsync(stoppingToken)
        ).ConfigureAwait(false);

        _log.LogInformation("[ClickHouseWriter] Stopped.");
    }

    private async Task ConsumeLoopAsync(CancellationToken ct)
    {
        var reader = _channels.RawFlowsForPersistence.Reader;
        var buffer = new List<object?[]>(_opts.BatchSize);

        using var timer = new PeriodicTimer(_opts.FlushInterval);
        var flushTimerTask = timer.WaitForNextTickAsync(ct).AsTask();

        while (!ct.IsCancellationRequested)
        {
            var readTask = reader.WaitToReadAsync(ct).AsTask();
            var completed = await Task.WhenAny(readTask, flushTimerTask).ConfigureAwait(false);

            if (completed == flushTimerTask)
            {
                if (buffer.Count > 0)
                    await FlushAsync(buffer, ct).ConfigureAwait(false);

                flushTimerTask = timer.WaitForNextTickAsync(ct).AsTask();
                continue;
            }

            if (!await readTask.ConfigureAwait(false))
                break; // канал закрыт

            while (reader.TryRead(out var record))
            {
                // Порядок значений должен совпадать с ColumnNames.
                buffer.Add(
                [
                    record.FlowTimestamp.UtcDateTime,
                    record.SrcAddr,
                    record.DstAddr,
                    record.SrcPort,
                    record.DstPort,
                    record.Protocol,
                    record.Bytes,
                    record.Packets,
                ]);

                if (buffer.Count >= _opts.BatchSize)
                {
                    await FlushAsync(buffer, ct).ConfigureAwait(false);
                    flushTimerTask = timer.WaitForNextTickAsync(ct).AsTask();
                }
            }
        }

        // Финальный флаш оставшихся записей при штатной остановке.
        if (buffer.Count > 0)
            await FlushAsync(buffer, ct: default).ConfigureAwait(false);
    }

    private async Task FlushAsync(List<object?[]> buffer, CancellationToken ct)
    {
        var rowCount = buffer.Count;
        var attempt  = 0;
        var elapsed  = TimeSpan.Zero;

        while (true)
        {
            try
            {
                await using var connection = await _connectionFactory
                    .CreateOpenConnectionAsync(ct)
                    .ConfigureAwait(false);

                // ClickHouseBulkCopy is marked [Obsolete] in ClickHouse.Driver 1.2.0,
                // but there is no non-obsolete bulk-insert alternative available;
                // revisit when the driver is upgraded.
#pragma warning disable CS0618
                using var bulkCopy = new ClickHouseBulkCopy(connection)
                {
                    DestinationTableName = _opts.RawTableName,
                    ColumnNames          = ColumnNames,
                    BatchSize            = rowCount,
                };
#pragma warning restore CS0618

                await bulkCopy.WriteToServerAsync(buffer, ct).ConfigureAwait(false);

                _log.LogDebug("[ClickHouseWriter] Flushed {Count} rows to {Table}",
                    rowCount, _opts.RawTableName);

                buffer.Clear();
                return;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                if (attempt >= RetryDelays.Length || elapsed >= MaxRetryBudget)
                {
                    _log.LogError(ex,
                        "[ClickHouseWriter] Failed to flush {Count} rows after {Attempts} attempts — dropping batch",
                        rowCount, attempt + 1);

                    Interlocked.Add(ref _droppedCount, rowCount);
                    buffer.Clear();
                    return;
                }

                var delay = RetryDelays[attempt];
                _log.LogWarning(ex,
                    "[ClickHouseWriter] Flush attempt {Attempt} failed for {Count} rows, retrying in {Delay}",
                    attempt + 1, rowCount, delay);

                await Task.Delay(delay, ct).ConfigureAwait(false);
                elapsed += delay;
                attempt++;
            }
        }
    }

    private async Task ReportDroppedLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));

        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            var dropped = Interlocked.Exchange(ref _droppedCount, 0);
            if (dropped > 0)
                _log.LogWarning("[ClickHouseWriter] Dropped {Count} rows in the last minute due to flush failures", dropped);
        }
    }
}
