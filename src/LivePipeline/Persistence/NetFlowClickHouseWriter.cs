using System.Linq;
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

    // Пул переиспользуемых object?[8]-строк — избегаем `new object?[8]` на каждую
    // flow-запись (BatchSize аллокаций на каждый flush под нагрузкой).
    // Боксинг отдельных полей (DateTime/uint/ushort/byte/ulong) остаётся —
    // это требование ClickHouseBulkCopy.WriteToServerAsync(IEnumerable<object?[]>),
    // но аллокация самих 8-элементных массивов исключена.
    private readonly object?[][] _rowPool;

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

        _rowPool = new object?[_opts.BatchSize][];
        for (int i = 0; i < _rowPool.Length; i++)
            _rowPool[i] = new object?[ColumnNames.Length];
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
        var count  = 0;

        using var timer = new PeriodicTimer(_opts.FlushInterval);
        var flushTimerTask = timer.WaitForNextTickAsync(ct).AsTask();

        while (!ct.IsCancellationRequested)
        {
            var readTask = reader.WaitToReadAsync(ct).AsTask();
            var completed = await Task.WhenAny(readTask, flushTimerTask).ConfigureAwait(false);

            if (completed == flushTimerTask)
            {
                if (count > 0)
                    count = await FlushAsync(count, ct).ConfigureAwait(false);

                flushTimerTask = timer.WaitForNextTickAsync(ct).AsTask();
                continue;
            }

            if (!await readTask.ConfigureAwait(false))
                break; // канал закрыт

            while (reader.TryRead(out var record))
            {
                // Порядок значений должен совпадать с ColumnNames.
                var row = _rowPool[count];
                row[0] = record.FlowTimestamp.UtcDateTime;
                row[1] = record.SrcAddr;
                row[2] = record.DstAddr;
                row[3] = record.SrcPort;
                row[4] = record.DstPort;
                row[5] = record.Protocol;
                row[6] = record.Bytes;
                row[7] = record.Packets;
                count++;

                if (count >= _opts.BatchSize)
                {
                    count = await FlushAsync(count, ct).ConfigureAwait(false);
                    flushTimerTask = timer.WaitForNextTickAsync(ct).AsTask();
                }
            }
        }

        // Финальный флаш оставшихся записей при штатной остановке.
        if (count > 0)
            await FlushAsync(count, ct: default).ConfigureAwait(false);
    }

    /// <summary>
    /// Сбрасывает первые <paramref name="rowCount"/> строк из <see cref="_rowPool"/>
    /// в ClickHouse. Возвращает новое значение счётчика строк в буфере
    /// (0 при успехе или при окончательном дропе батча после исчерпания ретраев).
    /// </summary>
    private async Task<int> FlushAsync(int rowCount, CancellationToken ct)
    {
        var attempt = 0;
        var elapsed = TimeSpan.Zero;
        var rows    = _rowPool.Take(rowCount);

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

                await bulkCopy.WriteToServerAsync(rows, ct).ConfigureAwait(false);

                _log.LogDebug("[ClickHouseWriter] Flushed {Count} rows to {Table}",
                    rowCount, _opts.RawTableName);

                return 0;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                if (attempt >= RetryDelays.Length || elapsed >= MaxRetryBudget)
                {
                    _log.LogError(ex,
                        "[ClickHouseWriter] Failed to flush {Count} rows after {Attempts} attempts — dropping batch",
                        rowCount, attempt + 1);

                    Interlocked.Add(ref _droppedCount, rowCount);
                    return 0;
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
