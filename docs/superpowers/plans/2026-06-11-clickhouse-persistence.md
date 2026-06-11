# ClickHouse Persistence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist `InboundFlowRecord`s to a ClickHouse `flows_raw` table (14-day TTL) and 1-minute rollups to `flows_trends_1m` (long retention), via a new best-effort Channel 3 + `NetFlowClickHouseWriter` BackgroundService, without affecting the existing live-dashboard path.

**Architecture:** `NetFlowMetricAggregator` fans out each consumed `InboundFlowRecord` to a new bounded `Channel<InboundFlowRecord>` (Channel 3, `DropWrite` on full). A new `NetFlowClickHouseWriter` BackgroundService batches Channel 3 records (by size or time) and bulk-inserts into `flows_raw` via `ClickHouse.Driver`. The aggregator also accumulates a 1-minute rollup from its existing per-second `MetricSnapshot`s and writes one row per minute to `flows_trends_1m`.

**Tech Stack:** .NET 9, `System.Threading.Channels`, `ClickHouse.Driver` NuGet package, ClickHouse server (Docker), `Microsoft.Extensions.Options`.

---

## File Structure

- Create: `LivePipeline/Models/ClickHouseOptions.cs` — config POCO.
- Create: `LivePipeline/Persistence/IClickHouseConnectionFactory.cs` + `ClickHouseConnectionFactory.cs` — wraps connection-string → `ClickHouseConnection`.
- Create: `LivePipeline/Persistence/NetFlowClickHouseWriter.cs` — BackgroundService, Channel 3 consumer, batches + bulk inserts `flows_raw`, retry/backoff.
- Create: `LivePipeline/Persistence/MinuteTrendAccumulator.cs` — small mutable accumulator for `flows_trends_1m` rows, plus a `TrendsWriter` helper used by the aggregator.
- Modify: `LivePipeline/Pipeline/PipelineChannels.cs` — add Channel 3 (`RawFlowsForPersistence`).
- Modify: `LivePipeline/Pipeline/NetFlowMetricAggregator.cs` — fan out to Channel 3; accumulate + flush `flows_trends_1m` once per wall-clock minute.
- Modify: `LivePipeline/Models/PipelineOptions.cs` — add `Channel3Capacity`.
- Modify: `LivePipeline/LivePipeline.csproj` — add `ClickHouse.Driver` package reference.
- Modify: `LivePipeline/Program.cs` — register options, factory, hosted service.
- Modify: `LivePipeline/appsettings.json` — add `"ClickHouse"` section + `Channel3Capacity`.
- Create: `docker-compose.yml` (repo root) — ClickHouse service.
- Create: `clickhouse-init/001-schema.sql` — `CREATE TABLE` statements for `flows_raw` and `flows_trends_1m`.

---

### Task 1: Add ClickHouse.Driver package and configuration options

**Files:**
- Modify: `LivePipeline/LivePipeline.csproj`
- Create: `LivePipeline/Models/ClickHouseOptions.cs`
- Modify: `LivePipeline/Models/PipelineOptions.cs`
- Modify: `LivePipeline/appsettings.json`

- [ ] **Step 1: Add the NuGet package**

Run from `J:\Video\WORK_ASSETS\experiments\ClaudeProGraphify\NetFlowv9`:

```bash
dotnet add LivePipeline/LivePipeline.csproj package ClickHouse.Driver
```

Expected: `LivePipeline/LivePipeline.csproj` gains a `<PackageReference Include="ClickHouse.Driver" Version="..." />` entry.

- [ ] **Step 2: Create `ClickHouseOptions`**

Create `LivePipeline/Models/ClickHouseOptions.cs`:

```csharp
namespace NetFlowAnalizer.LivePipeline.Models;

/// <summary>
/// Конфигурация подключения и батчинга для записи в ClickHouse.
/// Читается из appsettings.json, секция "ClickHouse".
/// </summary>
public sealed class ClickHouseOptions
{
    public const string Section = "ClickHouse";

    /// <summary>Connection string для ClickHouse.Driver (HTTP, порт 8123 по умолчанию).</summary>
    public string ConnectionString { get; set; } = "Host=localhost;Port=8123;Database=netflow";

    /// <summary>Имя таблицы для сырых flow-записей.</summary>
    public string RawTableName { get; set; } = "flows_raw";

    /// <summary>Имя таблицы для минутных трендов.</summary>
    public string TrendsTableName { get; set; } = "flows_trends_1m";

    /// <summary>Размер батча для bulk-insert в flows_raw.</summary>
    public int BatchSize { get; set; } = 50_000;

    /// <summary>Интервал принудительного флаша батча, даже если BatchSize не достигнут.</summary>
    public TimeSpan FlushInterval { get; set; } = TimeSpan.FromSeconds(1);
}
```

- [ ] **Step 3: Add `Channel3Capacity` to `PipelineOptions`**

In `LivePipeline/Models/PipelineOptions.cs`, after the `ParsedChannelCapacity` property (after line 35), add:

```csharp

    // ── Channel 3: Persistence (Aggregator → ClickHouse Writer) ─────────────
    /// <summary>
    /// Ёмкость канала для записей, идущих на персист в ClickHouse.
    /// FullMode=DropWrite — персист best-effort, не блокирует live-метрики.
    /// </summary>
    public int  Channel3Capacity { get; set; } = 100_000;
```

- [ ] **Step 4: Update `appsettings.json`**

Replace the contents of `LivePipeline/appsettings.json` with:

```json
{
  "Pipeline": {
    "UdpPort": 2055,
    "MaxUdpPacketSize": 65535,
    "RawChannelCapacity": 1024,
    "ParsedChannelCapacity": 16384,
    "Channel3Capacity": 100000,
    "ParserWorkerCount": 8,
    "MetricFlushIntervalMs": 1000,
    "WebSocketPath": "/ws/metrics"
  },
  "ClickHouse": {
    "ConnectionString": "Host=localhost;Port=8123;Database=netflow",
    "RawTableName": "flows_raw",
    "TrendsTableName": "flows_trends_1m",
    "BatchSize": 50000,
    "FlushInterval": "00:00:01"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
```

- [ ] **Step 5: Build to verify**

Run: `dotnet build LivePipeline/LivePipeline.csproj`
Expected: 0 errors.

- [ ] **Step 6: Commit**

```bash
git add LivePipeline/LivePipeline.csproj LivePipeline/Models/ClickHouseOptions.cs LivePipeline/Models/PipelineOptions.cs LivePipeline/appsettings.json
git commit -m "Add ClickHouse.Driver package and configuration options"
```

---

### Task 2: Add Channel 3 (persistence channel) to PipelineChannels

**Files:**
- Modify: `LivePipeline/Pipeline/PipelineChannels.cs`

- [ ] **Step 1: Add the `RawFlowsForPersistence` channel**

In `LivePipeline/Pipeline/PipelineChannels.cs`, after the `ParsedRecords` property declaration (after line 39), add:

```csharp

    // ── Channel 3 ────────────────────────────────────────────────────────────
    /// <summary>
    /// Flow-записи для персиста в ClickHouse: NetFlowMetricAggregator → NetFlowClickHouseWriter.
    ///
    /// SingleWriter=true   — только Aggregator пишет (fan-out из AccumulateLoop).
    /// SingleReader=true   — только NetFlowClickHouseWriter читает.
    /// FullMode=DropWrite  — best-effort: персист НИКОГДА не блокирует live-метрики.
    ///                       При переполнении новые записи отбрасываются молча
    ///                       (счётчик потерь ведёт NetFlowClickHouseWriter).
    /// </summary>
    public Channel<InboundFlowRecord> RawFlowsForPersistence { get; }
```

Then in the constructor, after the `ParsedRecords = ...` initialization (after line 61), add:

```csharp

        RawFlowsForPersistence = Channel.CreateBounded<InboundFlowRecord>(
            new BoundedChannelOptions(opts.Channel3Capacity)
            {
                FullMode                      = BoundedChannelFullMode.DropWrite,
                SingleWriter                  = true,
                SingleReader                  = true,
                AllowSynchronousContinuations = false,
            });
```

- [ ] **Step 2: Build to verify**

Run: `dotnet build LivePipeline/LivePipeline.csproj`
Expected: 0 errors.

- [ ] **Step 3: Commit**

```bash
git add LivePipeline/Pipeline/PipelineChannels.cs
git commit -m "Add Channel 3 (persistence) to PipelineChannels with DropWrite backpressure"
```

---

### Task 3: ClickHouse connection factory

**Files:**
- Create: `LivePipeline/Persistence/IClickHouseConnectionFactory.cs`
- Create: `LivePipeline/Persistence/ClickHouseConnectionFactory.cs`

- [ ] **Step 1: Create the interface**

Create `LivePipeline/Persistence/IClickHouseConnectionFactory.cs`:

```csharp
using ClickHouse.Driver.ADO;

namespace NetFlowAnalizer.LivePipeline.Persistence;

/// <summary>
/// Фабрика подключений к ClickHouse. Каждый вызов создаёт новое
/// (открытое) соединение — ClickHouseConnection не потокобезопасен
/// для конкурентного использования, поэтому каждый writer держит своё.
/// </summary>
public interface IClickHouseConnectionFactory
{
    Task<ClickHouseConnection> CreateOpenConnectionAsync(CancellationToken ct);
}
```

- [ ] **Step 2: Create the implementation**

Create `LivePipeline/Persistence/ClickHouseConnectionFactory.cs`:

```csharp
using ClickHouse.Driver.ADO;
using Microsoft.Extensions.Options;
using NetFlowAnalizer.LivePipeline.Models;

namespace NetFlowAnalizer.LivePipeline.Persistence;

public sealed class ClickHouseConnectionFactory : IClickHouseConnectionFactory
{
    private readonly string _connectionString;

    public ClickHouseConnectionFactory(IOptions<ClickHouseOptions> options)
    {
        _connectionString = options.Value.ConnectionString;
    }

    public async Task<ClickHouseConnection> CreateOpenConnectionAsync(CancellationToken ct)
    {
        var connection = new ClickHouseConnection(_connectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        return connection;
    }
}
```

- [ ] **Step 3: Build to verify**

Run: `dotnet build LivePipeline/LivePipeline.csproj`
Expected: 0 errors. (If `ClickHouse.Driver.ADO` namespace differs from the installed package version, check the actual namespace via `dotnet build` error output and adjust the `using` statements in both files accordingly — the package exposes `ClickHouseConnection` as an ADO.NET `DbConnection` implementation.)

- [ ] **Step 4: Commit**

```bash
git add LivePipeline/Persistence/IClickHouseConnectionFactory.cs LivePipeline/Persistence/ClickHouseConnectionFactory.cs
git commit -m "Add ClickHouse connection factory"
```

---

### Task 4: NetFlowClickHouseWriter (Channel 3 consumer, batched bulk insert)

**Files:**
- Create: `LivePipeline/Persistence/NetFlowClickHouseWriter.cs`

- [ ] **Step 1: Create the writer**

Create `LivePipeline/Persistence/NetFlowClickHouseWriter.cs`:

```csharp
using System.Data;
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

                using var bulkCopy = new ClickHouseBulkCopy(connection)
                {
                    DestinationTableName = _opts.RawTableName,
                    ColumnNames          = ColumnNames,
                    BatchSize            = rowCount,
                };

                await bulkCopy.InitAsync().ConfigureAwait(false);
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
```

- [ ] **Step 2: Build to verify**

Run: `dotnet build LivePipeline/LivePipeline.csproj`
Expected: 0 errors. If `ClickHouse.Driver.Copy.ClickHouseBulkCopy` or its members (`DestinationTableName`, `ColumnNames`, `BatchSize`, `InitAsync`, `WriteToServerAsync`) don't match the installed package's actual API, run:

```bash
dotnet build LivePipeline/LivePipeline.csproj 2>&1 | grep -i "error CS"
```

and adjust the `ClickHouseBulkCopy` usage to match the installed `ClickHouse.Driver` version's actual API (the shape — construct with a connection, set destination table + column names, call an init/write method with rows as `IEnumerable<object?[]>`) is stable across versions; only exact method/property names may need small adjustments.

- [ ] **Step 3: Commit**

```bash
git add LivePipeline/Persistence/NetFlowClickHouseWriter.cs
git commit -m "Add NetFlowClickHouseWriter: batched bulk insert into flows_raw with retry/drop"
```

---

### Task 5: Minute-trend accumulation in NetFlowMetricAggregator + fan-out to Channel 3

**Files:**
- Create: `LivePipeline/Persistence/MinuteTrendAccumulator.cs`
- Modify: `LivePipeline/Pipeline/NetFlowMetricAggregator.cs`

- [ ] **Step 1: Create `MinuteTrendAccumulator`**

Create `LivePipeline/Persistence/MinuteTrendAccumulator.cs`:

```csharp
namespace NetFlowAnalizer.LivePipeline.Persistence;

/// <summary>
/// Накапливает per-second MetricSnapshot'ы в течение текущей календарной минуты
/// для записи одной строки в flows_trends_1m.
///
/// Не потокобезопасен — используется только из FlushLoop в NetFlowMetricAggregator
/// (тот же поток, что вызывает TakeSnapshot раз в секунду).
/// </summary>
public sealed class MinuteTrendAccumulator
{
    private long   _totalFlows;
    private long   _totalBytes;
    private long   _totalPackets;
    private double _bpsSum;
    private double _ppsSum;
    private int    _sampleCount;
    private DateTimeOffset _minuteStart;

    public MinuteTrendAccumulator(DateTimeOffset now)
    {
        _minuteStart = FloorToMinute(now);
    }

    private static DateTimeOffset FloorToMinute(DateTimeOffset ts) =>
        new(ts.Year, ts.Month, ts.Day, ts.Hour, ts.Minute, 0, ts.Offset);

    /// <summary>
    /// Добавляет очередной секундный снимок. Если снимок относится к новой
    /// календарной минуте, возвращает завершённую строку для предыдущей минуты
    /// (и сбрасывает аккумулятор для новой), иначе — null.
    /// </summary>
    public TrendRow? AddSnapshotAndMaybeRoll(
        DateTimeOffset now, long totalFlows, long totalBytes, long totalPackets,
        double bitsPerSecond, double packetsPerSec)
    {
        var minute = FloorToMinute(now);

        TrendRow? completed = null;
        if (minute != _minuteStart && _sampleCount > 0)
        {
            completed = BuildRow();
            Reset(minute);
        }
        else if (minute != _minuteStart)
        {
            // Не было ни одного сэмпла в предыдущей минуте — просто сдвигаем окно.
            Reset(minute);
        }

        _totalFlows   += totalFlows;
        _totalBytes   += totalBytes;
        _totalPackets += totalPackets;
        _bpsSum       += bitsPerSecond;
        _ppsSum       += packetsPerSec;
        _sampleCount++;

        return completed;
    }

    private TrendRow BuildRow() => new(
        Timestamp:     _minuteStart,
        TotalFlows:    _totalFlows,
        TotalBytes:    _totalBytes,
        TotalPackets:  _totalPackets,
        BitsPerSecond: _sampleCount > 0 ? _bpsSum / _sampleCount : 0,
        PacketsPerSec: _sampleCount > 0 ? _ppsSum / _sampleCount : 0);

    private void Reset(DateTimeOffset minute)
    {
        _minuteStart  = minute;
        _totalFlows   = 0;
        _totalBytes   = 0;
        _totalPackets = 0;
        _bpsSum       = 0;
        _ppsSum       = 0;
        _sampleCount  = 0;
    }
}

/// <summary>Одна строка для таблицы flows_trends_1m.</summary>
public readonly record struct TrendRow(
    DateTimeOffset Timestamp,
    long   TotalFlows,
    long   TotalBytes,
    long   TotalPackets,
    double BitsPerSecond,
    double PacketsPerSec);
```

- [ ] **Step 2: Wire fan-out to Channel 3 in `AccumulateLoopAsync`**

In `LivePipeline/Pipeline/NetFlowMetricAggregator.cs`, modify `AccumulateLoopAsync` (lines 74-84) to also write to Channel 3:

```csharp
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
```

- [ ] **Step 3: Add ClickHouse client + minute accumulator fields and constructor params**

In `LivePipeline/Pipeline/NetFlowMetricAggregator.cs`, add usings at the top (after line 8):

```csharp
using ClickHouse.Driver.ADO;
using NetFlowAnalizer.LivePipeline.Persistence;
```

Add fields after `_currentBucket` (after line 42):

```csharp
    private readonly IClickHouseConnectionFactory _chConnectionFactory;
    private readonly ClickHouseOptions            _chOpts;
    private MinuteTrendAccumulator?               _trendAccumulator;
```

Update the constructor to accept the new dependencies:

```csharp
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
```

(Add the necessary `using Microsoft.Extensions.Options;` and `using NetFlowAnalizer.LivePipeline.Models;` — both are already present per the existing file header.)

- [ ] **Step 4: Roll up and write `flows_trends_1m` from `FlushLoopAsync`**

In `LivePipeline/Pipeline/NetFlowMetricAggregator.cs`, in `FlushLoopAsync` (lines 88-121), after computing `snapshot` (after line 102) and before broadcasting, add the minute-rollup logic. Replace the body of the `while` loop with:

```csharp
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
```

- [ ] **Step 5: Add `WriteTrendRowAsync` helper**

In `LivePipeline/Pipeline/NetFlowMetricAggregator.cs`, add a new private method after `SerializeSnapshot` (after the closing brace that currently ends the file at line 140):

```csharp

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
```

- [ ] **Step 6: Build to verify**

Run: `dotnet build LivePipeline/LivePipeline.csproj`
Expected: 0 errors. If `ClickHouseConnection.CreateCommand()` parameter binding (`@name` syntax) doesn't match the installed `ClickHouse.Driver` version, check the build error and adjust parameter naming convention accordingly (the package supports named parameters; exact prefix character may be `@` or `{name:Type}` depending on version — adjust both the `CommandText` placeholders and `ParameterName` values consistently).

- [ ] **Step 7: Commit**

```bash
git add LivePipeline/Persistence/MinuteTrendAccumulator.cs LivePipeline/Pipeline/NetFlowMetricAggregator.cs
git commit -m "Add minute-trend rollup (flows_trends_1m) and fan-out to persistence channel"
```

---

### Task 6: Register persistence services in Program.cs

**Files:**
- Modify: `LivePipeline/Program.cs`

- [ ] **Step 1: Add usings**

In `LivePipeline/Program.cs`, add to the using block at the top (after line 7):

```csharp
using NetFlowAnalizer.LivePipeline.Persistence;
```

- [ ] **Step 2: Register ClickHouseOptions, factory, and hosted service**

In `LivePipeline/Program.cs`, after the `// ── 2. Парсер и кэш шаблонов` section (after line 67), add a new section:

```csharp

// ── 2b. ClickHouse-персистентность ────────────────────────────────────────
//
// ClickHouseOptions — конфигурация подключения и батчинга (appsettings.json,
// секция "ClickHouse"). ClickHouseConnectionFactory создаёт по соединению на
// каждый flush (ClickHouseConnection не потокобезопасен для конкуррентного
// использования). NetFlowClickHouseWriter — четвёртый BackgroundService,
// best-effort consumer Channel 3.

builder.Services
    .AddOptions<ClickHouseOptions>()
    .Bind(builder.Configuration.GetSection(ClickHouseOptions.Section))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddSingleton<IClickHouseConnectionFactory, ClickHouseConnectionFactory>();
builder.Services.AddHostedService<NetFlowClickHouseWriter>();
```

- [ ] **Step 3: Build to verify**

Run: `dotnet build LivePipeline/LivePipeline.csproj`
Expected: 0 errors.

- [ ] **Step 4: Commit**

```bash
git add LivePipeline/Program.cs
git commit -m "Register ClickHouse persistence services in Program.cs"
```

---

### Task 7: Docker Compose + ClickHouse schema init script

**Files:**
- Create: `docker-compose.yml` (repo root: `J:\Video\WORK_ASSETS\experiments\ClaudeProGraphify\NetFlowv9\docker-compose.yml`)
- Create: `clickhouse-init/001-schema.sql`

- [ ] **Step 1: Create the schema init script**

Create `clickhouse-init/001-schema.sql`:

```sql
CREATE DATABASE IF NOT EXISTS netflow;

CREATE TABLE IF NOT EXISTS netflow.flows_raw
(
    Timestamp DateTime CODEC(DoubleDelta, ZSTD(1)),
    SrcIp     UInt32   CODEC(ZSTD(1)),
    DstIp     UInt32   CODEC(ZSTD(1)),
    SrcPort   UInt16   CODEC(ZSTD(1)),
    DstPort   UInt16   CODEC(ZSTD(1)),
    Protocol  UInt8    CODEC(ZSTD(1)),
    Bytes     UInt64   CODEC(ZSTD(1)),
    Packets   UInt64   CODEC(ZSTD(1))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(Timestamp)
ORDER BY (Timestamp, SrcIp, DstIp)
TTL Timestamp + INTERVAL 14 DAY;

CREATE TABLE IF NOT EXISTS netflow.flows_trends_1m
(
    Timestamp     DateTime,
    TotalFlows    UInt64,
    TotalBytes    UInt64,
    TotalPackets  UInt64,
    BitsPerSecond Float64,
    PacketsPerSec Float64
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(Timestamp)
ORDER BY Timestamp;
```

- [ ] **Step 2: Create `docker-compose.yml`**

Create `J:\Video\WORK_ASSETS\experiments\ClaudeProGraphify\NetFlowv9\docker-compose.yml`:

```yaml
services:
  clickhouse:
    image: clickhouse/clickhouse-server:24.8
    container_name: netflow-clickhouse
    ports:
      - "8123:8123"   # HTTP interface (used by ClickHouse.Driver)
      - "9000:9000"   # Native TCP interface
    volumes:
      - clickhouse-data:/var/lib/clickhouse
      - ./clickhouse-init:/docker-entrypoint-initdb.d
    ulimits:
      nofile:
        soft: 262144
        hard: 262144

volumes:
  clickhouse-data:
```

- [ ] **Step 3: Verify compose file syntax**

Run: `docker compose config`
Expected: prints the resolved compose configuration with no errors (Docker doesn't need to be running for `config` to validate syntax; if Docker itself isn't installed/running on this machine, skip running the container and note this in the final report).

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml clickhouse-init/001-schema.sql
git commit -m "Add ClickHouse Docker Compose service and schema init script"
```

---

### Task 8: Build, integration smoke test, and documentation note

**Files:**
- None (verification only)

- [ ] **Step 1: Full solution build**

Run: `dotnet build NetFlowAnalizer.sln`
Expected: 0 errors across all projects.

- [ ] **Step 2: Start ClickHouse (if Docker available)**

Run: `docker compose up -d clickhouse`
Expected: container starts; `clickhouse-init/001-schema.sql` runs on first start, creating `netflow.flows_raw` and `netflow.flows_trends_1m`.

If Docker is unavailable in this environment, skip this step and note it — Tasks 1-7 still produce buildable, reviewable code; the runtime smoke test becomes a manual follow-up for the user.

- [ ] **Step 3: Run the pipeline and verify writes (only if Step 2 succeeded)**

Run: `dotnet run --project LivePipeline/LivePipeline.csproj`

Send some test NetFlow v9 traffic to UDP port 2055 (using whatever existing test/sample generator exists in the repo, or `nc`/a small script).

After ~5-10 seconds, query:

```bash
docker exec netflow-clickhouse clickhouse-client --query "SELECT count() FROM netflow.flows_raw"
docker exec netflow-clickhouse clickhouse-client --query "SELECT *, IPv4NumToString(SrcIp), IPv4NumToString(DstIp) FROM netflow.flows_raw LIMIT 5"
```

Expected: non-zero row count; IPs render as dotted-decimal.

After ~70+ seconds, query:

```bash
docker exec netflow-clickhouse clickhouse-client --query "SELECT * FROM netflow.flows_trends_1m"
```

Expected: at least one row for the completed minute.

- [ ] **Step 4: Stop services**

```bash
docker compose down
```

(Use `docker compose down -v` only if you want to discard the ClickHouse data volume — do not do this without checking with the user first, since it deletes persisted data.)
