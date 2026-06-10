# ClickHouse Persistence for NetFlow Pipeline — Design Spec

**Date:** 2026-06-10
**Status:** Approved

## Goal

Persist NetFlow data from the `LivePipeline` for later analysis, without
degrading the live dashboard path (Channel 2 → `NetFlowMetricAggregator` →
WebSocket). Two tables in ClickHouse:

- `flows_raw` — per-flow detail, short retention (forensics/audit).
- `flows_trends_1m` — minute-level aggregates, long retention (historical
  trend charts).

## Context

- `LivePipeline` currently has a 2-channel pipeline:
  `NetFlowUdpReceiver` → Channel 1 (`RawPacketBuffer`) →
  `NetFlowParserWorkerPool` → Channel 2 (`InboundFlowRecord`) →
  `NetFlowMetricAggregator` → WebSocket (`MetricSnapshot`, 1/sec).
- No persistent storage exists today — confirmed in prior session
  (`docs/superpowers/specs/2026-06-10-live-dashboard-design.md`).
- `InboundFlowRecord` fields used here: `Timestamp`, `SrcIp`/`DstIp` (UInt32),
  `SrcPort`/`DstPort`, `Protocol`, `Bytes`, `Packets` (exact field names to be
  confirmed against the existing struct during implementation — this spec
  uses the canonical names from the struct as-is).
- ClickHouse instance: assumed to run via Docker (added to
  `docker-compose.yml` as part of implementation), reachable via HTTP
  (port 8123).
- .NET client: **`ClickHouse.Driver`** (official NuGet package), used for
  bulk insert via its bulk-copy API.

## Architecture

```
                         Channel 2 (InboundFlowRecord)
                                    │
                ┌───────────────────┴───────────────────┐
                ▼                                         ▼
   NetFlowMetricAggregator                    Channel 3 (InboundFlowRecord)
   (existing, unchanged 1s logic)                         │
        │                                                  ▼
        │ (new: 1-min rollup)                  NetFlowClickHouseWriter
        ▼                                       (new BackgroundService)
   flows_trends_1m                                         │
                                                            ▼
                                                       flows_raw
```

- `NetFlowMetricAggregator` keeps its existing per-second logic untouched.
  After consuming a record from Channel 2 for its in-memory bucket, it
  additionally calls `Channel3Writer.TryWrite(record)` to fan the same
  record out to the persistence path. This is a non-blocking, best-effort
  write (see Backpressure below) — it does not change Channel 2's
  consumption rate or the aggregator's existing `BoundedChannelFullMode.Wait`
  semantics on Channel 2.

- `NetFlowClickHouseWriter` (new `BackgroundService`) is the sole consumer of
  Channel 3. It batches records and bulk-inserts into `flows_raw`.

- `flows_trends_1m` is populated by the aggregator itself: it already builds
  one `MetricSnapshot` per second; a new minute-level accumulator (a small
  in-memory struct holding running sums/counts) is updated on every
  `MetricSnapshot` tick and flushed as one row to `flows_trends_1m` once per
  minute (boundary determined by wall-clock minute rollover, not a 60-tick
  counter, to stay aligned with real time even if ticks are occasionally
  delayed).

## Channel 3: Configuration & Backpressure

- New bounded `Channel<InboundFlowRecord>`, registered in DI alongside
  Channels 1 and 2.
- Capacity: configurable (default 100,000), `SingleReader = true`,
  `SingleWriter = true` (only the aggregator writes, only
  `NetFlowClickHouseWriter` reads).
- **`BoundedChannelFullMode.DropWrite`** — deliberately different from
  Channels 1/2 (`Wait`). Persistence is best-effort and must never apply
  backpressure to the live metrics/dashboard path. If Channel 3 is full
  (ClickHouse slow/unreachable), new records for `flows_raw` are silently
  dropped; the live dashboard and `flows_trends_1m` (driven independently by
  the aggregator's own snapshot logic) are unaffected.
- Dropped-record count is tracked via an `Interlocked` counter and logged
  periodically (e.g. every minute) by `NetFlowClickHouseWriter` if non-zero.

## NetFlowClickHouseWriter

- `BackgroundService` reading from Channel 3.
- Maintains a reusable `List<InboundFlowRecord>` buffer (or pooled array),
  pre-sized to the configured batch size.
- Flush triggers (whichever first):
  - Buffer reaches **`BatchSize`** records (default 50,000), or
  - **`FlushInterval`** elapsed since last flush (default 1 second), checked
    via `PeriodicTimer` running concurrently with the channel-read loop.
- On flush: bulk-insert the buffer into `flows_raw` via `ClickHouse.Driver`'s
  bulk-copy API, then clear the buffer (reuse, no reallocation).
- **Error handling on flush failure** (ClickHouse unreachable / insert
  error):
  - Log the error (with record count and exception).
  - Retry the same batch with exponential backoff (e.g. 1s, 2s, 4s, capped at
    30s), up to a configurable max retry duration (default 2 minutes).
  - If retries are exhausted, drop the batch (log a warning with dropped
    count) and continue — do not block the channel-read loop indefinitely,
    since that would cause Channel 3 to fill and start dropping anyway.
  - While a flush is being retried, the channel-read loop continues reading
    into a *new* buffer up to a hard cap (e.g. 3× `BatchSize`); beyond that
    cap, reads pause until the retry resolves (bounded memory growth).

## Schema

```sql
CREATE TABLE flows_raw
(
    Timestamp DateTime,
    SrcIp     UInt32,
    DstIp     UInt32,
    SrcPort   UInt16,
    DstPort   UInt16,
    Protocol  UInt8,
    Bytes     UInt64,
    Packets   UInt64
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(Timestamp)
ORDER BY (Timestamp, SrcIp, DstIp)
TTL Timestamp + INTERVAL 14 DAY;

CREATE TABLE flows_trends_1m
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

- IPs stored as `UInt32` (matching `InboundFlowRecord`'s in-memory
  representation — no string conversion, no allocation on insert).
  Analysts use `IPv4NumToString(SrcIp)` / `IPv4NumToString(DstIp)` in SELECT
  queries to render dotted-decimal addresses.
- `flows_raw` TTL: 14 days (configurable constant in the migration script;
  not runtime-configurable for v1 — YAGNI).
- `flows_trends_1m`: no TTL (long-term retention, "year or more" per
  requirements; operators can add a TTL later via `ALTER TABLE` if needed —
  not part of this spec).
- `flows_trends_1m` does **not** include top-IP or per-protocol breakdowns in
  v1 — out of scope (see below). Only the scalar KPI fields already present
  in `MetricSnapshot`'s top-level numeric fields.

## Configuration & DI

New `ClickHouseOptions` (bound from `appsettings.json`, section
`"ClickHouse"`):

```csharp
public sealed class ClickHouseOptions
{
    public string ConnectionString { get; set; } = "Host=localhost;Port=8123;Database=netflow";
    public string RawTableName     { get; set; } = "flows_raw";
    public string TrendsTableName  { get; set; } = "flows_trends_1m";
    public int    BatchSize        { get; set; } = 50_000;
    public TimeSpan FlushInterval  { get; set; } = TimeSpan.FromSeconds(1);
    public int    Channel3Capacity { get; set; } = 100_000;
}
```

DI registration in `Program.cs` (new section, alongside existing channel
registrations):

```csharp
builder.Services.Configure<ClickHouseOptions>(
    builder.Configuration.GetSection("ClickHouse"));

builder.Services.AddSingleton(Channel.CreateBounded<InboundFlowRecord>(
    new BoundedChannelOptions(chOptions.Channel3Capacity)
    {
        SingleReader = true,
        SingleWriter = true,
        FullMode = BoundedChannelFullMode.DropWrite,
    }));
// reader/writer accessors registered the same pattern as Channels 1/2

builder.Services.AddSingleton<IClickHouseConnectionFactory, ClickHouseConnectionFactory>();
builder.Services.AddHostedService<NetFlowClickHouseWriter>();
```

`NetFlowMetricAggregator`'s constructor gains a `ChannelWriter<InboundFlowRecord>`
parameter for Channel 3 (injected the same way Channel 2's writer is injected
into the parser worker pool today).

## Deployment

- ClickHouse added to `docker-compose.yml` as a new service (official
  `clickhouse/clickhouse-server` image), with a named volume for data and
  port 8123 exposed.
- Schema (the two `CREATE TABLE` statements above) applied via a SQL file
  mounted into the container's `/docker-entrypoint-initdb.d/` (ClickHouse's
  standard init-script mechanism) — no custom migration tooling needed for
  v1.

## Out of Scope (YAGNI)

- Top-IP / per-protocol breakdowns in `flows_trends_1m`.
- Runtime-configurable TTL or retention policy changes via API.
- Read-side query API / analyst dashboard for ClickHouse data (separate
  future work — this spec covers only the write path).
- Alternative storage backends (InfluxDB, etc.) — ClickHouse only.
- Custom RowBinary writer — using `ClickHouse.Driver`'s built-in bulk-copy
  API for v1; a hand-rolled writer is a possible future optimization but not
  needed now (per the engineering trade-off discussion: official driver
  gives ~90-95% of the performance at much lower complexity).
- Retry/backoff configuration exposed via `ClickHouseOptions` — constants for
  v1 (1s/2s/4s.../30s cap, 2min max) are hardcoded in
  `NetFlowClickHouseWriter`; can be promoted to config later if needed.

## Testing / Verification

- Unit test: `NetFlowClickHouseWriter` batching logic (size trigger and time
  trigger) using a fake/mock ClickHouse client.
- Integration test (optional, requires Docker): spin up ClickHouse via
  testcontainers, verify rows land in `flows_raw` after writing records to
  Channel 3, and that `flows_trends_1m` gets one row per simulated minute.
- Manual verification: run `docker-compose up`, run `LivePipeline` against
  live/simulated NetFlow traffic, query
  `SELECT count() FROM flows_raw` and
  `SELECT *, IPv4NumToString(SrcIp) FROM flows_raw LIMIT 10` to confirm data
  and IP rendering.
