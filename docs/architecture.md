# Architecture — NetFlow v9 Live Pipeline

## Overview

The pipeline receives NetFlow v9 UDP exports from a router in real time,
parses them with zero heap allocation on the hot path, stores per-flow records
in ClickHouse, and exposes live metrics via WebSocket and Grafana dashboards.

The design is built around four `BackgroundService` instances connected by
bounded `System.Threading.Channels`. Each stage runs independently; backpressure
propagates naturally through the channel bounds.

---

## Data flow

```
[Router / NetFlow exporter]
        │  UDP :2055
        ▼
┌─────────────────────────────────────────┐
│  NetFlowUdpReceiver          Service #1 │
│  Socket.ReceiveAsync(Memory<byte>)      │
│  ArrayPool<byte>.Shared.Rent()          │
└───────────────────┬─────────────────────┘
                    │  Channel<RawPacketBuffer>
                    │  Bounded(1 024)  FullMode=Wait
                    │  SingleWriter=true  SingleReader=false
                    ▼
┌─────────────────────────────────────────┐
│  NetFlowParserWorkerPool     Service #2 │
│  N parallel Task.Run workers            │
│  LiveNetFlowV9Parser (stateless)        │
│  ArrayPool<byte>.Shared.Return() ↩     │
└───────────────────┬─────────────────────┘
                    │  Channel<InboundFlowRecord>
                    │  Bounded(16 384)  FullMode=Wait
                    │  SingleWriter=false  SingleReader=true
                    ▼
┌─────────────────────────────────────────┐
│  NetFlowMetricAggregator     Service #3 │
│  MetricBucket (double-buffered)         │
│  Interlocked.Exchange swap every 1 s    │
└────────────┬────────────────────────────┘
             │                 │
             │  JSON snapshot  │  Channel<InboundFlowRecord>
             │  (Utf8JsonWriter)│  Bounded(100 000)  FullMode=DropWrite
             ▼                 │  SingleWriter=true  SingleReader=true
    WebSocket /ws/metrics      ▼
    (live dashboard)  ┌────────────────────────────────────────┐
                      │  NetFlowClickHouseWriter     Service #4 │
                      │  BatchSize=50 000 rows                  │
                      │  FlushInterval=1 s                      │
                      │  Retry: up to 6 attempts, 2-min budget  │
                      └──────────────┬─────────────────────────┘
                                     │
                                     ▼
                               ClickHouse
                         flows_raw  +  flows_trends_1m
                                     │
                                     ▼
                               Grafana :3000
```

---

## Backpressure strategy

| Channel | Bound | Mode | Effect |
|---|---|---|---|
| Channel 1 — `RawPackets` | 1 024 | `Wait` | Receiver blocks; router UDP datagrams queue in kernel `SO_RCVBUF` |
| Channel 2 — `ParsedRecords` | 16 384 | `Wait` | Parser workers block; backpressure propagates to Channel 1 |
| Channel 3 — `RawFlowsForPersistence` | 100 000 | `DropWrite` | ClickHouse slowness never blocks the live WebSocket feed |

The rule: persistence is best-effort. The live metrics path always wins.

---

## BackgroundService #1 — NetFlowUdpReceiver

- Binds to `0.0.0.0:Pipeline:UdpPort` (default `2055`) using a low-level `Socket`.
- Calls `Socket.ReceiveAsync(Memory<byte>, SocketFlags, CancellationToken)` in a tight loop.
- For each datagram: rents a buffer from `ArrayPool<byte>.Shared`, copies the datagram, writes a `RawPacketBuffer` struct (array reference + actual length) to Channel 1.
- Does not parse. Does not allocate beyond the rented array.

---

## BackgroundService #2 — NetFlowParserWorkerPool

- Spawns `Pipeline:ParserWorkerCount` workers (default: `Environment.ProcessorCount`).
- Each worker loops on `Channel.Reader.WaitToReadAsync` → `TryRead`.
- Calls `LiveNetFlowV9Parser.Parse(Span<byte>)` — stateless, shared singleton.
- After parsing, calls `ArrayPool<byte>.Shared.Return()` to release the buffer.
- Writes zero or more `InboundFlowRecord` values to Channel 2.

**`InboundFlowRecord`** is a `readonly struct`:

```csharp
public readonly struct InboundFlowRecord
{
    public DateTimeOffset FlowTimestamp { get; init; }
    public uint  SrcAddr   { get; init; }   // big-endian UInt32
    public uint  DstAddr   { get; init; }
    public ushort SrcPort  { get; init; }
    public ushort DstPort  { get; init; }
    public byte  Protocol  { get; init; }
    public ulong Bytes     { get; init; }
    public ulong Packets   { get; init; }
}
```

---

## BackgroundService #3 — NetFlowMetricAggregator

Two concurrent loops inside one `BackgroundService`:

**AccumulateLoop** — reads every `InboundFlowRecord` from Channel 2 and calls
`MetricBucket.Add(in record)` on the current bucket.

**FlushLoop** — fires every `MetricFlushIntervalMs` (default 1 000 ms):
1. `Interlocked.Exchange(ref _currentBucket, _standbyBucket)` — atomic bucket swap.
2. `TakeSnapshot()` on the old bucket → `MetricSnapshot`.
3. Serializes snapshot to JSON via `Utf8JsonWriter` (zero-alloc write path).
4. Broadcasts bytes to all connected WebSocket clients via `IMetricsWebSocketHub`.
5. Calls `oldBucket.Clear()` — resets counters in-place; no `new MetricBucket()` allocation.
6. Also writes every `InboundFlowRecord` to Channel 3 (best-effort, `DropWrite`).

**`MetricBucket` internals:**

| Field | Type | Thread safety |
|---|---|---|
| `_bytes`, `_packets`, `_flowCount` | `long` | `Interlocked.Add` / `Increment` |
| `_srcIpBytes`, `_dstIpBytes` | `ConcurrentDictionary<uint, long>` | Lock-free `AddOrUpdate` with factory args (no closures) |
| `_protoBytes`, `_protoPackets` | `ConcurrentDictionary<byte, long>` | Same |

**Top-10 extraction** — no LINQ, no heap allocation:
`stackalloc` min-heap of 10 elements on the stack; O(n log 10) single pass over the
dictionary. IP strings (`uint` → `"a.b.c.d"`) are built only for the final ≤ 10 results.

---

## BackgroundService #4 — NetFlowClickHouseWriter

- Reads `Channel<InboundFlowRecord>` (Channel 3, `DropWrite`).
- Accumulates rows into a pre-allocated `object?[][]` pool (`BatchSize` × 8 columns);
  avoids `new object?[8]` per flow-record on the flush path.
- Flushes to `flows_raw` when either condition is met:
  - row count reaches `ClickHouseOptions.BatchSize` (default 50 000), or
  - `PeriodicTimer` fires (default 1 s).
- Uses `ClickHouseBulkCopy.WriteToServerAsync`.
- **Retry logic:** up to 6 attempts with exponential backoff (1 s → 2 s → 4 s → 8 s → 16 s → 30 s),
  total budget 2 minutes. After exhaustion the batch is dropped and the loss count is
  incremented; a warning is logged every minute if losses > 0.

**HTTP client:** `IHttpClientFactory` with a named `SocketsHttpHandler`.
`AutomaticDecompression = DecompressionMethods.All` is required — ClickHouse returns
gzip-compressed responses by default, and without this the driver receives compressed
bytes and throws `InvalidOperationException` when parsing response headers.

---

## ClickHouse schema

### `netflow.flows_raw`

```sql
CREATE TABLE netflow.flows_raw (
    Timestamp  DateTime,
    SrcIp      UInt32,
    DstIp      UInt32,
    SrcPort    UInt16,
    DstPort    UInt16,
    Protocol   UInt8,
    Bytes      UInt64,
    Packets    UInt64
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(Timestamp)
ORDER BY (Timestamp, SrcIp, DstIp)
TTL Timestamp + INTERVAL 14 DAY
SETTINGS index_granularity = 8192;
```

Codecs: `DoubleDelta` on `Timestamp`, `ZSTD` on numeric fields.

### `netflow.flows_trends_1m`

```sql
CREATE TABLE netflow.flows_trends_1m (
    Timestamp      DateTime,
    FlowCount      UInt64,
    TotalBytes     UInt64,
    TotalPackets   UInt64,
    BitsPerSecond  Float64,
    PacketsPerSec  Float64
)
ENGINE = MergeTree()
ORDER BY Timestamp;
```

`MinuteTrendAccumulator` (inside `NetFlowClickHouseWriter`) rolls up
per-second MetricBucket snapshots into per-minute rows.

---

## WebSocket protocol

- Endpoint: `ws://<host>/ws/metrics` (configurable via `Pipeline:WebSocketPath`).
- Server sends one JSON frame per second; client sends nothing.
- Frame schema:

```json
{
  "timestamp": "2026-07-27T16:48:16Z",
  "totalFlows": 142,
  "totalBytes": 3871234,
  "totalPackets": 3214,
  "bitsPerSecond": 30969872.0,
  "packetsPerSec": 3214.0,
  "topSrcIPs":  [{ "ip": "192.168.1.1",  "bytes": 2100000 }],
  "topDstIPs":  [{ "ip": "143.244.40.52","bytes": 1800000 }],
  "protocols":  [{ "name": "TCP", "bytes": 3500000, "packets": 2900 }]
}
```

`SimpleMetricsWebSocketHub` broadcasts to all registered `WebSocket` instances
concurrently. To replace with SignalR, implement `IMetricsWebSocketHub` — the
Aggregator has no dependency on the concrete hub type.

---

## Configuration reference

All settings are overridable via environment variables (`__` = section separator).

| Key | Default | Description |
|---|---|---|
| `Pipeline__UdpPort` | `2055` | NetFlow UDP receive port |
| `Pipeline__MaxUdpPacketSize` | `65535` | Max datagram buffer size (bytes) |
| `Pipeline__RawChannelCapacity` | `1024` | Channel 1 bound |
| `Pipeline__ParsedChannelCapacity` | `16384` | Channel 2 bound |
| `Pipeline__Channel3Capacity` | `100000` | Channel 3 bound (DropWrite) |
| `Pipeline__ParserWorkerCount` | CPU count | Parser worker threads |
| `Pipeline__MetricFlushIntervalMs` | `1000` | WebSocket publish interval (ms) |
| `ClickHouse__ConnectionString` | `Host=localhost;...` | ClickHouse connection |
| `ClickHouse__BatchSize` | `50000` | Rows per bulk-insert |
| `ClickHouse__FlushInterval` | `00:00:01` | Periodic flush interval |

---

## Project layout

```
src/
├── LivePipeline/
│   ├── Pipeline/          — BackgroundServices #1 #2 #3, PipelineChannels
│   ├── Aggregation/       — MetricBucket, MetricSnapshot, MetricJsonContext
│   ├── Parsers/           — LiveNetFlowV9Parser (stateless)
│   ├── Persistence/       — NetFlowClickHouseWriter, ClickHouseConnectionFactory
│   ├── WebSocket/         — IMetricsWebSocketHub, SimpleMetricsWebSocketHub
│   ├── Models/            — InboundFlowRecord, RawPacketBuffer, options
│   └── wwwroot/           — live WebSocket dashboard (static HTML/JS)
├── NetFlowAnalizer.Core/  — domain interfaces and models (RFC 3954)
└── NetFlowAnalizer.Infrastructure/ — NetFlowV9Parser (PCAP/offline), TemplateCache
legacy/
├── NetFlowAnalizer/       — original offline PCAP analyzer
└── NetFlowAnalizer.Console/ — CLI for offline analyzer
infra/
├── clickhouse-init/       — 001-schema.sql (applied on first container start)
└── grafana/               — datasource + dashboard auto-provisioning
```

---

## Technology choices and rationale

| Choice | Rationale |
|---|---|
| `System.Threading.Channels` over `BlockingCollection` | Lock-free fast path, native async support, fine-grained `SingleWriter`/`SingleReader` hints for optimized internal locking |
| `ArrayPool<byte>` over per-packet `byte[]` | Eliminates GC pressure on the hot path; UDP socket receives ~thousands of packets/second |
| `struct` for `InboundFlowRecord` and `RawPacketBuffer` | Channels hold value types inline — no boxing, no heap allocation per flow |
| `ConcurrentDictionary` with factory-arg `AddOrUpdate` | No closure allocation per call; factory delegates are `static` |
| `stackalloc` min-heap for Top-10 | Avoids `List<T>` + LINQ on every 1-second flush; O(n log 10) single pass |
| Double-buffered `MetricBucket` | Avoids `new MetricBucket()` allocation every second; `Clear()` resets in-place |
| `DropWrite` on Channel 3 | ClickHouse unavailability must never block the live WebSocket feed |
| `IHttpClientFactory` + `SocketsHttpHandler` | Single connection pool shared across all flushes; prevents socket exhaustion under high flush rate |
