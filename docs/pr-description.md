# PR: NetFlow v9 Live Pipeline — v1.0.0

**Branch:** `main` → `origin/main`  
**Diff:** 79 files changed, +16 349 / −41 lines  
**Commits:** 9 (squashed from ~62 working commits)

---

## What this PR does

Replaces the offline PCAP analyzer with a production-grade live pipeline that:

- Receives NetFlow v9 UDP exports from a router in real time
- Parses packets with zero heap allocation on the hot path
- Stores per-flow records in ClickHouse (14-day TTL, compressed)
- Exposes live metrics via WebSocket (1-second cadence)
- Provides historical dashboards in Grafana via ClickHouse datasource
- Runs as a single `docker compose up` command

---

## Background

The original project (`NetFlowv9/`) parsed PCAP files offline. This PR keeps
that work intact under `legacy/` and builds the live pipeline in `src/LivePipeline/`
as a new ASP.NET Core 9 service. Both share the `NetFlowAnalizer.Core` and
`NetFlowAnalizer.Infrastructure` libraries via `src/`.

---

## Architecture

```
[Router UDP :2055]
      │
      ▼  ArrayPool<byte>
 NetFlowUdpReceiver          BackgroundService #1
      │  Channel<RawPacketBuffer>  Bounded(1024)  Wait
      ▼
 NetFlowParserWorkerPool     BackgroundService #2  (N workers, stateless parser)
      │  Channel<InboundFlowRecord>  Bounded(16384)  Wait
      ▼
 NetFlowMetricAggregator     BackgroundService #3  (double-buffered MetricBucket)
      │                    │
      │  WebSocket JSON     │  Channel<InboundFlowRecord>  Bounded(100000)  DropWrite
      ▼                    ▼
 /ws/metrics          NetFlowClickHouseWriter    BackgroundService #4
 (live dashboard)          │  batch 50 000 rows / 1 s
                           ▼
                      ClickHouse → flows_raw + flows_trends_1m → Grafana
```

Full design: [`docs/architecture.md`](architecture.md)

---

## Commits

| Hash | Description |
|---|---|
| `b879d24` | feat: reorganize into src/legacy layout — Core, Infrastructure, Console |
| `b7c4e57` | feat: zero-alloc NetFlow v9 live pipeline on System.Threading.Channels |
| `8715682` | feat: real-time WebSocket metrics dashboard |
| `9071d6b` | feat: ClickHouse persistence — flows_raw, flows_trends_1m |
| `e1886f9` | feat: Docker multi-stage build and docker-compose stack |
| `d7654ac` | feat: Grafana auto-provisioned dashboards via ClickHouse datasource |
| `913a3ea` | docs: README, LIVEPIPELINE_GUIDE, GRAFANA_GUIDE |
| `4351dab` | chore: remove old NetFlowv9/ directory |
| `dc3c461` | docs: add architecture.md |

---

## Key technical decisions

### Zero allocation on the hot path

Every UDP datagram is handled without touching the GC heap:

- `ArrayPool<byte>.Shared.Rent()` in the receiver; `.Return()` in the parser after processing.
- `InboundFlowRecord` and `RawPacketBuffer` are `readonly struct` — channels hold them inline.
- `MetricBucket.Add()` uses `Interlocked.Add` on plain `long` fields and `ConcurrentDictionary.AddOrUpdate`
  with `static` factory delegates (no closures → no allocations).
- Top-10 IP extraction uses a `stackalloc` min-heap; IP strings are built only for ≤10 results per second.

### Backpressure

| Channel | Bound | Mode | Reason |
|---|---|---|---|
| Raw packets (UDP → Parser) | 1 024 | `Wait` | Block receiver; datagrams queue in kernel `SO_RCVBUF` |
| Parsed records (Parser → Aggregator) | 16 384 | `Wait` | Full backpressure through both stages |
| Persistence (Aggregator → ClickHouse) | 100 000 | `DropWrite` | ClickHouse slowness must never block the live WebSocket path |

### Double-buffered MetricBucket

The aggregator holds two `MetricBucket` instances. Every second it swaps them via
`Interlocked.Exchange`, serializes the old one to JSON, and calls `Clear()` on it
for reuse — no `new MetricBucket()` allocation per flush.

### ClickHouse HTTP client

`IHttpClientFactory` with a named `SocketsHttpHandler`:
`AutomaticDecompression = DecompressionMethods.All` is required — ClickHouse compresses
HTTP responses with gzip by default, and without this the driver throws
`InvalidOperationException` when parsing response headers.

### Docker build

Multi-stage `Dockerfile` (`sdk:9.0` publish → `aspnet:9.0` runtime).
`.dockerignore` excludes `**/obj/` — Windows NuGet caches in `obj/` contain
hardcoded Windows paths (`C:\Program Files\...`) that break the Linux container build.

---

## What's included

### New: `src/LivePipeline/`

```
Pipeline/
  NetFlowUdpReceiver.cs          — Socket.ReceiveAsync + ArrayPool + Channel 1
  NetFlowParserWorkerPool.cs     — N parallel workers, Channel 1 → Channel 2
  NetFlowMetricAggregator.cs     — double-buffered accumulation, Channel 2 → WS + Channel 3
  PipelineChannels.cs            — all three channels with their BoundedChannelOptions
Aggregation/
  MetricBucket.cs                — lock-free counters, stackalloc top-10 heap
  MetricSnapshot.cs              — serializable snapshot struct
  MetricJsonContext.cs           — source-gen JsonSerializerContext (AOT-ready)
Parsers/
  LiveNetFlowV9Parser.cs         — stateless RFC 3954 parser over Span<byte>
Persistence/
  NetFlowClickHouseWriter.cs     — BackgroundService #4, batched bulk insert, retry
  ClickHouseConnectionFactory.cs — IHttpClientFactory-backed connection factory
  MinuteTrendAccumulator.cs      — rolls up per-second snapshots into 1-min rows
WebSocket/
  IMetricsWebSocketHub.cs        — abstraction (replaceable with SignalR)
  SimpleMetricsWebSocketHub.cs   — concurrent broadcast to all connected clients
Models/
  InboundFlowRecord.cs           — readonly struct, 8 fields
  RawPacketBuffer.cs             — readonly struct, array ref + length
  PipelineOptions.cs             — Pipeline config section
  ClickHouseOptions.cs           — ClickHouse config section
wwwroot/
  index.html + live-dashboard.js — real-time WebSocket dashboard
```

### New: infrastructure

```
infra/clickhouse-init/001-schema.sql   — flows_raw (TTL 14d) + flows_trends_1m
infra/grafana/provisioning/            — datasource + dashboard auto-provisioning
infra/grafana/dashboards/              — NetFlow Traffic: Bps/Pps, Summary, Top Ports
Dockerfile                             — multi-stage sdk → aspnet
docker-compose.yml                     — livepipeline + clickhouse + grafana
.dockerignore                          — excludes **/obj/, **/bin/
```

### Preserved: `legacy/`

```
legacy/NetFlowAnalizer/           — original offline PCAP analyzer (unchanged)
legacy/NetFlowAnalizer.Console/   — CLI for offline analysis (updated project refs)
```

### Shared libraries: `src/`

```
src/NetFlowAnalizer.Core/         — domain interfaces, RFC 3954 models
src/NetFlowAnalizer.Infrastructure/ — NetFlowV9Parser, TemplateCache, PCAP reader
```

---

## How to test

### Full stack (Docker)

```bash
docker compose up --build
```

| Service | URL |
|---|---|
| Live WebSocket dashboard | http://localhost:5000 |
| Grafana | http://localhost:3000 |
| ClickHouse | http://localhost:8123 |
| NetFlow UDP | udp://localhost:2055 |

### Verify data is arriving

```bash
docker exec netflow-clickhouse \
  clickhouse-client --query \
  "SELECT count(), sum(Bytes) FROM netflow.flows_raw"

docker exec netflow-clickhouse \
  clickhouse-client --query \
  "SELECT Timestamp, IPv4NumToString(SrcIp), IPv4NumToString(DstIp), DstPort
   FROM netflow.flows_raw ORDER BY Timestamp DESC LIMIT 5"
```

### Without a router (synthetic load)

See [`docs/LIVEPIPELINE_GUIDE.md § Part 10`](LIVEPIPELINE_GUIDE.md) — a minimal
.NET console app that sends ~5 M synthetic flow records to `udp://127.0.0.1:2055`.

### Local dev (no Docker)

```bash
docker compose up clickhouse grafana
dotnet run --project src/LivePipeline/LivePipeline.csproj
```

---

## Configuration

All settings are environment-variable overridable (`__` = section separator):

```
Pipeline__UdpPort=2055
Pipeline__ParserWorkerCount=8
Pipeline__MetricFlushIntervalMs=1000
ClickHouse__ConnectionString=Host=clickhouse;Port=8123;Database=netflow;User=default;Password=
```

Full reference: [`docs/architecture.md — Configuration`](architecture.md#configuration-reference)

---

## Not in this PR (future work)

- OpenTelemetry metrics export (dotnet-counters stub already stubbed in `Program.cs`)
- Health check endpoint (`/health`) — commented out in `Program.cs`, ready to enable
- SignalR hub as drop-in replacement for `SimpleMetricsWebSocketHub`
- Per-minute trend rollup surfaced directly on `localhost:5000` REST endpoint
- IPv6 support (current parser handles IPv4 only)

---

## Checklist

- [x] `docker compose up --build` — builds cleanly on Linux container
- [x] Live flows confirmed from MikroTik router (TCP/443, UDP/53 traffic visible in ClickHouse)
- [x] Grafana dashboards auto-provision on first start (no manual config)
- [x] `dotnet build` — 0 errors, 0 warnings
- [x] `.dockerignore` excludes Windows NuGet obj/ cache (fix for Linux build)
- [x] `legacy/` projects still build after ProjectReference path updates
- [x] Architecture documented in `docs/architecture.md`
