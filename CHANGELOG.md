# Changelog

All notable changes to this project are documented here.

---

## [1.0.0] — 2026-08-03

First production release. Replaces the offline PCAP analyzer with a live
zero-allocation NetFlow v9 pipeline backed by ClickHouse and Grafana.

### Added

**Live pipeline — `src/LivePipeline/`**

- `NetFlowUdpReceiver` — UDP socket receiver using `Socket.ReceiveAsync(Memory<byte>)` and `ArrayPool<byte>` for zero-copy datagram capture.
- `NetFlowParserWorkerPool` — pool of N parallel workers (default: CPU count) that parse NetFlow v9 packets over `Span<byte>` with no heap allocation; releases `ArrayPool` buffers after parse.
- `NetFlowMetricAggregator` — double-buffered `MetricBucket` with lock-free `Interlocked` counters and `ConcurrentDictionary` per-IP / per-protocol accumulators; publishes JSON snapshots every second.
- `NetFlowClickHouseWriter` — best-effort BackgroundService that batches flow records (up to 50 000 rows) into ClickHouse bulk inserts with exponential-backoff retry (max 2 min budget).
- `SimpleMetricsWebSocketHub` — broadcasts `MetricSnapshot` JSON to all connected WebSocket clients at `/ws/metrics`.
- `LiveNetFlowV9Parser` — stateless RFC 3954 parser; shared across all worker threads.
- `MetricBucket.ExtractTop10()` — stackalloc min-heap, O(n log 10), no LINQ.
- Live WebSocket dashboard at `http://localhost:5000` showing real-time bps, pps, flow count, top IPs, and protocols.

**ClickHouse persistence**

- `flows_raw` table — per-flow records with DoubleDelta+ZSTD codecs, 14-day TTL.
- `flows_trends_1m` table — per-minute rollups (BitsPerSecond, PacketsPerSec, FlowCount, TotalBytes).
- `MinuteTrendAccumulator` — rolls up per-second snapshots into 1-minute rows.
- `IClickHouseConnectionFactory` with `IHttpClientFactory` + `SocketsHttpHandler` pooling; `AutomaticDecompression = All` required for ClickHouse gzip responses.

**Infrastructure**

- Multi-stage `Dockerfile` (`sdk:9.0` publish → `aspnet:9.0` runtime).
- `docker-compose.yml` — `livepipeline` + `clickhouse` + `grafana` as one stack.
- `.dockerignore` — excludes `**/obj/` and `**/bin/` to prevent Windows NuGet path metadata from breaking the Linux container build.
- `infra/clickhouse-init/001-schema.sql` — schema applied automatically on first container start.

**Grafana**

- Auto-provisioned ClickHouse datasource via `infra/grafana/provisioning/`.
- "NetFlow Traffic" dashboard with three panels: Bps/Pps time series, summary stat, top 10 destination ports.

**System.Threading.Channels backpressure**

| Channel | Bound | Mode |
|---|---|---|
| Raw packets (UDP → Parser) | 1 024 | `Wait` |
| Parsed records (Parser → Aggregator) | 16 384 | `Wait` |
| Persistence (Aggregator → ClickHouseWriter) | 100 000 | `DropWrite` |

**Documentation**

- `README.md` — quick start, router config (MikroTik / Cisco), architecture diagram.
- `docs/architecture.md` — full design: data flow, backpressure table, MetricBucket internals, ClickHouse schema, WebSocket protocol, configuration reference.
- `docs/LIVEPIPELINE_GUIDE.md` — 12-part development narrative (Russian).
- `docs/GRAFANA_GUIDE.md` — ClickHouse SQL reference for NetFlow panels.
- `docs/pr-description.md` — PR description with commit table, technical decisions, test checklist.

### Changed

- Renamed `NetFlowv9.sln` → `NetFlowAnalizer.sln`.
- Reorganized project layout:
  - `NetFlowAnalizer.Core/` → `src/NetFlowAnalizer.Core/`
  - `NetFlowAnalizer.Infrastructure/` → `src/NetFlowAnalizer.Infrastructure/`
  - `NetFlowv9/` → `legacy/NetFlowAnalizer/`
  - `clickhouse-init/` → `infra/clickhouse-init/`
  - `grafana/` → `infra/grafana/`
  - `GUIDE.md`, `ROADMAP.md` → `docs/`
- Added `graphify-out/` to `.gitignore`.

### Preserved

- `legacy/NetFlowAnalizer/` — original offline PCAP analyzer (unchanged).
- `legacy/NetFlowAnalizer.Console/` — CLI for offline analysis (ProjectReference paths updated).
- `src/NetFlowAnalizer.Core/` and `src/NetFlowAnalizer.Infrastructure/` — shared parser and domain models, now referenced by both legacy and live pipeline.

---

## [0.x] — 2026-06 (pre-release)

Initial offline NetFlow v9 analyzer: PCAP file reader, template cache,
RFC 3954 parser, JSON exporter. Not tagged; preserved in `legacy/`.
