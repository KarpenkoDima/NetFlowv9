# NetFlow v9 Live Pipeline

Live NetFlow v9 pipeline built on .NET 9: receives UDP traffic from a router in real time, parses it with zero heap allocation on the hot path, stores flows in ClickHouse, and exposes live metrics via WebSocket and Grafana dashboards.

## What's inside

```
src/LivePipeline/      — main live pipeline (ASP.NET Core 9, BackgroundService × 4)
src/NetFlowAnalizer.*  — shared parser core (RFC 3954)
infra/clickhouse-init/ — DB schema (flows_raw, flows_trends_1m)
infra/grafana/         — auto-provisioned datasource + dashboard
```

---

## Quick start with Docker

The full stack — pipeline + ClickHouse + Grafana — runs with a single command:

```bash
docker compose up --build
```

| Service | URL |
|---|---|
| Live dashboard (WebSocket) | http://localhost:5000 |
| Grafana | http://localhost:3000 |
| ClickHouse HTTP | http://localhost:8123 |
| NetFlow UDP receiver | udp://localhost:2055 |

> First run downloads base images and compiles the project (~2–3 min).  
> Subsequent starts use the cached layer — only changed `.cs` files trigger a rebuild.

### Start individual services

```bash
# Infrastructure only (ClickHouse + Grafana)
docker compose up clickhouse grafana

# Rebuild and restart only the pipeline (after code changes)
docker compose up --build livepipeline

# Stop everything, keep volumes
docker compose stop

# Full teardown including volumes
docker compose down -v
```

---

## Configure your router to send NetFlow

### MikroTik RouterOS

```
/ip traffic-flow
set enabled=yes

/ip traffic-flow target
add dst-address=<YOUR_COLLECTOR_IP> port=2055 version=9
```

Replace `<YOUR_COLLECTOR_IP>` with the host running `docker compose up`.

### Cisco IOS

```
ip flow-export destination <YOUR_COLLECTOR_IP> 2055
ip flow-export version 9
ip flow-export source <INTERFACE>

interface <INTERFACE>
 ip flow ingress
```

### Juniper / other vendors

Point your NetFlow v9 exporter to `<YOUR_COLLECTOR_IP>:2055/udp`.

> **Behind NAT?** If the collector is on a different subnet, make sure UDP/2055 is forwarded to the Docker host.

---

## Verify data is arriving

```bash
# Check how many flows are in ClickHouse
docker exec netflow-clickhouse \
  clickhouse-client --query "SELECT count() FROM netflow.flows_raw"

# Last 5 flows
docker exec netflow-clickhouse \
  clickhouse-client --query \
  "SELECT Timestamp, IPv4NumToString(SrcIp), IPv4NumToString(DstIp), DstPort, Protocol
   FROM netflow.flows_raw ORDER BY Timestamp DESC LIMIT 5"

# Bps/Pps from 1-minute trends
docker exec netflow-clickhouse \
  clickhouse-client --query \
  "SELECT Timestamp, BitsPerSecond, PacketsPerSec
   FROM netflow.flows_trends_1m ORDER BY Timestamp DESC LIMIT 10"
```

---

## Architecture

```
[Router / NetFlow exporter]
        │ UDP :2055
        ▼
  NetFlowUdpReceiver      BackgroundService #1 — Socket.ReceiveAsync + ArrayPool
        │ Channel<RawPacketBuffer>  Bounded(1024), backpressure=Wait
        ▼
  NetFlowParserWorkerPool BackgroundService #2 — N parallel workers, zero-alloc parser
        │ Channel<InboundFlowRecord> Bounded(16384), backpressure=Wait
        ▼
  NetFlowMetricAggregator BackgroundService #3 — 1-second buckets, double-buffered
        │                         │ Channel<InboundFlowRecord> DropWrite (best-effort)
        ▼                         ▼
  WebSocket /ws/metrics    NetFlowClickHouseWriter  BackgroundService #4
  (live dashboard)         batched bulk insert → flows_raw + flows_trends_1m
                                    │
                                    ▼
                               ClickHouse ← Grafana dashboards
```

**Backpressure strategy:**
- Channel 1 & 2 use `Wait` — parser and aggregator always see all packets, slow consumer causes natural backpressure to the UDP kernel buffer.
- Channel 3 uses `DropWrite` — ClickHouse being slow never blocks the live WebSocket feed.

---

## Configuration

Override any setting via environment variable (`__` = section separator):

```bash
# docker-compose or shell
Pipeline__UdpPort=2055
Pipeline__ParserWorkerCount=8
Pipeline__MetricFlushIntervalMs=1000
ClickHouse__ConnectionString=Host=clickhouse;Port=8123;Database=netflow;User=default;Password=
```

Full options live in [`src/LivePipeline/appsettings.json`](src/LivePipeline/appsettings.json).

---

## Grafana dashboards

Grafana auto-provisions at startup from `infra/grafana/provisioning/`.  
Open http://localhost:3000 — no login required, anonymous admin.

Dashboard **«NetFlow Traffic»** has three panels:

| Panel | Source table | Shows |
|---|---|---|
| Bps / Pps | `flows_trends_1m` | Bits per second + packets per second, timeseries |
| Summary | `flows_trends_1m` | Total flows, bytes, packets for the selected range |
| Top 10 Dst Ports | `flows_raw` | Ports ranked by byte volume |

> **Timezone:** the datasource is configured with `timezone: UTC`. Make sure your browser timezone is set correctly so Grafana converts timestamps to local time.

---

## Synthetic load (for testing without a router)

Build and run the minimal generator below to send 90 seconds of fake NetFlow to localhost:

```bash
mkdir synload && cd synload
dotnet new console
```

Replace `Program.cs` with the generator from [`docs/LIVEPIPELINE_GUIDE.md § Part 10`](docs/LIVEPIPELINE_GUIDE.md) and run:

```bash
dotnet run
```

This sends ~5–6 M flow records to `udp://127.0.0.1:2055` and populates all three Grafana panels with real data.

---

## Local development (without Docker)

```bash
# 1. Infrastructure only
docker compose up clickhouse grafana

# 2. Pipeline from source
dotnet run --project src/LivePipeline/LivePipeline.csproj
```

The pipeline connects to `localhost:8123` (default `appsettings.json`).  
Open http://localhost:5000 for the live WebSocket dashboard.

---

## Project structure

```
.
├── src/
│   ├── LivePipeline/               main project
│   ├── NetFlowAnalizer.Core/       shared models + interfaces (RFC 3954)
│   └── NetFlowAnalizer.Infrastructure/ shared parser + template cache
├── legacy/
│   ├── NetFlowAnalizer/            offline PCAP analyzer (superseded)
│   └── NetFlowAnalizer.Console/    CLI for the offline analyzer
├── infra/
│   ├── clickhouse-init/            SQL schema applied on first container start
│   └── grafana/                    datasource + dashboard provisioning
├── docs/
│   ├── GUIDE.md                    comprehensive guide to the offline analyzer
│   ├── LIVEPIPELINE_GUIDE.md       comprehensive guide to LivePipeline
│   └── ROADMAP.md                  project history and decisions
├── Dockerfile
└── docker-compose.yml
```

---

## Documentation

| Document | What it covers |
|---|---|
| [docs/LIVEPIPELINE_GUIDE.md](docs/LIVEPIPELINE_GUIDE.md) | How LivePipeline was built: Channels, ArrayPool, ClickHouse, Grafana |
| [docs/GUIDE.md](docs/GUIDE.md) | Deep-dive into the NetFlow v9 parser (offline analyzer, 20 chapters) |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phase-by-phase project history |

---

## References

- [RFC 3954 — Cisco Systems NetFlow Services Export Version 9](https://www.rfc-editor.org/rfc/rfc3954)
- [ClickHouse MergeTree](https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/mergetree)
- [grafana-clickhouse-datasource](https://github.com/grafana/clickhouse-datasource)
