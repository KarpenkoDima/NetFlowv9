# NetFlow v9 Live Pipeline

A high-performance NetFlow v9 collector built with .NET 9, `System.Threading.Channels`, ClickHouse, Grafana and WebSockets.

The application receives NetFlow v9 datagrams over UDP, parses template-based flow records, calculates live traffic metrics, stores flow metadata in ClickHouse and exposes dashboards for network traffic analysis.

## Project status

| Property                         | Current state                                 |
| -------------------------------- | --------------------------------------------- |
| Status                           | Operational internal infrastructure project   |
| Current deployment               | Hospital network                              |
| Current exporters                | 2 MikroTik routers                            |
| Intended deployment profile      | Small trusted networks with up to 5 exporters |
| Protocol                         | NetFlow v9 over UDP                           |
| Current release                  | `v1.0.0`                                      |
| Address family in live analytics | IPv4                                          |
| Historical persistence           | Best effort                                   |

The current deployment receives NetFlow traffic from two MikroTik routers through a shared processing pipeline.

The application is designed for a small installation of up to five exporters. However, the current version does not persist the exporter address and does not provide reliable per-router separation in ClickHouse or Grafana.

The collector processes network-flow metadata only. It does not capture packet payloads, HTTP content, files, credentials or application data.

---

## What the project can do

* Receive live NetFlow v9 datagrams over UDP.
* Parse Template FlowSets and Data FlowSets.
* Cache NetFlow v9 templates.
* Decode IPv4 source and destination addresses.
* Decode source and destination ports.
* Decode protocol numbers.
* Decode byte and packet counters stored as 32-bit or 64-bit values.
* Process parser hot paths with `ReadOnlySpan<byte>` and `BinaryPrimitives`.
* Reuse UDP buffers through `ArrayPool<byte>`.
* Separate receiving, parsing, aggregation and persistence with bounded channels.
* Calculate live traffic, protocol and top-address metrics.
* Broadcast metric snapshots through WebSockets.
* Store raw flow records in ClickHouse.
* Store one-minute traffic trends.
* Apply a retention policy to raw data.
* Provision Grafana dashboards automatically.
* Deploy the full stack with Docker Compose.
* Analyze saved PCAP files through the preserved offline analyzer.

---

## Current operating scope

The project is intended for a controlled internal network rather than internet-facing or multi-tenant operation.

The current hospital installation uses two centrally managed MikroTik routers. The routers are expected to export compatible NetFlow v9 templates.

For the current multi-router deployment, a single parser worker is recommended:

```bash
Pipeline__ParserWorkerCount=1
```

This preserves packet processing order inside the parser pipeline.

It does not provide complete template isolation between exporters. See [Known limitations](#known-limitations) for details.

---

## What's inside

```text
src/LivePipeline/      — live collector and ASP.NET Core dashboard
src/NetFlowAnalizer.*  — shared NetFlow v9 parser components
infra/clickhouse-init/ — ClickHouse schema
infra/grafana/         — Grafana datasource and dashboard provisioning
legacy/                — original offline PCAP analyzer
docs/                  — architecture and development guides
```

---

## Quick start with Docker

The complete stack consists of:

* NetFlow live collector;
* ClickHouse;
* Grafana.

Start it with:

```bash
docker compose up --build
```

| Service                  | Address                 |
| ------------------------ | ----------------------- |
| Live WebSocket dashboard | `http://localhost:5000` |
| Grafana                  | `http://localhost:3000` |
| ClickHouse HTTP endpoint | `http://localhost:8123` |
| NetFlow UDP receiver     | `udp://0.0.0.0:2055`    |

The initial run downloads container images and builds the application. Subsequent builds can reuse Docker layers when project dependencies have not changed.

### Start individual services

```bash
# Infrastructure only
docker compose up clickhouse grafana

# Rebuild and restart the collector
docker compose up --build livepipeline

# Stop containers without deleting data volumes
docker compose stop

# Stop containers and delete all project volumes
docker compose down -v
```

> [!WARNING]
> `docker compose down -v` deletes the ClickHouse data volume. Historical flow data stored in that volume will be lost.

---

## Configure MikroTik RouterOS

Enable Traffic Flow:

```routeros
/ip traffic-flow
set enabled=yes packet-sampling=no
```

Add the collector as a NetFlow v9 target:

```routeros
/ip traffic-flow target
add dst-address=<COLLECTOR_IP> \
    src-address=<ROUTER_MANAGEMENT_IP> \
    port=2055 \
    version=9 \
    v9-template-refresh=20 \
    v9-template-timeout=1m
```

Replace:

* `<COLLECTOR_IP>` with the address of the machine running the collector;
* `<ROUTER_MANAGEMENT_IP>` with the stable management address of the MikroTik router.

Example:

```routeros
/ip traffic-flow target
add dst-address=192.168.10.50 \
    src-address=192.168.10.1 \
    port=2055 \
    version=9 \
    v9-template-refresh=20 \
    v9-template-timeout=1m
```

For a second router:

```routeros
/ip traffic-flow target
add dst-address=192.168.10.50 \
    src-address=192.168.20.1 \
    port=2055 \
    version=9 \
    v9-template-refresh=20 \
    v9-template-timeout=1m
```

Packet sampling should remain disabled because the current collector does not read sampling parameters from Options Template FlowSets and does not compensate traffic counters for sampled exports.

### Firewall

Permit UDP port `2055` only from approved router addresses.

Conceptually:

```text
ALLOW UDP/2055 FROM MikroTik-1
ALLOW UDP/2055 FROM MikroTik-2
DENY  UDP/2055 FROM other hosts
```

The exact firewall configuration depends on the operating system and network topology.

### Other exporters

The parser implements NetFlow v9 rather than a MikroTik-specific protocol. Other NetFlow v9 exporters may work, but the current real deployment and validation were performed with MikroTik RouterOS.

Cisco, Juniper and other exporters may use different templates and fields that are currently skipped by the live parser.

---

## Verify that data is arriving

### Check collector logs

```bash
docker compose logs -f livepipeline
```

### Count stored flows

```bash
docker exec netflow-clickhouse \
  clickhouse-client \
  --query "SELECT count() FROM netflow.flows_raw"
```

### Show the latest flows

```bash
docker exec netflow-clickhouse \
  clickhouse-client \
  --query "
    SELECT
        Timestamp,
        IPv4NumToString(SrcIp) AS Source,
        IPv4NumToString(DstIp) AS Destination,
        SrcPort,
        DstPort,
        Protocol,
        Bytes,
        Packets
    FROM netflow.flows_raw
    ORDER BY Timestamp DESC
    LIMIT 10"
```

### Show one-minute trends

```bash
docker exec netflow-clickhouse \
  clickhouse-client \
  --query "
    SELECT
        Timestamp,
        TotalFlows,
        TotalBytes,
        TotalPackets,
        BitsPerSecond,
        PacketsPerSec
    FROM netflow.flows_trends_1m
    ORDER BY Timestamp DESC
    LIMIT 10"
```

If the collector receives UDP datagrams but no rows appear in ClickHouse, inspect:

```bash
docker compose logs livepipeline
docker compose logs clickhouse
```

---

## Architecture

```text
[Router / NetFlow v9 exporter]
                │
                │ UDP :2055
                ▼
┌─────────────────────────────────────────────┐
│ NetFlowUdpReceiver                         │
│ BackgroundService #1                       │
│                                             │
│ Socket.ReceiveAsync                        │
│ ArrayPool<byte>                            │
└─────────────────────┬───────────────────────┘
                      │
                      │ Channel<RawPacketBuffer>
                      │ bounded, Wait
                      ▼
┌─────────────────────────────────────────────┐
│ NetFlowParserWorkerPool                    │
│ BackgroundService #2                       │
│                                             │
│ NetFlow v9 header parsing                  │
│ Template FlowSet parsing                   │
│ Data FlowSet parsing                       │
└─────────────────────┬───────────────────────┘
                      │
                      │ Channel<InboundFlowRecord>
                      │ bounded, Wait
                      ▼
┌─────────────────────────────────────────────┐
│ NetFlowMetricAggregator                    │
│ BackgroundService #3                       │
│                                             │
│ Live counters                              │
│ Protocol statistics                        │
│ Top source and destination addresses       │
└───────────────┬───────────────────┬─────────┘
                │                   │
                │                   │ best-effort persistence channel
                ▼                   ▼
┌───────────────────────┐   ┌──────────────────────────────┐
│ WebSocket             │   │ NetFlowClickHouseWriter      │
│ /ws/metrics           │   │ BackgroundService #4         │
│                       │   │                              │
│ Live browser metrics  │   │ Batched bulk inserts         │
└───────────────────────┘   └──────────────┬───────────────┘
                                           │
                                           ▼
                                     ┌──────────────┐
                                     │ ClickHouse   │
                                     └──────┬───────┘
                                            │
                                            ▼
                                     ┌──────────────┐
                                     │ Grafana      │
                                     └──────────────┘
```

### Channel strategy

The first two channels use:

```text
BoundedChannelFullMode.Wait
```

This applies bounded backpressure inside the application:

```text
UDP receiver → parser → aggregator
```

It does not guarantee lossless NetFlow delivery.

NetFlow v9 uses UDP, so datagrams can be lost:

* between the router and collector;
* in network equipment;
* in the operating-system receive buffer;
* during collector overload;
* during process restarts.

The persistence channel uses:

```text
BoundedChannelFullMode.DropWrite
```

This prevents an unavailable or slow ClickHouse instance from blocking the live metrics pipeline.

Historical storage is therefore best effort rather than guaranteed.

---

## Performance approach

The parser hot path is designed to minimize managed allocations.

Used techniques include:

* `ReadOnlySpan<byte>`;
* `BinaryPrimitives`;
* `ArrayPool<byte>`;
* bounded `Channel<T>`;
* value-type flow records;
* batched ClickHouse inserts;
* source-generated JSON serialization;
* reusable output buffers;
* `stackalloc` for small temporary collections.

The parser hot path is allocation-conscious and may be zero-allocation for supported records.

The complete application is not fully zero-allocation. Allocations still occur in infrastructure components, WebSocket broadcasting, database integration, logging and dashboard serialization.

---

## Configuration

Configuration values can be overridden through environment variables.

Double underscores represent nested configuration sections:

```bash
Pipeline__UdpPort=2055
Pipeline__ParserWorkerCount=1
Pipeline__MetricFlushIntervalMs=1000

ClickHouse__ConnectionString=Host=clickhouse;Port=8123;Database=netflow;User=default;Password=
```

The complete configuration is stored in:

```text
src/LivePipeline/appsettings.json
```

### Recommended current settings

For the current installation with two MikroTik exporters:

```bash
Pipeline__UdpPort=2055
Pipeline__ParserWorkerCount=1
Pipeline__MetricFlushIntervalMs=1000
```

Do not increase the parser worker count merely because several routers send traffic to the collector.

The current parser worker pool does not shard packets by exporter. Multiple workers may process a Data FlowSet before the Template FlowSet required to decode it.

---

## Grafana dashboards

Grafana provisioning files are stored in:

```text
infra/grafana/provisioning/
```

The included dashboard provides:

| Panel                 | Source            | Description                                     |
| --------------------- | ----------------- | ----------------------------------------------- |
| Bps / Pps             | `flows_trends_1m` | Approximate exported traffic rates              |
| Summary               | `flows_trends_1m` | Flows, bytes and packets for the selected range |
| Top destination ports | `flows_raw`       | Destination ports ranked by byte volume         |

Open:

```text
http://localhost:3000
```

### Security warning

The bundled Docker configuration enables development-oriented Grafana settings.

Do not expose the default configuration directly to:

* the internet;
* a guest network;
* a general hospital user VLAN;
* an untrusted administrative network.

Before broader deployment:

* disable anonymous administrator access;
* enable authenticated Grafana users;
* create non-default ClickHouse users;
* set non-empty passwords;
* restrict ClickHouse ports;
* place the dashboard behind HTTPS;
* restrict access through firewall rules.

### Timezone

Flow timestamps are stored in UTC.

Grafana and the browser can convert UTC timestamps to the user's local timezone when the datasource and dashboard are configured correctly.

---

## Synthetic load

The project documentation contains a synthetic NetFlow generator that can be used when a physical router is unavailable.

Create a console project:

```bash
mkdir synload
cd synload
dotnet new console
```

Use the generator described in:

```text
docs/LIVEPIPELINE_GUIDE.md
```

Run it with:

```bash
dotnet run
```

The generator sends synthetic NetFlow v9 templates and data records to:

```text
udp://127.0.0.1:2055
```

Synthetic traffic is intended for functional and development testing. It does not replace load tests with real MikroTik templates and realistic traffic distributions.

---

## Local development without containerizing the collector

Start ClickHouse and Grafana:

```bash
docker compose up clickhouse grafana
```

Run the collector from source:

```bash
dotnet run --project src/LivePipeline/LivePipeline.csproj
```

The default local configuration connects to ClickHouse through:

```text
localhost:8123
```

Open the live dashboard:

```text
http://localhost:5000
```

---

## Project structure

```text
.
├── src/
│   ├── LivePipeline/
│   │   ├── Aggregation/
│   │   ├── Models/
│   │   ├── Parsing/
│   │   ├── Persistence/
│   │   ├── Pipeline/
│   │   └── WebSocket/
│   │
│   ├── NetFlowAnalizer.Core/
│   │   └── shared protocol models and interfaces
│   │
│   └── NetFlowAnalizer.Infrastructure/
│       └── parser and template-cache implementation
│
├── legacy/
│   ├── NetFlowAnalizer/
│   │   └── original offline PCAP analyzer
│   │
│   └── NetFlowAnalizer.Console/
│       └── command-line offline analyzer
│
├── infra/
│   ├── clickhouse-init/
│   │   └── ClickHouse schema
│   │
│   └── grafana/
│       └── datasource and dashboard provisioning
│
├── docs/
│   ├── architecture.md
│   ├── GUIDE.md
│   ├── GRAFANA_GUIDE.md
│   ├── LIVEPIPELINE_GUIDE.md
│   └── ROADMAP.md
│
├── CHANGELOG.md
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Known limitations

### Exporter identity is not persisted

The UDP receiver currently processes the datagram payload without preserving the sender endpoint.

As a result:

* the exporter IP address is not stored in ClickHouse;
* Grafana cannot filter flows reliably by router;
* the collector cannot report a separate last-seen time for each exporter;
* traffic from multiple routers is aggregated into one shared view.

### Template cache is not isolated by exporter

The current template-cache identity is based on:

```text
SourceId + TemplateId
```

A complete multi-exporter implementation should use:

```text
ExporterAddress + SourceId + TemplateId
```

If two routers use the same source and template identifiers for different structures, one template may replace another.

The current deployment assumes centrally controlled MikroTik routers with compatible export templates.

### Packet ordering with several parser workers

Multiple parser workers consume packets from one shared channel.

A Data FlowSet may theoretically be processed before the Template FlowSet needed to decode it.

For the current installation:

```bash
Pipeline__ParserWorkerCount=1
```

is recommended.

### UDP is best effort

The collector cannot guarantee delivery of every NetFlow packet.

UDP does not provide:

* acknowledgements;
* retransmission;
* duplicate suppression;
* guaranteed ordering.

### Sequence-gap detection is not implemented

The NetFlow v9 sequence number is parsed but not currently tracked per exporter.

The collector therefore does not report:

* missing export packets;
* exporter restarts;
* out-of-order packets;
* packet-loss percentage.

### Limited live field set

The live parser currently extracts:

* `IN_BYTES`;
* `IN_PKTS`;
* `PROTOCOL`;
* `L4_SRC_PORT`;
* `L4_DST_PORT`;
* `IPV4_SRC_ADDR`;
* `IPV4_DST_ADDR`.

Other fields are skipped.

The current live pipeline does not expose:

* IPv6 addresses;
* input and output interface indexes;
* TCP flags;
* Type of Service;
* autonomous-system numbers;
* next-hop addresses;
* VLAN identifiers;
* exact flow start and end timestamps.

### Options templates and sampling

Options Template FlowSets are ignored.

The collector does not read:

* sampling interval;
* sampling algorithm;
* exporter metadata;
* interface metadata.

Traffic counters are not corrected for sampled NetFlow.

### Approximate traffic rate

The displayed Bps and Pps values are derived from flow records exported during an aggregation interval.

They should be treated as approximate exported-flow rates, not as exact real-time interface utilization.

For exact link utilization, use:

* MikroTik interface counters;
* SNMP;
* RouterOS API;
* another network telemetry source.

### Best-effort persistence

A slow or unavailable ClickHouse server does not stop the live WebSocket pipeline.

Under sustained database failure or overload, historical records may be dropped.

The current release does not provide:

* a durable local queue;
* write-ahead logging;
* replay after restart;
* exactly-once delivery.

### Automated testing

The repository does not yet include a complete automated test suite for:

* malformed packets;
* multiple exporters;
* template replacement;
* channel saturation;
* packet ordering;
* ClickHouse outages;
* graceful shutdown;
* parser fuzzing;
* end-to-end Docker deployment.

The project should not be treated as billing-grade or forensic-grade traffic accounting software.

---

## What this project is not

This project is not:

* a replacement for Wireshark or packet capture;
* a complete SIEM;
* an intrusion-prevention system;
* a billing-grade traffic-accounting platform;
* an IPFIX collector;
* an sFlow collector;
* a multi-tenant NetFlow service;
* a source of exact interface utilization.

Its main purpose is internal network visibility:

* top talkers;
* traffic directions;
* destination ports;
* protocol distribution;
* historical flow investigation;
* approximate traffic trends.

---

## Documentation

| Document                                                   | Description                                                  |
| ---------------------------------------------------------- | ------------------------------------------------------------ |
| [`docs/architecture.md`](docs/architecture.md)             | Pipeline architecture and design decisions                   |
| [`docs/LIVEPIPELINE_GUIDE.md`](docs/LIVEPIPELINE_GUIDE.md) | Channels, buffer pooling, WebSockets, ClickHouse and Grafana |
| [`docs/GUIDE.md`](docs/GUIDE.md)                           | Detailed NetFlow v9 parser guide                             |
| [`docs/GRAFANA_GUIDE.md`](docs/GRAFANA_GUIDE.md)           | Grafana installation and dashboard usage                     |
| [`docs/ROADMAP.md`](docs/ROADMAP.md)                       | Project development history                                  |

---

## References

* [RFC 3954 — Cisco Systems NetFlow Services Export Version 9](https://www.rfc-editor.org/rfc/rfc3954)
* [System.Threading.Channels](https://learn.microsoft.com/dotnet/core/extensions/channels)
* [ArrayPool<T>](https://learn.microsoft.com/dotnet/api/system.buffers.arraypool-1)
* [ClickHouse MergeTree](https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/mergetree)
* [Grafana ClickHouse datasource](https://github.com/grafana/clickhouse-datasource)

---

## License

This repository does not currently declare an open-source license.

Unless a license file is added, the source code is publicly visible but no automatic permission is granted to copy, modify, redistribute or use it in another project.
