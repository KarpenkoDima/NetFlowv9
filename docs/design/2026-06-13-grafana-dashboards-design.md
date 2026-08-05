# Grafana Dashboards Design

## Goal

Add a Grafana instance to the local docker-compose stack that visualizes
NetFlow traffic data already persisted to ClickHouse (`flows_raw`,
`flows_trends_1m`), with zero manual setup after `docker compose up`.

## Scope

- New `grafana` service in `docker-compose.yml`, networked with the existing
  `clickhouse` service.
- Auto-provisioned ClickHouse datasource (via `grafana-clickhouse-datasource`
  plugin).
- One pre-built dashboard, "NetFlow Traffic", with three panels, provisioned
  from a JSON file checked into the repo.
- Local-dev only: anonymous admin access, no auth, no TLS — consistent with
  the existing ClickHouse setup (no password).

Out of scope (not part of this design):
- Prometheus / OpenTelemetry metrics export from the .NET app (GC, channel
  depths, exceptions). May be a follow-up dashboard later.
- Alerting rules.
- Production hardening (auth, TLS, persistence beyond a local volume).

## Architecture

```
docker-compose.yml
├── clickhouse   (existing)
└── grafana      (new)
     - image: grafana/grafana:latest
     - port 3000:3000
     - env: GF_INSTALL_PLUGINS=grafana-clickhouse-datasource
     - env: GF_AUTH_ANONYMOUS_ENABLED=true / ORG_ROLE=Admin / DISABLE_LOGIN_FORM=true
     - volumes:
         - grafana-data:/var/lib/grafana          (plugin cache, Grafana state)
         - ./grafana/provisioning:/etc/grafana/provisioning
         - ./grafana/dashboards:/var/lib/grafana/dashboards
     - depends_on: clickhouse
```

New volume `grafana-data` alongside the existing `clickhouse-data` volume.

## Provisioning files

### `grafana/provisioning/datasources/clickhouse.yml`

```yaml
apiVersion: 1
datasources:
  - name: ClickHouse-NetFlow
    type: grafana-clickhouse-datasource
    access: proxy
    isDefault: true
    jsonData:
      host: clickhouse
      port: 9000
      defaultDatabase: netflow
    secureJsonData:
      username: default
      password: ""
```

Connects over the ClickHouse native protocol (port 9000), same port already
exposed by the `clickhouse` service in docker-compose.

### `grafana/provisioning/dashboards/dashboard.yml`

```yaml
apiVersion: 1
providers:
  - name: NetFlow
    folder: NetFlow
    type: file
    options:
      path: /var/lib/grafana/dashboards
```

Grafana scans `/var/lib/grafana/dashboards` (mapped to `./grafana/dashboards`)
and loads any JSON dashboards found there into the "NetFlow" folder.

## Dashboard: "NetFlow Traffic" (`grafana/dashboards/netflow-traffic.json`)

Three panels, all driven by the standard Grafana time-range picker via
`$__timeFilter(Timestamp)`.

### Panel A — Bps/pps over time (time series)

Source: `flows_trends_1m` (1-minute rollups written by
`NetFlowMetricAggregator.WriteTrendRowAsync`).

```sql
SELECT Timestamp, BitsPerSecond, PacketsPerSec
FROM netflow.flows_trends_1m
WHERE $__timeFilter(Timestamp)
ORDER BY Timestamp
```

Two series on dual Y axes: `BitsPerSecond` (left), `PacketsPerSec` (right).

### Panel B — Top-10 destination ports by traffic (bar gauge / table)

Source: `flows_raw` (per-flow records written by `NetFlowClickHouseWriter`).

```sql
SELECT DstPort, sum(Bytes) AS TotalBytes, sum(Packets) AS TotalPackets
FROM netflow.flows_raw
WHERE $__timeFilter(Timestamp)
GROUP BY DstPort
ORDER BY TotalBytes DESC
LIMIT 10
```

### Panel C — Summary stats for the selected period (stat panels)

Source: `flows_trends_1m`.

```sql
SELECT
    sum(TotalFlows)   AS Flows,
    sum(TotalBytes)   AS Bytes,
    sum(TotalPackets) AS Packets
FROM netflow.flows_trends_1m
WHERE $__timeFilter(Timestamp)
```

Three stat tiles: total flows, total bytes, total packets over the selected
time range.

## File layout (new/changed files)

```
docker-compose.yml                               (modified: + grafana service, + grafana-data volume)
grafana/
  provisioning/
    datasources/clickhouse.yml                   (new)
    dashboards/dashboard.yml                     (new)
  dashboards/
    netflow-traffic.json                         (new: panels A, B, C)
```

## Testing / verification

- `docker compose up -d` brings up `clickhouse` + `grafana` with no manual
  steps.
- Open `http://localhost:3000` — anonymous admin session, no login screen.
- Datasource "ClickHouse-NetFlow" is present and green ("Save & test" passes)
  without any manual configuration.
- Dashboard "NetFlow Traffic" appears under the "NetFlow" folder with panels
  A, B, C rendering data (once the pipeline has written at least one
  `flows_trends_1m` row and some `flows_raw` rows — can be generated with the
  existing synthetic load generator).
- Changing the dashboard time range updates all three panels via
  `$__timeFilter`.

## Notes / future follow-ups

- Application-level observability (GC/exceptions/channel depth via
  Prometheus + OpenTelemetry) is intentionally out of scope here and would
  be a separate design.
- Anonymous admin access and empty ClickHouse password are local-dev
  conveniences already consistent with the existing `docker-compose.yml` —
  not suitable for any shared/production environment as-is.
