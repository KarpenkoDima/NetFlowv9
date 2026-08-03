# Grafana Dashboards Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Grafana service to the docker-compose stack with an
auto-provisioned ClickHouse datasource and a pre-built "NetFlow Traffic"
dashboard (3 panels) reading from the existing `flows_raw` /
`flows_trends_1m` tables — zero manual setup after `docker compose up`.

**Architecture:** New `grafana` service added to `docker-compose.yml`,
networked with the existing `clickhouse` service. Grafana provisioning
(datasource + dashboard provider) is mounted from `./grafana/provisioning`,
and the dashboard JSON itself from `./grafana/dashboards`. Per the design
spec, this is local-dev only: anonymous admin access, no auth, no TLS.

**Tech Stack:** Docker Compose, Grafana (`grafana/grafana:latest`),
`grafana-clickhouse-datasource` plugin, ClickHouse (existing service).

**Spec:** `docs/superpowers/specs/2026-06-13-grafana-dashboards-design.md`

---

## File Structure

```
docker-compose.yml                               (modified)
grafana/
  provisioning/
    datasources/clickhouse.yml                   (new)
    dashboards/dashboard.yml                     (new)
  dashboards/
    netflow-traffic.json                         (new)
```

---

### Task 1: Add Grafana service to docker-compose.yml

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Add the `grafana` service and `grafana-data` volume**

Current `docker-compose.yml`:

```yaml
services:
  clickhouse:
    image: clickhouse/clickhouse-server:latest #24.8
    container_name: netflow-clickhouse
    ports:
      - "8123:8123"
      - "9000:9000"
    environment:
      - CLICKHOUSE_DB=netflow
      - CLICKHOUSE_USER=default
      - CLICKHOUSE_PASSWORD=
      - CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1
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

Replace its full contents with:

```yaml
services:
  clickhouse:
    image: clickhouse/clickhouse-server:latest #24.8
    container_name: netflow-clickhouse
    ports:
      - "8123:8123"
      - "9000:9000"
    environment:
      - CLICKHOUSE_DB=netflow
      - CLICKHOUSE_USER=default
      - CLICKHOUSE_PASSWORD=
      - CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1
    volumes:
      - clickhouse-data:/var/lib/clickhouse
      - ./clickhouse-init:/docker-entrypoint-initdb.d
    ulimits:
      nofile:
        soft: 262144
        hard: 262144

  grafana:
    image: grafana/grafana:latest
    container_name: netflow-grafana
    ports:
      - "3000:3000"
    environment:
      - GF_INSTALL_PLUGINS=grafana-clickhouse-datasource
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
      - GF_AUTH_DISABLE_LOGIN_FORM=true
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards
    depends_on:
      - clickhouse

volumes:
  clickhouse-data:
  grafana-data:
```

- [ ] **Step 2: Commit**

```bash
git add docker-compose.yml
git commit -m "Add Grafana service to docker-compose stack"
```

---

### Task 2: Provision ClickHouse datasource

**Files:**
- Create: `grafana/provisioning/datasources/clickhouse.yml`

- [ ] **Step 1: Create the datasource provisioning file**

```yaml
apiVersion: 1
datasources:
  - name: ClickHouse-NetFlow
    uid: clickhouse-netflow
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

The fixed `uid: clickhouse-netflow` lets the dashboard JSON in Task 4
reference this datasource directly without a UID lookup.

- [ ] **Step 2: Commit**

```bash
git add grafana/provisioning/datasources/clickhouse.yml
git commit -m "Provision ClickHouse datasource for Grafana"
```

---

### Task 3: Provision dashboard file-provider

**Files:**
- Create: `grafana/provisioning/dashboards/dashboard.yml`

- [ ] **Step 1: Create the dashboard provider file**

```yaml
apiVersion: 1
providers:
  - name: NetFlow
    folder: NetFlow
    type: file
    options:
      path: /var/lib/grafana/dashboards
```

- [ ] **Step 2: Commit**

```bash
git add grafana/provisioning/dashboards/dashboard.yml
git commit -m "Provision dashboard file-provider for Grafana"
```

---

### Task 4: Create "NetFlow Traffic" dashboard (3 panels)

**Files:**
- Create: `grafana/dashboards/netflow-traffic.json`

- [ ] **Step 1: Create the dashboard JSON**

```json
{
  "annotations": {
    "list": [
      {
        "builtIn": 1,
        "datasource": { "type": "grafana", "uid": "-- Grafana --" },
        "enable": true,
        "hide": true,
        "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts",
        "type": "dashboard"
      }
    ]
  },
  "editable": true,
  "fiscalYearStartMonth": 0,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "panels": [
    {
      "datasource": { "type": "grafana-clickhouse-datasource", "uid": "clickhouse-netflow" },
      "fieldConfig": {
        "defaults": {
          "color": { "mode": "palette-classic" },
          "custom": {
            "axisCenteredZero": false,
            "axisColorMode": "text",
            "axisLabel": "",
            "axisPlacement": "auto",
            "drawStyle": "line",
            "fillOpacity": 10,
            "lineWidth": 1,
            "pointSize": 5,
            "showPoints": "never"
          },
          "unit": "short"
        },
        "overrides": [
          {
            "matcher": { "id": "byName", "options": "BitsPerSecond" },
            "properties": [
              { "id": "unit", "value": "bps" },
              { "id": "custom.axisPlacement", "value": "left" }
            ]
          },
          {
            "matcher": { "id": "byName", "options": "PacketsPerSec" },
            "properties": [
              { "id": "unit", "value": "pps" },
              { "id": "custom.axisPlacement", "value": "right" }
            ]
          }
        ]
      },
      "gridPos": { "h": 8, "w": 24, "x": 0, "y": 0 },
      "id": 1,
      "options": {
        "legend": { "calcs": [], "displayMode": "list", "placement": "bottom", "showLegend": true },
        "tooltip": { "mode": "multi", "sort": "none" }
      },
      "targets": [
        {
          "datasource": { "type": "grafana-clickhouse-datasource", "uid": "clickhouse-netflow" },
          "format": 0,
          "queryType": "sql",
          "rawSql": "SELECT Timestamp, BitsPerSecond, PacketsPerSec FROM netflow.flows_trends_1m WHERE $__timeFilter(Timestamp) ORDER BY Timestamp",
          "refId": "A"
        }
      ],
      "title": "Bps / Pps Over Time",
      "type": "timeseries"
    },
    {
      "datasource": { "type": "grafana-clickhouse-datasource", "uid": "clickhouse-netflow" },
      "fieldConfig": {
        "defaults": {
          "color": { "mode": "thresholds" },
          "custom": { "align": "auto", "cellOptions": { "type": "auto" } },
          "mappings": [],
          "thresholds": { "mode": "absolute", "steps": [ { "color": "green", "value": null } ] }
        },
        "overrides": [
          {
            "matcher": { "id": "byName", "options": "Bytes" },
            "properties": [ { "id": "unit", "value": "bytes" } ]
          }
        ]
      },
      "gridPos": { "h": 4, "w": 24, "x": 0, "y": 8 },
      "id": 2,
      "options": {
        "colorMode": "value",
        "graphMode": "area",
        "justifyMode": "auto",
        "orientation": "auto",
        "reduceOptions": { "calcs": ["lastNotNull"], "fields": "", "values": false },
        "textMode": "auto"
      },
      "targets": [
        {
          "datasource": { "type": "grafana-clickhouse-datasource", "uid": "clickhouse-netflow" },
          "format": 1,
          "queryType": "sql",
          "rawSql": "SELECT sum(TotalFlows) AS Flows, sum(TotalBytes) AS Bytes, sum(TotalPackets) AS Packets FROM netflow.flows_trends_1m WHERE $__timeFilter(Timestamp)",
          "refId": "A"
        }
      ],
      "title": "Summary (selected period)",
      "type": "stat"
    },
    {
      "datasource": { "type": "grafana-clickhouse-datasource", "uid": "clickhouse-netflow" },
      "fieldConfig": {
        "defaults": {
          "custom": { "align": "auto", "cellOptions": { "type": "auto" }, "filterable": true },
          "mappings": [],
          "thresholds": { "mode": "absolute", "steps": [ { "color": "green", "value": null } ] }
        },
        "overrides": [
          {
            "matcher": { "id": "byName", "options": "TotalBytes" },
            "properties": [ { "id": "unit", "value": "bytes" } ]
          }
        ]
      },
      "gridPos": { "h": 8, "w": 24, "x": 0, "y": 12 },
      "id": 3,
      "options": {
        "cellHeight": "sm",
        "footer": { "countRows": false, "fields": "", "reducer": ["sum"], "show": false },
        "showHeader": true,
        "sortBy": [ { "desc": true, "displayName": "TotalBytes" } ]
      },
      "targets": [
        {
          "datasource": { "type": "grafana-clickhouse-datasource", "uid": "clickhouse-netflow" },
          "format": 1,
          "queryType": "sql",
          "rawSql": "SELECT DstPort, sum(Bytes) AS TotalBytes, sum(Packets) AS TotalPackets FROM netflow.flows_raw WHERE $__timeFilter(Timestamp) GROUP BY DstPort ORDER BY TotalBytes DESC LIMIT 10",
          "refId": "A"
        }
      ],
      "title": "Top 10 Destination Ports",
      "type": "table"
    }
  ],
  "refresh": "30s",
  "schemaVersion": 39,
  "tags": ["netflow"],
  "templating": { "list": [] },
  "time": { "from": "now-1h", "to": "now" },
  "timepicker": {},
  "timezone": "browser",
  "title": "NetFlow Traffic",
  "uid": "netflow-traffic",
  "version": 1,
  "weekStart": ""
}
```

Panel layout:
- **Panel 1 — "Bps / Pps Over Time"**: time series, dual Y-axis
  (`BitsPerSecond` left in `bps`, `PacketsPerSec` right in `pps`), source
  `flows_trends_1m`.
- **Panel 2 — "Summary (selected period)"**: stat panel showing
  `Flows`/`Bytes`/`Packets` totals over the selected time range, source
  `flows_trends_1m`.
- **Panel 3 — "Top 10 Destination Ports"**: table of top 10 `DstPort` by
  `TotalBytes`/`TotalPackets`, source `flows_raw`.

- [ ] **Step 2: Validate the JSON is well-formed**

Run:

```bash
python3 -c "import json; json.load(open('grafana/dashboards/netflow-traffic.json'))" && echo "VALID JSON"
```

Expected: `VALID JSON`

- [ ] **Step 3: Commit**

```bash
git add grafana/dashboards/netflow-traffic.json
git commit -m "Add NetFlow Traffic dashboard (bps/pps, summary, top ports)"
```

---

### Task 5: End-to-end verification

**Files:** none (verification only)

- [ ] **Step 1: Bring up the stack**

```bash
docker compose up -d
```

Expected: both `netflow-clickhouse` and `netflow-grafana` containers report
`Up` / `running` (check with `docker compose ps`). Grafana may take ~30-60s
to download and install the `grafana-clickhouse-datasource` plugin on first
start — wait for it before the next steps.

- [ ] **Step 2: Confirm Grafana is reachable without login**

```bash
curl -s http://localhost:3000/api/health
```

Expected: JSON response with `"database": "ok"`.

- [ ] **Step 3: Confirm the ClickHouse datasource is provisioned**

```bash
curl -s http://localhost:3000/api/datasources/uid/clickhouse-netflow
```

Expected: JSON response with `"name": "ClickHouse-NetFlow"`,
`"type": "grafana-clickhouse-datasource"`, `"uid": "clickhouse-netflow"`.

- [ ] **Step 4: Confirm the dashboard is provisioned**

```bash
curl -s "http://localhost:3000/api/search?query=NetFlow"
```

Expected: JSON array containing an entry with `"uid": "netflow-traffic"` and
`"title": "NetFlow Traffic"`, folder `"NetFlow"`.

- [ ] **Step 5: Generate traffic and confirm panels render data**

Run the LivePipeline (`dotnet run --project .\LivePipeline\`) and the
synthetic load generator from the earlier session (sends NetFlow v9 packets
to UDP `:2055`) for at least 1-2 minutes so `flows_raw` and
`flows_trends_1m` get rows.

Then open `http://localhost:3000/d/netflow-traffic` in a browser and confirm:
- "Bps / Pps Over Time" shows a non-empty line graph.
- "Summary (selected period)" shows non-zero `Flows`/`Bytes`/`Packets`.
- "Top 10 Destination Ports" shows rows (the synthetic generator always uses
  `DstPort = 443`, so expect a single row with `DstPort = 443`).

If panels show "No data", widen the dashboard time range (top-right picker)
to cover the time the load generator ran.

- [ ] **Step 6: Tear down (optional)**

```bash
docker compose down
```

(Keep `grafana-data`/`clickhouse-data` volumes unless you want a clean
re-provision test — `docker compose down -v` removes them too.)

---

## Self-Review Notes

- **Spec coverage:** Task 1 covers the docker-compose service + volume from
  spec §1; Task 2 covers the datasource provisioning from spec §2; Task 3
  covers the dashboard provider from spec §2; Task 4 covers all three panels
  (A/B/C) from spec §3 with the exact queries from the spec; Task 5 covers
  the "Testing / verification" section of the spec.
- **Placeholder scan:** none found — all file contents are complete and
  copy-pasteable.
- **Type/UID consistency:** datasource `uid: clickhouse-netflow` (Task 2)
  matches every panel's `datasource.uid` and `targets[].datasource.uid` in
  Task 4. Dashboard `uid: netflow-traffic` (Task 4) matches the URL used in
  Task 5 Step 5.
