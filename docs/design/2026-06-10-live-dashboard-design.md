# Live Dashboard (LivePipeline) — Design Spec

**Date:** 2026-06-10
**Status:** Approved

## Goal

Add a browser dashboard to the `LivePipeline` web project that connects to the
existing `/ws/metrics` WebSocket endpoint and renders `MetricSnapshot` JSON
(sent ~once per second by `NetFlowMetricAggregator`) as live charts —
no file upload, no historical storage.

## Context

- `LivePipeline/Program.cs` already calls `app.UseWebSockets()` and exposes
  `/ws/metrics` (path configurable via `PipelineOptions.WebSocketPath`,
  default `/ws/metrics`).
- `MetricSnapshot` (in `LivePipeline/Aggregation/MetricSnapshot.cs`) is the
  JSON contract, serialized via `MetricJsonContext` (System.Text.Json source
  generation, camelCase):

```json
{
  "timestamp": "2026-06-09T12:00:00Z",
  "totalFlows": 12345,
  "totalBytes": 98765432,
  "totalPackets": 54321,
  "bitsPerSecond": 790123456.0,
  "packetsPerSec": 54321.0,
  "topSrcIPs": [{"ip":"192.168.1.1","bytes":1234567}, ...],
  "topDstIPs": [{"ip":"8.8.8.8","bytes":9876543}, ...],
  "protocols":  [{"name":"TCP","bytes":8765432,"packets":43210}, ...]
}
```

- The old static dashboard (`NetFlowAnalizer/view/index.html` + `app.js`)
  reads a different, file-uploaded JSON shape (`{packets:[...], templates:{}}`)
  and is **not modified** by this work — it remains a separate, independent
  tool.
- Reusable helpers from the old `app.js` (copied, not shared via reference,
  since the projects are independent): `formatBytes()`, `generateColors()`.
  `getProtocolName()` is **not** needed — `MetricSnapshot.Protocols[].Name` is
  already a human-readable string (e.g. `"TCP"`) produced server-side by
  `MetricBucket.GetProtocolName()`.

## File Structure

```
LivePipeline/
├── wwwroot/
│   ├── index.html          (new) — page layout
│   └── live-dashboard.js   (new) — WebSocket client + Chart.js rendering
└── Program.cs               (modified) — add app.UseStaticFiles()
```

`Microsoft.NET.Sdk.Web` serves `wwwroot/` as the static file root once
`UseStaticFiles()` is registered; `index.html` becomes the default document
at `/`.

## Layout (index.html)

Reuses the visual style (CSS) of the old dashboard's `.card`, `.stat-box`,
`.dashboard` grid classes — copied inline into `index.html` (no shared CSS
file, to keep the two dashboards independent).

```
┌─────────────────────────────────────────────────────────────┐
│ NetFlow Live Dashboard                    ● Live / ● Reconn. │
├─────────────────────────────────────────────────────────────┤
│ [Flows/sec]   [Bits/sec]   [Packets/sec]   [Last Update]     │  <- KPI row
├──────────────────────────────┬──────────────────────────────┤
│ Top Source IPs (bar)          │ Top Destination IPs (bar)    │
├──────────────────────────────┼──────────────────────────────┤
│ Protocol Distribution (donut) │ Traffic Over Time (line)     │
└──────────────────────────────┴──────────────────────────────┘
```

- 4 stat-boxes in a KPI row (mirrors old `.summary-stats` grid).
- 2×2 chart grid (mirrors old `.dashboard` grid, `repeat(2, 1fr)`,
  responsive to 1 column under 768px).
- Connection status indicator: text + colored dot in the header
  (green "● Live" / amber "● Reconnecting…").

## WebSocket Client (live-dashboard.js)

### Connection & reconnect

```js
const WS_PATH = '/ws/metrics';
let ws;

function connect() {
  ws = new WebSocket(`ws://${location.host}${WS_PATH}`);
  ws.onopen    = () => setStatus(true);
  ws.onmessage = (e) => updateDashboard(JSON.parse(e.data));
  ws.onclose   = () => { setStatus(false); setTimeout(connect, 2000); };
  ws.onerror   = () => ws.close();
}
```

- Reconnect delay: fixed 2000ms (no exponential backoff — YAGNI for a local
  monitoring tool).
- `setStatus(connected)` toggles the header indicator dot/text.

### Data flow per snapshot (`updateDashboard(snapshot)`)

1. **KPI row** — direct text replacement:
   - `Flows/sec` = `snapshot.totalFlows`
   - `Bits/sec`  = `formatBitsPerSecond(snapshot.bitsPerSecond)`
   - `Packets/sec` = `Math.round(snapshot.packetsPerSec)`
   - `Last Update` = `new Date(snapshot.timestamp).toLocaleTimeString()`

2. **Traffic Over Time (line chart)** — rolling window of **60 points**
   (60 seconds @ 1 tick/sec):
   - Append `new Date(snapshot.timestamp).toLocaleTimeString()` to
     `chart.data.labels`, `snapshot.bitsPerSecond` to bps dataset,
     `snapshot.packetsPerSec` to pps dataset.
   - If `labels.length > 60`, `shift()` all three arrays.
   - Two Y axes (`bps` left, `pps` right) — same pattern as old
     `createTimeChart`.
   - `chart.update()` (no animation — `chart.update('none')` to avoid jank
     on 1-second ticks).

3. **Top Source IPs / Top Destination IPs (horizontal bar charts)** —
   full replace each tick:
   - `chart.data.labels = snapshot.topSrcIPs.map(e => e.ip)`
   - `chart.data.datasets[0].data = snapshot.topSrcIPs.map(e => e.bytes)`
   - `chart.update('none')`
   - Same for `topDstIPs`.
   - Tooltip formats bytes via `formatBytes()`.

4. **Protocol Distribution (donut chart)** — full replace each tick:
   - `chart.data.labels = snapshot.protocols.map(p => p.name)`
   - `chart.data.datasets[0].data = snapshot.protocols.map(p => p.bytes)`
   - `chart.data.datasets[0].backgroundColor/borderColor` regenerated via
     `generateColors(labels.length)` only when label count changes (avoid
     color reassignment churn every tick if protocol set is stable —
     simplification: regenerate every tick, it's cheap for ≤10 protocols).
   - `chart.update('none')`.

### Helper functions (copied from old app.js, trimmed)

- `formatBytes(bytes, decimals=2)` — unchanged.
- `formatBitsPerSecond(bps)` — new, same scaling logic as `formatBytes` but
  with bit units (bps/Kbps/Mbps/Gbps).
- `generateColors(count)` — unchanged.

## Charts initialized on page load

All 4 Chart.js instances are created once in `initCharts()` with empty data,
then populated/updated on each WebSocket message. No chart is destroyed and
recreated per tick (matches the "full replace data + update" pattern, which
is cheaper than the old dashboard's destroy/recreate-on-file-upload pattern).

## Error Handling

- Malformed JSON in `onmessage`: `try/catch` around `JSON.parse`, log to
  console, skip the tick (don't crash the chart loop).
- WebSocket connection failure: handled by the reconnect loop; status
  indicator shows "Reconnecting…".

## Out of Scope (YAGNI)

- No flow-record table, no tabs, no file upload (separate tool already
  covers that).
- No persistent history beyond the 60-second rolling window.
- No authentication/authorization on the WebSocket endpoint (matches
  existing `/ws/metrics` behavior).
- No shared CSS/JS between the old static dashboard and this new live
  dashboard — intentionally independent.

## Testing / Verification

- `dotnet build LivePipeline/LivePipeline.csproj` — must compile cleanly.
- Manual verification: run `LivePipeline`, open `http://localhost:<port>/`,
  confirm:
  - Connection indicator shows "● Live" once a snapshot arrives.
  - KPI values update every ~1 second.
  - All 4 charts render and update without console errors.
  - Killing/restarting the pipeline triggers "● Reconnecting…" and
    auto-recovers within ~2 seconds of the server coming back.
