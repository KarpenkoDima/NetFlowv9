# Live Dashboard (LivePipeline) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a static `wwwroot/index.html` + `live-dashboard.js` to the `LivePipeline` project that connects to `/ws/metrics`, parses `MetricSnapshot` JSON, and renders 4 live-updating Chart.js charts plus a KPI row.

**Architecture:** Two new static files served via `app.UseStaticFiles()` (added to `Program.cs`). The JS file owns a single `WebSocket` connection with fixed-delay reconnect, an `initCharts()` that creates 4 Chart.js instances once, and an `updateDashboard(snapshot)` that mutates chart data in place and calls `chart.update('none')`.

**Tech Stack:** ASP.NET Core static files middleware, vanilla JS, Chart.js 3.9.1 (CDN, same version as the old dashboard), WebSocket API.

---

## File Structure

```
LivePipeline/
├── wwwroot/
│   ├── index.html          (new)
│   └── live-dashboard.js   (new)
└── Program.cs               (modified — add UseStaticFiles + UseDefaultFiles)
```

---

### Task 1: Enable static file serving in Program.cs

**Files:**
- Modify: `LivePipeline/Program.cs`

- [ ] **Step 1: Read the current middleware section**

Open `LivePipeline/Program.cs` and find the section right before
`app.UseWebSockets(...)`. The file currently has numbered comment sections
`// ── 6. WebSocket middleware ───` etc.

- [ ] **Step 2: Add UseDefaultFiles + UseStaticFiles before UseWebSockets**

Insert this block immediately before the `app.UseWebSockets(...)` call
(which is under the `// ── 6. WebSocket middleware ───` comment):

```csharp
// ── 5b. Статические файлы (live-дашборд) ──────────────────────────────────
//
// wwwroot/index.html отдаётся по "/", wwwroot/live-dashboard.js — по
// "/live-dashboard.js". UseDefaultFiles должен идти ДО UseStaticFiles.

app.UseDefaultFiles();
app.UseStaticFiles();

```

- [ ] **Step 3: Build to verify no compile errors**

Run: `cd "J:\Video\WORK_ASSETS\experiments\ClaudeProGraphify\NetFlowv9" && dotnet build LivePipeline/LivePipeline.csproj`
Expected: `Сборка успешно завершена.` (Build succeeded), 0 errors.

- [ ] **Step 4: Commit**

```bash
cd "J:\Video\WORK_ASSETS\experiments\ClaudeProGraphify\NetFlowv9"
git add LivePipeline/Program.cs
git commit -m "Enable static file serving for live dashboard"
```

---

### Task 2: Create wwwroot/index.html

**Files:**
- Create: `LivePipeline/wwwroot/index.html`

- [ ] **Step 1: Create the wwwroot directory and index.html**

```bash
mkdir -p "J:\Video\WORK_ASSETS\experiments\ClaudeProGraphify\NetFlowv9\LivePipeline\wwwroot"
```

Write `LivePipeline/wwwroot/index.html` with this exact content:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetFlow Live Dashboard</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f7fa;
            color: #333;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            background-color: #2c3e50;
            color: white;
            padding: 15px 0;
            margin-bottom: 20px;
        }

        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        h1 {
            margin: 0;
            font-size: 24px;
        }

        #status {
            font-size: 14px;
            font-weight: 600;
        }

        #status .dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 6px;
            vertical-align: middle;
        }

        #status.live .dot { background-color: #2ecc71; }
        #status.reconnecting .dot { background-color: #f39c12; }

        .summary-stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            grid-gap: 15px;
            margin-bottom: 20px;
        }

        @media (max-width: 768px) {
            .summary-stats {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        .stat-box {
            padding: 15px;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            text-align: center;
        }

        .stat-value {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 5px;
            color: #2980b9;
        }

        .stat-label {
            font-size: 14px;
            color: #7f8c8d;
        }

        .dashboard {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            grid-gap: 20px;
        }

        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
        }

        .card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
        }

        .card-header {
            margin-top: 0;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
            font-size: 18px;
            color: #2c3e50;
        }

        .chart-container {
            position: relative;
            height: 350px;
            width: 100%;
        }
    </style>
</head>
<body>
    <header>
        <div class="header-content">
            <h1>NetFlow Live Dashboard</h1>
            <div id="status" class="reconnecting"><span class="dot"></span><span id="status-text">Connecting…</span></div>
        </div>
    </header>

    <div class="container">
        <div class="summary-stats">
            <div class="stat-box">
                <div class="stat-value" id="kpi-flows">-</div>
                <div class="stat-label">Flows/sec</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" id="kpi-bps">-</div>
                <div class="stat-label">Bits/sec</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" id="kpi-pps">-</div>
                <div class="stat-label">Packets/sec</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" id="kpi-updated">-</div>
                <div class="stat-label">Last Update</div>
            </div>
        </div>

        <div class="dashboard">
            <div class="card">
                <h3 class="card-header">Top Source IPs</h3>
                <div class="chart-container">
                    <canvas id="src-ip-chart"></canvas>
                </div>
            </div>

            <div class="card">
                <h3 class="card-header">Top Destination IPs</h3>
                <div class="chart-container">
                    <canvas id="dst-ip-chart"></canvas>
                </div>
            </div>

            <div class="card">
                <h3 class="card-header">Protocol Distribution</h3>
                <div class="chart-container">
                    <canvas id="protocol-chart"></canvas>
                </div>
            </div>

            <div class="card">
                <h3 class="card-header">Traffic Over Time (60s)</h3>
                <div class="chart-container">
                    <canvas id="time-chart"></canvas>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <script src="live-dashboard.js"></script>
</body>
</html>
```

- [ ] **Step 2: Commit**

```bash
cd "J:\Video\WORK_ASSETS\experiments\ClaudeProGraphify\NetFlowv9"
git add LivePipeline/wwwroot/index.html
git commit -m "Add live dashboard HTML layout"
```

---

### Task 3: Create wwwroot/live-dashboard.js — helpers and chart init

**Files:**
- Create: `LivePipeline/wwwroot/live-dashboard.js`

- [ ] **Step 1: Write the file with helpers, chart initialization, and the WebSocket client**

Write `LivePipeline/wwwroot/live-dashboard.js` with this exact content:

```javascript
// ── State ────────────────────────────────────────────────────────────────

const MAX_TIME_POINTS = 60; // 60 seconds rolling window
let charts = {};
let ws;

// ── Helpers ──────────────────────────────────────────────────────────────

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatBitsPerSecond(bps, decimals = 2) {
    if (bps === 0) return '0 bps';
    const k = 1000;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
    const i = Math.floor(Math.log(bps) / Math.log(k));
    return parseFloat((bps / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function generateColors(count) {
    const baseColors = [
        [54, 162, 235],   // Blue
        [255, 99, 132],   // Red
        [75, 192, 192],   // Green
        [255, 205, 86],   // Yellow
        [153, 102, 255],  // Purple
        [255, 159, 64],   // Orange
        [201, 203, 207],  // Grey
        [54, 72, 178],    // Dark Blue
        [255, 69, 0],     // Orange Red
        [46, 139, 87]     // Sea Green
    ];

    const bg = [];
    const border = [];

    for (let i = 0; i < count; i++) {
        const [r, g, b] = baseColors[i % baseColors.length];
        bg.push(`rgba(${r}, ${g}, ${b}, 0.7)`);
        border.push(`rgba(${r}, ${g}, ${b}, 1)`);
    }

    return { bg, border };
}

// ── Chart initialization ────────────────────────────────────────────────

function initCharts() {
    charts.srcIp = new Chart(document.getElementById('src-ip-chart').getContext('2d'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Bytes', data: [], backgroundColor: 'rgba(54, 162, 235, 0.7)', borderColor: 'rgba(54, 162, 235, 1)', borderWidth: 1 }] },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: (ctx) => formatBytes(ctx.raw) } }
            },
            scales: { x: { ticks: { callback: (v) => formatBytes(v) } } }
        }
    });

    charts.dstIp = new Chart(document.getElementById('dst-ip-chart').getContext('2d'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Bytes', data: [], backgroundColor: 'rgba(75, 192, 192, 0.7)', borderColor: 'rgba(75, 192, 192, 1)', borderWidth: 1 }] },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: (ctx) => formatBytes(ctx.raw) } }
            },
            scales: { x: { ticks: { callback: (v) => formatBytes(v) } } }
        }
    });

    charts.protocol = new Chart(document.getElementById('protocol-chart').getContext('2d'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: [], borderWidth: 1 }] },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '50%',
            plugins: {
                legend: { position: 'top', align: 'start', labels: { boxWidth: 15, padding: 15, usePointStyle: true, pointStyle: 'circle' } },
                tooltip: {
                    callbacks: {
                        label: (ctx) => {
                            const value = ctx.raw;
                            const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                            const pct = total > 0 ? Math.round((value / total) * 100) : 0;
                            return `${ctx.label}: ${formatBytes(value)} (${pct}%)`;
                        }
                    }
                }
            }
        }
    });

    charts.time = new Chart(document.getElementById('time-chart').getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                { label: 'Bits/sec', data: [], yAxisID: 'bps', borderColor: 'rgba(54, 162, 235, 1)', backgroundColor: 'rgba(54, 162, 235, 0.2)', fill: true, tension: 0.1 },
                { label: 'Packets/sec', data: [], yAxisID: 'pps', borderColor: 'rgba(255, 99, 132, 1)', backgroundColor: 'rgba(255, 99, 132, 0.2)', fill: true, tension: 0.1 }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                bps: { type: 'linear', position: 'left', title: { display: true, text: 'Bits/sec' }, ticks: { callback: (v) => formatBitsPerSecond(v, 0) } },
                pps: { type: 'linear', position: 'right', title: { display: true, text: 'Packets/sec' }, grid: { drawOnChartArea: false } }
            }
        }
    });
}

// ── Dashboard update ─────────────────────────────────────────────────────

function updateDashboard(snapshot) {
    // KPI row
    document.getElementById('kpi-flows').textContent = snapshot.totalFlows.toLocaleString();
    document.getElementById('kpi-bps').textContent = formatBitsPerSecond(snapshot.bitsPerSecond);
    document.getElementById('kpi-pps').textContent = Math.round(snapshot.packetsPerSec).toLocaleString();
    document.getElementById('kpi-updated').textContent = new Date(snapshot.timestamp).toLocaleTimeString();

    // Traffic over time — rolling 60-point window
    const label = new Date(snapshot.timestamp).toLocaleTimeString();
    const timeData = charts.time.data;
    timeData.labels.push(label);
    timeData.datasets[0].data.push(snapshot.bitsPerSecond);
    timeData.datasets[1].data.push(snapshot.packetsPerSec);
    if (timeData.labels.length > MAX_TIME_POINTS) {
        timeData.labels.shift();
        timeData.datasets[0].data.shift();
        timeData.datasets[1].data.shift();
    }
    charts.time.update('none');

    // Top Source IPs
    charts.srcIp.data.labels = snapshot.topSrcIPs.map(e => e.ip);
    charts.srcIp.data.datasets[0].data = snapshot.topSrcIPs.map(e => e.bytes);
    charts.srcIp.update('none');

    // Top Destination IPs
    charts.dstIp.data.labels = snapshot.topDstIPs.map(e => e.ip);
    charts.dstIp.data.datasets[0].data = snapshot.topDstIPs.map(e => e.bytes);
    charts.dstIp.update('none');

    // Protocol distribution
    const protoLabels = snapshot.protocols.map(p => p.name);
    const protoColors = generateColors(protoLabels.length);
    charts.protocol.data.labels = protoLabels;
    charts.protocol.data.datasets[0].data = snapshot.protocols.map(p => p.bytes);
    charts.protocol.data.datasets[0].backgroundColor = protoColors.bg;
    charts.protocol.data.datasets[0].borderColor = protoColors.border;
    charts.protocol.update('none');
}

// ── Connection status ────────────────────────────────────────────────────

function setStatus(connected) {
    const el = document.getElementById('status');
    const text = document.getElementById('status-text');
    if (connected) {
        el.className = 'live';
        text.textContent = 'Live';
    } else {
        el.className = 'reconnecting';
        text.textContent = 'Reconnecting…';
    }
}

// ── WebSocket client ─────────────────────────────────────────────────────

const WS_PATH = '/ws/metrics';

function connect() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${location.host}${WS_PATH}`);

    ws.onopen = () => setStatus(true);

    ws.onmessage = (event) => {
        try {
            const snapshot = JSON.parse(event.data);
            updateDashboard(snapshot);
        } catch (err) {
            console.error('Failed to parse metric snapshot:', err);
        }
    };

    ws.onclose = () => {
        setStatus(false);
        setTimeout(connect, 2000);
    };

    ws.onerror = () => ws.close();
}

// ── Bootstrap ─────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    connect();
});
```

- [ ] **Step 2: Commit**

```bash
cd "J:\Video\WORK_ASSETS\experiments\ClaudeProGraphify\NetFlowv9"
git add LivePipeline/wwwroot/live-dashboard.js
git commit -m "Add live dashboard WebSocket client and Chart.js rendering"
```

---

### Task 4: Build and manual verification

**Files:** none (verification only)

- [ ] **Step 1: Build the LivePipeline project**

Run: `cd "J:\Video\WORK_ASSETS\experiments\ClaudeProGraphify\NetFlowv9" && dotnet build LivePipeline/LivePipeline.csproj`
Expected: `Сборка успешно завершена.` (Build succeeded), 0 errors.

- [ ] **Step 2: Run the LivePipeline app**

Run: `cd "J:\Video\WORK_ASSETS\experiments\ClaudeProGraphify\NetFlowv9" && dotnet run --project LivePipeline/LivePipeline.csproj`
Expected: Console shows `[Receiver] Listening on UDP :2055` (or configured port) and the Kestrel
"Now listening on: http://localhost:XXXX" line.

- [ ] **Step 3: Open the dashboard in a browser**

Navigate to `http://localhost:<port>/` (port from step 2's console output).
Expected:
- Page loads with header "NetFlow Live Dashboard" and a status indicator.
- All 4 chart cards render (initially empty — no data sent yet).
- Status indicator shows "● Live" within ~1 second (WebSocket connects even
  with zero NetFlow traffic, since the aggregator ticks every second
  regardless of flow volume).
- Browser console (F12) shows no errors.

- [ ] **Step 4: (Optional) Send test NetFlow traffic and verify charts populate**

If an `nfgen`/NetFlow simulator or real exporter is available, point it at
`UDP :<UdpPort from appsettings.json>`. Expected: KPI values become non-zero,
"Traffic Over Time" chart starts plotting points, IP/protocol charts populate
with bars/segments.

If no traffic generator is available, this step can be skipped — Tasks 1-3
are independently verifiable via Steps 1-3 (page loads, WebSocket connects,
no console errors).

- [ ] **Step 5: Stop the app**

Press `Ctrl+C` in the terminal running `dotnet run`.

---

## Self-Review Notes

- **Spec coverage:** KPI row ✓ (Task 2/3), Traffic Over Time 60s rolling ✓
  (Task 3 `MAX_TIME_POINTS`), Top Src/Dst IP bars ✓, Protocol donut ✓,
  WebSocket reconnect (2s fixed) ✓, `formatBytes`/`generateColors` copied ✓,
  `formatBitsPerSecond` added per spec ✓, static file serving ✓ (Task 1),
  `getProtocolName` correctly omitted (server already sends names) ✓.
- **Placeholder scan:** none found — all code blocks are complete and exact.
- **Type consistency:** `MetricSnapshot` field names (`totalFlows`,
  `bitsPerSecond`, `packetsPerSec`, `topSrcIPs[].ip/.bytes`,
  `topDstIPs[].ip/.bytes`, `protocols[].name/.bytes/.packets`, `timestamp`)
  match `LivePipeline/Aggregation/MetricSnapshot.cs` camelCase JSON contract
  exactly.
