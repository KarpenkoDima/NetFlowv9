// ═══════════════════════════════════════════════════════════════════════════
//  NetFlow Dashboard — app.js
//  Поддерживает два режима:
//    1. Static  — загрузка JSON-файла (PCAP-режим, существующая логика)
//    2. Live    — WebSocket-подключение к /ws/metrics (live pipeline режим)
// ═══════════════════════════════════════════════════════════════════════════

// ── Глобальное состояние ──────────────────────────────────────────────────
let netflowData   = null;
let charts        = {};
let liveCharts    = {};
let ws            = null;

let currentFlowPage    = 1;
const recordsPerPage   = 100;
let totalFlowRecords   = 0;
let allFlowRecords     = [];

// Скользящее окно данных для Time Chart в live-режиме
const MAX_TIME_POINTS  = 60;
const liveTimeLabels   = [];
const liveBpsData      = [];
const livePpsData      = [];

// ── Инициализация ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('upload-file').addEventListener('change', handleFileUpload);
    document.getElementById('ws-connect-btn').addEventListener('click', toggleLiveConnection);
    setupTabs();
});

// ═════════════════════════════════════════════════════════════════════════
//  LIVE MODE — WebSocket
// ═════════════════════════════════════════════════════════════════════════

function toggleLiveConnection() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        disconnectLive();
    } else {
        connectLive();
    }
}

function connectLive() {
    const url = document.getElementById('ws-url').value.trim();
    if (!url) { setLiveStatus('Введите URL WebSocket', 'error'); return; }

    setLiveStatus('Подключение…', 'connecting');
    document.getElementById('ws-connect-btn').textContent = 'Отключить';

    ws = new WebSocket(url);

    ws.onopen = () => {
        setLiveStatus('Подключено', 'connected');
        document.getElementById('live-dashboard').style.display = 'block';
        initLiveCharts();
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleLiveUpdate(data);
        } catch (e) {
            console.error('Ошибка парсинга WebSocket-сообщения:', e);
        }
    };

    ws.onclose = () => {
        setLiveStatus('Отключено', 'disconnected');
        document.getElementById('ws-connect-btn').textContent = 'Подключить';
        ws = null;
    };

    ws.onerror = () => {
        setLiveStatus('Ошибка соединения', 'error');
        document.getElementById('ws-connect-btn').textContent = 'Подключить';
    };
}

function disconnectLive() {
    if (ws) { ws.close(); ws = null; }
    setLiveStatus('Отключено', 'disconnected');
    document.getElementById('ws-connect-btn').textContent = 'Подключить';
}

function setLiveStatus(text, state) {
    const el = document.getElementById('ws-status');
    el.textContent = text;
    el.className = 'ws-status ws-status--' + state;
}

// ── Обработка входящего JSON-среза ───────────────────────────────────────
//
// Ожидаемый формат (camelCase, серверная сторона):
// {
//   "timestamp":    "2026-06-09T12:00:00Z",
//   "totalFlows":   12345,
//   "totalBytes":   98765432,
//   "totalPackets": 54321,
//   "bitsPerSecond": 790123456.0,
//   "packetsPerSec": 54321.0,
//   "topSrcIPs": [{"ip":"192.168.1.1","bytes":1234567}, ...],
//   "topDstIPs": [{"ip":"8.8.8.8","bytes":9876543}, ...],
//   "protocols":  [{"name":"TCP","bytes":8765432,"packets":43210}, ...]
// }

function handleLiveUpdate(data) {
    updateLiveStats(data);
    updateLiveSrcChart(data.topSrcIPs  || []);
    updateLiveDstChart(data.topDstIPs  || []);
    updateLiveProtocolChart(data.protocols || []);
    updateLiveTimeChart(data.timestamp, data.bitsPerSecond, data.packetsPerSec);
}

// ── Live Stats ────────────────────────────────────────────────────────────
function updateLiveStats(data) {
    setText('live-flows',   (data.totalFlows   || 0).toLocaleString());
    setText('live-bytes',   formatBytes(data.totalBytes   || 0));
    setText('live-bps',     formatBits(data.bitsPerSecond || 0));
    setText('live-pps',     Math.round(data.packetsPerSec || 0).toLocaleString());
    setText('live-ts',      new Date(data.timestamp).toLocaleTimeString());
}

// ── Top-10 Src IPs ────────────────────────────────────────────────────────
function updateLiveSrcChart(topIPs) {
    const chart = liveCharts.srcIP;
    if (!chart) return;
    chart.data.labels   = topIPs.map(e => e.ip);
    chart.data.datasets[0].data = topIPs.map(e => e.bytes);
    chart.update('none'); // 'none' = no animation → мгновенно
}

// ── Top-10 Dst IPs ────────────────────────────────────────────────────────
function updateLiveDstChart(topIPs) {
    const chart = liveCharts.dstIP;
    if (!chart) return;
    chart.data.labels   = topIPs.map(e => e.ip);
    chart.data.datasets[0].data = topIPs.map(e => e.bytes);
    chart.update('none');
}

// ── Protocol Distribution ─────────────────────────────────────────────────
function updateLiveProtocolChart(protocols) {
    const chart = liveCharts.protocol;
    if (!chart) return;
    chart.data.labels   = protocols.map(p => p.name);
    chart.data.datasets[0].data = protocols.map(p => p.bytes);
    const colors = generateColors(protocols.length);
    chart.data.datasets[0].backgroundColor = colors.bg;
    chart.data.datasets[0].borderColor     = colors.border;
    chart.update('none');
}

// ── Traffic Over Time (скользящее окно 60 точек) ──────────────────────────
function updateLiveTimeChart(timestamp, bps, pps) {
    const chart = liveCharts.time;
    if (!chart) return;

    const label = new Date(timestamp).toLocaleTimeString();
    liveTimeLabels.push(label);
    liveBpsData.push(bps);
    livePpsData.push(pps);

    // Удаляем точки старше MAX_TIME_POINTS
    if (liveTimeLabels.length > MAX_TIME_POINTS) {
        liveTimeLabels.shift();
        liveBpsData.shift();
        livePpsData.shift();
    }

    chart.data.labels                    = liveTimeLabels;
    chart.data.datasets[0].data          = liveBpsData;
    chart.data.datasets[1].data          = livePpsData;
    chart.update('none');
}

// ── Инициализация live-графиков ───────────────────────────────────────────
function initLiveCharts() {
    // Уничтожаем существующие, если переподключаемся
    Object.values(liveCharts).forEach(c => c?.destroy());
    liveCharts = {};
    liveTimeLabels.length = 0;
    liveBpsData.length    = 0;
    livePpsData.length    = 0;

    liveCharts.srcIP = createHorizontalBarChart(
        'live-src-ip-chart', 'Байт', 'rgba(54, 162, 235, 0.7)', 'rgba(54, 162, 235, 1)');

    liveCharts.dstIP = createHorizontalBarChart(
        'live-dst-ip-chart', 'Байт', 'rgba(75, 192, 192, 0.7)', 'rgba(75, 192, 192, 1)');

    liveCharts.protocol = createDoughnutChart('live-protocol-chart');

    liveCharts.time = createLiveTimeChart('live-time-chart');
}

// ── Chart factories ───────────────────────────────────────────────────────

function createHorizontalBarChart(canvasId, label, bgColor, borderColor) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return null;
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{ label, data: [], backgroundColor: bgColor, borderColor, borderWidth: 1 }]
        },
        options: {
            indexAxis: 'y',
            animation: false,
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: ctx => formatBytes(ctx.raw) } }
            },
            scales: { x: { ticks: { callback: v => formatBytes(v) } } }
        }
    });
}

function createDoughnutChart(canvasId) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return null;
    return new Chart(ctx, {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: [], borderWidth: 1 }] },
        options: {
            animation: false,
            responsive: true,
            maintainAspectRatio: false,
            cutout: '50%',
            plugins: {
                legend: { position: 'top' },
                tooltip: {
                    callbacks: {
                        label: context => {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const pct   = total ? Math.round((context.raw / total) * 100) : 0;
                            return `${context.label}: ${formatBytes(context.raw)} (${pct}%)`;
                        }
                    }
                }
            }
        }
    });
}

function createLiveTimeChart(canvasId) {
    const ctx = document.getElementById(canvasId)?.getContext('2d');
    if (!ctx) return null;
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'bps',
                    data: [],
                    yAxisID: 'bps',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    backgroundColor: 'rgba(54, 162, 235, 0.15)',
                    fill: true,
                    tension: 0.2,
                    pointRadius: 0,
                },
                {
                    label: 'pps',
                    data: [],
                    yAxisID: 'pps',
                    borderColor: 'rgba(255, 99, 132, 1)',
                    backgroundColor: 'rgba(255, 99, 132, 0.15)',
                    fill: true,
                    tension: 0.2,
                    pointRadius: 0,
                }
            ]
        },
        options: {
            animation: false,
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                bps: {
                    type: 'linear', position: 'left',
                    title: { display: true, text: 'bps' },
                    ticks: { callback: v => formatBits(v) }
                },
                pps: {
                    type: 'linear', position: 'right',
                    title: { display: true, text: 'pps' },
                    grid: { drawOnChartArea: false }
                }
            }
        }
    });
}

// ═════════════════════════════════════════════════════════════════════════
//  STATIC MODE — существующая логика загрузки PCAP JSON
// ═════════════════════════════════════════════════════════════════════════

function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    document.getElementById('file-name').textContent = file.name;
    document.getElementById('loading').textContent = 'Loading NetFlow data...';

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            netflowData = JSON.parse(e.target.result);
            processNetFlowData(netflowData);
            document.getElementById('loading').style.display = 'none';
            document.getElementById('dashboard-container').style.display = 'block';
        } catch (error) {
            document.getElementById('loading').textContent = `Error parsing JSON: ${error.message}`;
        }
    };
    reader.onerror = () => {
        document.getElementById('loading').textContent = 'Error reading file';
    };
    reader.readAsText(file);
}

function processNetFlowData(data) {
    if (data.version)
        document.getElementById('netflow-version').textContent = `NetFlow v${data.version}`;
    updateSummaryStats(data);
    createCharts(data);
    populateFlowsTable(data);
    displayTemplates(data);
    document.getElementById('raw-data').textContent = JSON.stringify(data, null, 2);
}

function updateSummaryStats(data) {
    const totalPackets = data.packets ? data.packets.length : 0;
    document.getElementById('total-packets').textContent = totalPackets;

    let totalFlows = 0;
    if (data.packets) {
        data.packets.forEach(packet => {
            if (packet.flowSets)
                packet.flowSets.forEach(fs => { if (fs.records) totalFlows += fs.records.length; });
        });
    }
    document.getElementById('total-flows').textContent = totalFlows;

    let totalTemplates = 0;
    if (data.templates) totalTemplates = Object.keys(data.templates).length;
    document.getElementById('total-templates').textContent = totalTemplates;

    let minTime = Infinity, maxTime = 0;
    if (data.packets)
        data.packets.forEach(p => {
            if (p.unixSecs) { minTime = Math.min(minTime, p.unixSecs); maxTime = Math.max(maxTime, p.unixSecs); }
        });

    if (minTime !== Infinity && maxTime !== 0) {
        const s = maxTime - minTime;
        document.getElementById('time-span').textContent =
            s < 60 ? `${s}s` : s < 3600 ? `${Math.round(s/60)}m` : `${Math.round(s/3600)}h`;
    } else {
        document.getElementById('time-span').textContent = 'N/A';
    }
}

function extractFlowRecords(data) {
    const flowRecords = [];
    if (data.packets) {
        data.packets.forEach(packet => {
            if (packet.flowSets) {
                packet.flowSets.forEach(fs => {
                    if (fs.flowSetId >= 256 && fs.records) {
                        fs.records.forEach(record => {
                            const pr = {};
                            for (const [ft, val] of Object.entries(record))
                                pr[getFieldName(parseInt(ft))] = val;
                            if (!pr.startTime && packet.unixSecs)
                                pr.startTime = new Date(packet.unixSecs * 1000).toISOString();
                            flowRecords.push(pr);
                        });
                    }
                });
            }
        });
    }
    return flowRecords;
}

function getFieldName(fieldType) {
    const m = {
        1:'bytes', 2:'packets', 4:'protocol', 5:'tos', 6:'tcpFlags',
        7:'srcPort', 8:'srcIP', 9:'srcMask', 10:'inputIF', 11:'dstPort',
        12:'dstIP', 13:'dstMask', 14:'outputIF', 15:'nextHop',
        21:'srcMAC', 22:'dstMAC', 34:'startTime', 35:'endTime',
        56:'flowStartSysUptime', 57:'flowEndSysUptime',
        80:'flowStartUnix', 81:'flowEndUnix',
        225:'postNATSrcIP', 226:'postNATDstIP',
        227:'postNATSrcPort', 228:'postNATDstPort'
    };
    return m[fieldType] || `field${fieldType}`;
}

function createCharts(data) {
    Object.values(charts).forEach(c => c?.destroy());
    charts = {};
    const recs = extractFlowRecords(data);
    createIPChart(recs);
    createPortChart(recs);
    createProtocolChart(recs);
    createTimeChart(recs);
}

function createIPChart(flowRecords) {
    const ipTraffic = {};
    flowRecords.forEach(r => {
        if (r.srcIP) ipTraffic[r.srcIP] = (ipTraffic[r.srcIP] || 0) + (parseInt(r.bytes) || 0);
        if (r.dstIP) ipTraffic[r.dstIP] = (ipTraffic[r.dstIP] || 0) + (parseInt(r.bytes) || 0);
    });
    const sorted = Object.entries(ipTraffic).sort((a,b)=>b[1]-a[1]).slice(0,10);
    const ctx = document.getElementById('ip-chart').getContext('2d');
    charts.ipChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(e=>e[0]),
            datasets: [{
                label: 'Traffic (Bytes)', data: sorted.map(e=>e[1]),
                backgroundColor: 'rgba(54,162,235,0.7)', borderColor: 'rgba(54,162,235,1)', borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y', responsive: true, maintainAspectRatio: false,
            plugins: { legend: {display:false}, tooltip: {callbacks:{label:c=>formatBytes(c.raw)}} },
            scales: { x: { ticks: { callback: v => formatBytes(v) } } }
        }
    });
}

function createPortChart(flowRecords) {
    const portTraffic = {};
    flowRecords.forEach(r => {
        if (r.srcPort) portTraffic[r.srcPort] = (portTraffic[r.srcPort]||0)+(parseInt(r.bytes)||0);
        if (r.dstPort) portTraffic[r.dstPort] = (portTraffic[r.dstPort]||0)+(parseInt(r.bytes)||0);
    });
    const sorted = Object.entries(portTraffic).sort((a,b)=>b[1]-a[1]).slice(0,10);
    const ctx = document.getElementById('port-chart').getContext('2d');
    charts.portChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sorted.map(e=>getWellKnownPort(parseInt(e[0]))||`Port ${e[0]}`),
            datasets: [{
                label: 'Traffic (Bytes)', data: sorted.map(e=>e[1]),
                backgroundColor: 'rgba(75,192,192,0.7)', borderColor: 'rgba(75,192,192,1)', borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y', responsive: true, maintainAspectRatio: false,
            plugins: { legend:{display:false}, tooltip:{callbacks:{label:c=>formatBytes(c.raw)}} },
            scales: { x: { ticks: { callback: v => formatBytes(v) } } }
        }
    });
}

function getWellKnownPort(port) {
    const m = {20:'FTP-Data(20)',21:'FTP(21)',22:'SSH(22)',23:'Telnet(23)',25:'SMTP(25)',
        53:'DNS(53)',80:'HTTP(80)',110:'POP3(110)',123:'NTP(123)',143:'IMAP(143)',
        161:'SNMP(161)',443:'HTTPS(443)',465:'SMTPS(465)',993:'IMAPS(993)',995:'POP3S(995)',
        1433:'SQL Server(1433)',3306:'MySQL(3306)',3389:'RDP(3389)',5060:'SIP(5060)',8080:'HTTP Proxy(8080)'};
    return m[port];
}

function createProtocolChart(flowRecords) {
    const protoTraffic = {};
    flowRecords.forEach(r => {
        if (r.protocol) {
            const name = getProtocolName(parseInt(r.protocol));
            protoTraffic[name] = (protoTraffic[name]||0)+(parseInt(r.bytes)||0);
        }
    });
    const sorted = Object.entries(protoTraffic).sort((a,b)=>b[1]-a[1]);
    const colors = generateColors(sorted.length);
    const ctx = document.getElementById('protocol-chart').getContext('2d');
    charts.protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: sorted.map(e=>e[0]),
            datasets: [{ data: sorted.map(e=>e[1]), backgroundColor: colors.bg, borderColor: colors.border, borderWidth: 1 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '50%',
            plugins: {
                legend: { position:'top', align:'start', labels:{boxWidth:15,padding:15,usePointStyle:true,pointStyle:'circle'} },
                tooltip: { callbacks: { label: ctx => { const t=ctx.dataset.data.reduce((a,b)=>a+b,0); return `${ctx.label}: ${formatBytes(ctx.raw)} (${Math.round(ctx.raw/t*100)}%)`; } } }
            }
        }
    });
    setTimeout(()=>charts.protocolChart?.resize(), 100);
}

function getProtocolName(n) {
    const m = {1:'ICMP(1)',2:'IGMP(2)',6:'TCP(6)',17:'UDP(17)',47:'GRE(47)',
        50:'ESP(50)',51:'AH(51)',58:'IPv6-ICMP(58)',89:'OSPF(89)',132:'SCTP(132)'};
    return m[n]||`Protocol ${n}`;
}

function createTimeChart(flowRecords) {
    const INTERVAL = 5*60*1000;
    const tt = {};
    flowRecords.forEach(r => {
        let ts;
        if (r.flowStartUnix) ts = parseInt(r.flowStartUnix)*1000;
        else if (r.startTime) ts = new Date(r.startTime).getTime();
        else if (r.flowEndUnix) ts = parseInt(r.flowEndUnix)*1000;
        if (ts) {
            const b = Math.floor(ts/INTERVAL)*INTERVAL;
            if (!tt[b]) tt[b]={bytes:0,packets:0};
            tt[b].bytes   += parseInt(r.bytes)||0;
            tt[b].packets += parseInt(r.packets)||0;
        }
    });
    const sorted = Object.entries(tt).sort((a,b)=>parseInt(a[0])-parseInt(b[0]));
    const ctx = document.getElementById('time-chart').getContext('2d');
    charts.timeChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: sorted.map(e=>new Date(parseInt(e[0])).toLocaleTimeString()),
            datasets: [
                { label:'Bytes',   data:sorted.map(e=>e[1].bytes),   yAxisID:'bytes',   borderColor:'rgba(54,162,235,1)',  backgroundColor:'rgba(54,162,235,0.2)',  fill:true, tension:0.1 },
                { label:'Packets', data:sorted.map(e=>e[1].packets), yAxisID:'packets', borderColor:'rgba(255,99,132,1)',  backgroundColor:'rgba(255,99,132,0.2)',  fill:true, tension:0.1 }
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            scales: {
                bytes:   { type:'linear', position:'left',  title:{display:true,text:'Bytes'},   ticks:{callback:v=>formatBytes(v,0)} },
                packets: { type:'linear', position:'right', title:{display:true,text:'Packets'}, grid:{drawOnChartArea:false} }
            }
        }
    });
}

function setupPagination() {
    let pc = document.getElementById('flows-pagination');
    if (!pc) {
        const tc = document.querySelector('#flows-tab .table-container');
        pc = document.createElement('div');
        pc.id = 'flows-pagination'; pc.className = 'pagination-controls';
        tc.parentNode.insertBefore(pc, tc.nextSibling);
    }
    pc.innerHTML = '';
    const totalPages = Math.ceil(totalFlowRecords/recordsPerPage);
    if (totalPages <= 1) return;

    const mkBtn = (html, disabled, onClick) => {
        const b = document.createElement('button');
        b.innerHTML = html; b.className = 'pagination-btn';
        b.disabled = disabled; if (!disabled) b.addEventListener('click', onClick);
        return b;
    };

    pc.appendChild(mkBtn('&laquo;', currentFlowPage===1, ()=>{currentFlowPage=1; populateFlowsTable();}));
    pc.appendChild(mkBtn('&lsaquo;', currentFlowPage===1, ()=>{currentFlowPage--; populateFlowsTable();}));

    const pi = document.createElement('span');
    pi.textContent = `Page ${currentFlowPage} of ${totalPages}`; pi.className='pagination-info';
    pc.appendChild(pi);

    pc.appendChild(mkBtn('&rsaquo;', currentFlowPage===totalPages, ()=>{currentFlowPage++; populateFlowsTable();}));
    pc.appendChild(mkBtn('&raquo;', currentFlowPage===totalPages, ()=>{currentFlowPage=totalPages; populateFlowsTable();}));

    const ri = document.createElement('div');
    ri.textContent = `Showing ${(currentFlowPage-1)*recordsPerPage+1}–${Math.min(currentFlowPage*recordsPerPage, totalFlowRecords)} of ${totalFlowRecords}`;
    ri.className = 'record-info'; pc.appendChild(ri);
}

function populateFlowsTable(data) {
    if (data) { allFlowRecords=extractFlowRecords(data); totalFlowRecords=allFlowRecords.length; currentFlowPage=1; }
    const tbody = document.querySelector('#flows-table tbody');
    tbody.innerHTML = '';
    const start = (currentFlowPage-1)*recordsPerPage;
    const recs  = allFlowRecords.slice(start, start+recordsPerPage);
    if (!recs.length) {
        const row = tbody.insertRow();
        const cell = row.insertCell(); cell.colSpan=9; cell.textContent='No records found';
        cell.style.cssText='text-align:center;padding:20px;'; return;
    }
    recs.forEach(r => {
        const row = tbody.insertRow();
        [r.srcIP||'-', r.srcPort||'-', r.dstIP||'-', r.dstPort||'-',
         getProtocolName(parseInt(r.protocol))||r.protocol||'-',
         r.bytes?formatBytes(r.bytes):'-', r.packets||'-',
         fmtTime(r.flowStartUnix, r.startTime),
         fmtTime(r.flowEndUnix,   r.endTime)
        ].forEach(v => { const c=row.insertCell(); c.textContent=v; });
    });
    setupPagination();
}

function fmtTime(unix, iso) {
    try {
        if (unix) return new Date(parseInt(unix)*1000).toLocaleString();
        if (iso)  return new Date(iso).toLocaleString();
    } catch { }
    return '-';
}

function createTableCell(content) {
    const cell = document.createElement('td');
    cell.textContent = content; return cell;
}

function displayTemplates(data) {
    const container = document.getElementById('templates-container');
    container.innerHTML = '';
    const templates = [];
    if (data.templates) {
        for (const sid in data.templates)
            for (const tid in data.templates[sid])
                templates.push({ sourceId:sid, templateId:tid, ...data.templates[sid][tid] });
    } else if (data.packets) {
        data.packets.forEach(p => {
            if (p.flowSets) p.flowSets.forEach(fs => {
                if (fs.flowSetId===0 && fs.templates)
                    fs.templates.forEach(t => templates.push({ sourceId:p.sourceId, templateId:t.templateId, ...t }));
            });
        });
    }
    if (!templates.length) { container.innerHTML='<p>No template records found</p>'; return; }
    templates.forEach(tmpl => {
        const div = document.createElement('div');
        div.className='card'; div.style.marginBottom='15px';
        const h = document.createElement('h4');
        h.textContent=`Template ID: ${tmpl.templateId}, Source ID: ${tmpl.sourceId}`;
        div.appendChild(h);
        if (tmpl.fields?.length) {
            const tbl=document.createElement('table');
            const thead=tbl.createTHead(); const hr=thead.insertRow();
            ['Field Type','Field Name','Length'].forEach(n=>{const th=document.createElement('th');th.textContent=n;hr.appendChild(th);});
            const tbody=tbl.createTBody();
            tmpl.fields.forEach(f=>{const row=tbody.insertRow();[f.type,getFieldName(f.type),f.length].forEach(v=>{const c=row.insertCell();c.textContent=v;});});
            div.appendChild(tbl);
        } else {
            const p=document.createElement('p'); p.textContent='No fields defined'; div.appendChild(p);
        }
        container.appendChild(div);
    });
}

// ── Tabs ──────────────────────────────────────────────────────────────────
function setupTabs() {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById(`${tab.dataset.tab}-tab`)?.classList.add('active');
        });
    });
}

// ── Утилиты ───────────────────────────────────────────────────────────────
function generateColors(count) {
    const base = [[54,162,235],[255,99,132],[75,192,192],[255,205,86],[153,102,255],
                  [255,159,64],[201,203,207],[54,72,178],[255,69,0],[46,139,87]];
    const bg=[], border=[];
    for (let i=0;i<count;i++) {
        const [r,g,b]=base[i%base.length];
        bg.push(`rgba(${r},${g},${b},0.7)`); border.push(`rgba(${r},${g},${b},1)`);
    }
    return {bg,border};
}

function formatBytes(bytes, decimals=2) {
    if (!bytes || bytes===0) return '0 B';
    const k=1024, dm=Math.max(0,decimals);
    const sizes=['B','KB','MB','GB','TB','PB'];
    const i=Math.floor(Math.log(bytes)/Math.log(k));
    return parseFloat((bytes/k**i).toFixed(dm))+' '+sizes[i];
}

function formatBits(bits) {
    if (!bits || bits===0) return '0 bps';
    const k=1000;
    const sizes=['bps','Kbps','Mbps','Gbps','Tbps'];
    const i=Math.floor(Math.log(bits)/Math.log(k));
    return parseFloat((bits/k**i).toFixed(2))+' '+sizes[i];
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}
