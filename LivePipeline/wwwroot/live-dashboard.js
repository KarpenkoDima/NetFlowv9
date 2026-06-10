'use strict';

const MAX_TIME_POINTS = 60;
const WS_PATH = '/ws/metrics';

let ws;
let srcIpChart, dstIpChart, protocolChart, timeChart;

function formatBytes(bytes, decimals = 2) {
    if (!bytes || bytes <= 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const idx = Math.min(i, sizes.length - 1);
    return `${parseFloat((bytes / Math.pow(k, idx)).toFixed(dm))} ${sizes[idx]}`;
}

function formatBitsPerSecond(bps) {
    if (!bps || bps <= 0) return '0 bps';
    const k = 1000;
    const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
    const i = Math.floor(Math.log(bps) / Math.log(k));
    const idx = Math.min(i, sizes.length - 1);
    return `${parseFloat((bps / Math.pow(k, idx)).toFixed(2))} ${sizes[idx]}`;
}

function generateColors(count) {
    const background = [];
    const border = [];
    for (let i = 0; i < count; i++) {
        const hue = Math.round((360 / Math.max(count, 1)) * i);
        background.push(`hsla(${hue}, 70%, 55%, 0.6)`);
        border.push(`hsla(${hue}, 70%, 55%, 1)`);
    }
    return { background, border };
}

function initCharts() {
    const srcCtx = document.getElementById('src-ip-chart').getContext('2d');
    srcIpChart = new Chart(srcCtx, {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Bytes', data: [], backgroundColor: 'hsla(210, 70%, 55%, 0.6)', borderColor: 'hsla(210, 70%, 55%, 1)', borderWidth: 1 }] },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: { callbacks: { label: (ctx) => formatBytes(ctx.parsed.x) } },
                legend: { display: false }
            },
            scales: { x: { ticks: { callback: (v) => formatBytes(v) } } }
        }
    });

    const dstCtx = document.getElementById('dst-ip-chart').getContext('2d');
    dstIpChart = new Chart(dstCtx, {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Bytes', data: [], backgroundColor: 'hsla(150, 70%, 45%, 0.6)', borderColor: 'hsla(150, 70%, 45%, 1)', borderWidth: 1 }] },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: { callbacks: { label: (ctx) => formatBytes(ctx.parsed.x) } },
                legend: { display: false }
            },
            scales: { x: { ticks: { callback: (v) => formatBytes(v) } } }
        }
    });

    const protoCtx = document.getElementById('protocol-chart').getContext('2d');
    protocolChart = new Chart(protoCtx, {
        type: 'doughnut',
        data: { labels: [], datasets: [{ label: 'Bytes', data: [], backgroundColor: [], borderColor: [], borderWidth: 1 }] },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: { callbacks: { label: (ctx) => `${ctx.label}: ${formatBytes(ctx.parsed)}` } }
            }
        }
    });

    const timeCtx = document.getElementById('time-chart').getContext('2d');
    timeChart = new Chart(timeCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Bits/sec',
                    data: [],
                    borderColor: 'hsla(210, 80%, 60%, 1)',
                    backgroundColor: 'hsla(210, 80%, 60%, 0.2)',
                    yAxisID: 'bps',
                    tension: 0.2,
                    pointRadius: 0
                },
                {
                    label: 'Packets/sec',
                    data: [],
                    borderColor: 'hsla(30, 80%, 55%, 1)',
                    backgroundColor: 'hsla(30, 80%, 55%, 0.2)',
                    yAxisID: 'pps',
                    tension: 0.2,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            scales: {
                bps: {
                    type: 'linear',
                    position: 'left',
                    ticks: { callback: (v) => formatBitsPerSecond(v) }
                },
                pps: {
                    type: 'linear',
                    position: 'right',
                    grid: { drawOnChartArea: false }
                }
            }
        }
    });
}

function updateDashboard(snapshot) {
    document.getElementById('kpi-flows').textContent = snapshot.totalFlows;
    document.getElementById('kpi-bps').textContent = formatBitsPerSecond(snapshot.bitsPerSecond);
    document.getElementById('kpi-pps').textContent = Math.round(snapshot.packetsPerSec);
    document.getElementById('kpi-updated').textContent = new Date(snapshot.timestamp).toLocaleTimeString();

    const label = new Date(snapshot.timestamp).toLocaleTimeString();
    timeChart.data.labels.push(label);
    timeChart.data.datasets[0].data.push(snapshot.bitsPerSecond);
    timeChart.data.datasets[1].data.push(snapshot.packetsPerSec);
    if (timeChart.data.labels.length > MAX_TIME_POINTS) {
        timeChart.data.labels.shift();
        timeChart.data.datasets[0].data.shift();
        timeChart.data.datasets[1].data.shift();
    }
    timeChart.update('none');

    srcIpChart.data.labels = (snapshot.topSrcIPs || []).map(e => e.ip);
    srcIpChart.data.datasets[0].data = (snapshot.topSrcIPs || []).map(e => e.bytes);
    srcIpChart.update('none');

    dstIpChart.data.labels = (snapshot.topDstIPs || []).map(e => e.ip);
    dstIpChart.data.datasets[0].data = (snapshot.topDstIPs || []).map(e => e.bytes);
    dstIpChart.update('none');

    const protocols = snapshot.protocols || [];
    const colors = generateColors(protocols.length);
    protocolChart.data.labels = protocols.map(p => p.name);
    protocolChart.data.datasets[0].data = protocols.map(p => p.bytes);
    protocolChart.data.datasets[0].backgroundColor = colors.background;
    protocolChart.data.datasets[0].borderColor = colors.border;
    protocolChart.update('none');
}

function setStatus(connected) {
    const dot = document.querySelector('.dot');
    const statusDiv = document.getElementById('connection-status');
    const statusText = document.getElementById('status-text');

    if (connected) {
        dot.classList.add('live');
        dot.classList.remove('reconnecting');
        statusDiv.classList.add('live');
        statusDiv.classList.remove('reconnecting');
        statusText.textContent = 'Live';
    } else {
        dot.classList.add('reconnecting');
        dot.classList.remove('live');
        statusDiv.classList.add('reconnecting');
        statusDiv.classList.remove('live');
        statusText.textContent = 'Reconnecting...';
    }
}

function connect() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}${WS_PATH}`);

    ws.onopen = () => setStatus(true);

    ws.onmessage = (e) => {
        try {
            updateDashboard(JSON.parse(e.data));
        } catch (err) {
            console.error('Failed to parse snapshot', err);
        }
    };

    ws.onclose = () => {
        setStatus(false);
        setTimeout(connect, 2000);
    };

    ws.onerror = () => ws.close();
}

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    setStatus(false);
    connect();
});
