// Global variables
let netflowData = null;
let charts = {};
let currentFlowPage = 1;
const recordsPerPage = 100;
let totalFlowRecords = 0;
let allFlowRecords = [];

// Initialize the dashboard when the page loads
document.addEventListener('DOMContentLoaded', () => {
    // Add event listener for file upload
    document.getElementById('upload-file').addEventListener('change', handleFileUpload);
    
    // Setup tab navigation
    setupTabs();
});

// Handle tab navigation
function setupTabs() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remove active class from all tabs
            tabs.forEach(t => t.classList.remove('active'));
            
            // Add active class to clicked tab
            tab.classList.add('active');
            
            // Hide all tab content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Show the content of the clicked tab
            const tabId = tab.getAttribute('data-tab');
            document.getElementById(`${tabId}-tab`).classList.add('active');
        });
    });
}

// Handle file upload
function handleFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    // Update file name display
    document.getElementById('file-name').textContent = file.name;
    
    // Show loading message
    document.getElementById('loading').textContent = 'Loading NetFlow data...';
    
    // Read the file as JSON
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            netflowData = JSON.parse(e.target.result);
            processNetFlowData(netflowData);
            
            // Hide loading and show dashboard
            document.getElementById('loading').style.display = 'none';
            document.getElementById('dashboard-container').style.display = 'block';
        } catch (error) {
            document.getElementById('loading').textContent = `Error parsing JSON: ${error.message}`;
        }
    };
    
    reader.onerror = function() {
        document.getElementById('loading').textContent = 'Error reading file';
    };
    
    reader.readAsText(file);
}

// Process NetFlow data and update dashboard
function processNetFlowData(data) {
    // Display NetFlow version
    if (data.version) {
        document.getElementById('netflow-version').textContent = `NetFlow v${data.version}`;
    }
    
    // Update summary statistics
    updateSummaryStats(data);
    
    // Create charts
    createCharts(data);
    
    // Populate flow records table - pass data to initialize all records
    populateFlowsTable(data);
    
    // Display template records
    displayTemplates(data);
    
    // Show raw data
    document.getElementById('raw-data').textContent = JSON.stringify(data, null, 2);
}

// Update summary statistics
function updateSummaryStats(data) {
    // Count packets
    const totalPackets = data.packets ? data.packets.length : 0;
    document.getElementById('total-packets').textContent = totalPackets;
    
    // Count flow records
    let totalFlows = 0;
    if (data.packets) {
        data.packets.forEach(packet => {
            if (packet.flowSets) {
                packet.flowSets.forEach(flowSet => {
                    if (flowSet.records) {
                        totalFlows += flowSet.records.length;
                    }
                });
            }
        });
    }
    document.getElementById('total-flows').textContent = totalFlows;
    
    // Count templates
    let totalTemplates = 0;
    if (data.templates) {
        totalTemplates = Object.keys(data.templates).length;
    }
    document.getElementById('total-templates').textContent = totalTemplates;
    
    // Calculate time span
    let minTime = Infinity;
    let maxTime = 0;
    
    if (data.packets) {
        data.packets.forEach(packet => {
            if (packet.unixSecs) {
                minTime = Math.min(minTime, packet.unixSecs);
                maxTime = Math.max(maxTime, packet.unixSecs);
            }
        });
    }
    
    if (minTime !== Infinity && maxTime !== 0) {
        const timeSpanSeconds = maxTime - minTime;
        if (timeSpanSeconds < 60) {
            document.getElementById('time-span').textContent = `${timeSpanSeconds}s`;
        } else if (timeSpanSeconds < 3600) {
            document.getElementById('time-span').textContent = `${Math.round(timeSpanSeconds / 60)}m`;
        } else {
            document.getElementById('time-span').textContent = `${Math.round(timeSpanSeconds / 3600)}h`;
        }
    } else {
        document.getElementById('time-span').textContent = 'N/A';
    }
}

// Extract flow records from data
function extractFlowRecords(data) {
    const flowRecords = [];
    
    if (data.packets) {
        data.packets.forEach(packet => {
            if (packet.flowSets) {
                packet.flowSets.forEach(flowSet => {
                    if (flowSet.flowSetId >= 256 && flowSet.records) {
                        flowSet.records.forEach(record => {
                            // Transform record format for easier access
                            const processedRecord = {};
                            
                            for (const [fieldType, value] of Object.entries(record)) {
                                // Map field type numbers to names
                                const fieldName = getFieldName(parseInt(fieldType));
                                processedRecord[fieldName] = value;
                            }
                            
                            // Add timestamp from packet if not in record
                            if (!processedRecord.startTime && packet.unixSecs) {
                                processedRecord.startTime = new Date(packet.unixSecs * 1000).toISOString();
                            }
                            
                            flowRecords.push(processedRecord);
                        });
                    }
                });
            }
        });
    }
    
    return flowRecords;
}

// Get field name from type number
function getFieldName(fieldType) {
    const fieldNames = {
        1: 'bytes',
        2: 'packets',
        4: 'protocol',
        5: 'tos',
        6: 'tcpFlags',
        7: 'srcPort',
        8: 'srcIP',
        9: 'srcMask',
        10: 'inputIF',
        11: 'dstPort',
        12: 'dstIP',
        13: 'dstMask',
        14: 'outputIF',
        15: 'nextHop',
        21: 'srcMAC',
        22: 'dstMAC',
        34: 'startTime',
        35: 'endTime',
        56: 'flowStartSysUptime',
        57: 'flowEndSysUptime',
        80: 'flowStartUnix',
        81: 'flowEndUnix',
        225: 'postNATSrcIP',
        226: 'postNATDstIP',
        227: 'postNATSrcPort',
        228: 'postNATDstPort'
    };
    
    return fieldNames[fieldType] || `field${fieldType}`;
}

// Create charts based on NetFlow data
function createCharts(data) {
    // First destroy any existing charts
    Object.values(charts).forEach(chart => {
        if (chart) {
            chart.destroy();
        }
    });
    charts = {};
    
    const flowRecords = extractFlowRecords(data);
    
    // Create Traffic by IP chart
    createIPChart(flowRecords);
    
    // Create Traffic by Port chart
    createPortChart(flowRecords);
    
    // Create Protocol Distribution chart
    createProtocolChart(flowRecords);
    
    // Create Traffic Over Time chart
    createTimeChart(flowRecords);
}

// Create IP traffic chart
function createIPChart(flowRecords) {
    // Aggregate data by IP
    const ipTraffic = {};
    
    flowRecords.forEach(record => {
        // Source IP traffic
        if (record.srcIP) {
            if (!ipTraffic[record.srcIP]) {
                ipTraffic[record.srcIP] = 0;
            }
            ipTraffic[record.srcIP] += parseInt(record.bytes) || 0;
        }
        
        // Destination IP traffic
        if (record.dstIP) {
            if (!ipTraffic[record.dstIP]) {
                ipTraffic[record.dstIP] = 0;
            }
            ipTraffic[record.dstIP] += parseInt(record.bytes) || 0;
        }
    });
    
    // Sort IPs by traffic and get top 10
    const sortedIPs = Object.entries(ipTraffic)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
    
    const labels = sortedIPs.map(entry => entry[0]);
    const values = sortedIPs.map(entry => entry[1]);
    
    // Create chart
    const ctx = document.getElementById('ip-chart').getContext('2d');
    charts.ipChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Traffic (Bytes)',
                data: values,
                backgroundColor: 'rgba(54, 162, 235, 0.7)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return formatBytes(context.raw);
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    }
                }
            }
        }
    });
}

// Create Port traffic chart
function createPortChart(flowRecords) {
    // Aggregate data by Port
    const portTraffic = {};
    
    flowRecords.forEach(record => {
        // Source Port traffic
        if (record.srcPort) {
            const port = record.srcPort;
            if (!portTraffic[port]) {
                portTraffic[port] = 0;
            }
            portTraffic[port] += parseInt(record.bytes) || 0;
        }
        
        // Destination Port traffic
        if (record.dstPort) {
            const port = record.dstPort;
            if (!portTraffic[port]) {
                portTraffic[port] = 0;
            }
            portTraffic[port] += parseInt(record.bytes) || 0;
        }
    });
    
    // Sort Ports by traffic and get top 10
    const sortedPorts = Object.entries(portTraffic)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
    
    const labels = sortedPorts.map(entry => {
        const port = parseInt(entry[0]);
        return getWellKnownPort(port) || `Port ${port}`;
    });
    const values = sortedPorts.map(entry => entry[1]);
    
    // Create chart
    const ctx = document.getElementById('port-chart').getContext('2d');
    charts.portChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Traffic (Bytes)',
                data: values,
                backgroundColor: 'rgba(75, 192, 192, 0.7)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return formatBytes(context.raw);
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: {
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    }
                }
            }
        }
    });
}

// Get well-known port name
function getWellKnownPort(port) {
    const portMap = {
        20: 'FTP-Data (20)',
        21: 'FTP (21)',
        22: 'SSH (22)',
        23: 'Telnet (23)',
        25: 'SMTP (25)',
        53: 'DNS (53)',
        80: 'HTTP (80)',
        110: 'POP3 (110)',
        123: 'NTP (123)',
        143: 'IMAP (143)',
        161: 'SNMP (161)',
        443: 'HTTPS (443)',
        465: 'SMTPS (465)',
        993: 'IMAPS (993)',
        995: 'POP3S (995)',
        1433: 'SQL Server (1433)',
        3306: 'MySQL (3306)',
        3389: 'RDP (3389)',
        5060: 'SIP (5060)',
        8080: 'HTTP Proxy (8080)'
    };
    
    return portMap[port];
}

// Create Protocol Distribution chart
function createProtocolChart(flowRecords) {
    // Aggregate data by Protocol
    const protocolTraffic = {};
    
    flowRecords.forEach(record => {
        if (record.protocol) {
            const protocol = getProtocolName(parseInt(record.protocol));
            if (!protocolTraffic[protocol]) {
                protocolTraffic[protocol] = 0;
            }
            protocolTraffic[protocol] += parseInt(record.bytes) || 0;
        }
    });
    
    // Sort and prepare chart data
    const sortedProtocols = Object.entries(protocolTraffic)
        .sort((a, b) => b[1] - a[1]);
    
    const labels = sortedProtocols.map(entry => entry[0]);
    const values = sortedProtocols.map(entry => entry[1]);
    
    // Generate colors
    const colors = generateColors(labels.length);
    
    // Create chart with improved configuration
    const ctx = document.getElementById('protocol-chart').getContext('2d');
    charts.protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors.bg,
                borderColor: colors.border,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '50%',
            plugins: {
                legend: {
                    position: 'top',
                    align: 'start',
                    labels: {
                        boxWidth: 15,
                        padding: 15,
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const value = context.raw;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${context.label}: ${formatBytes(value)} (${percentage}%)`;
                        }
                    }
                }
            },
            animation: {
                animateScale: true,
                animateRotate: true
            }
        }
    });
    
    // Fix chart rendering after a short delay
    setTimeout(() => {
        if (charts.protocolChart) {
            charts.protocolChart.resize();
        }
    }, 100);
}

// Get protocol name from number
function getProtocolName(protocolNum) {
    const protocols = {
        1: 'ICMP (1)',
        2: 'IGMP (2)',
        6: 'TCP (6)',
        17: 'UDP (17)',
        47: 'GRE (47)',
        50: 'ESP (50)',
        51: 'AH (51)',
        58: 'IPv6-ICMP (58)',
        89: 'OSPF (89)',
        132: 'SCTP (132)'
    };
    
    return protocols[protocolNum] || `Protocol ${protocolNum}`;
}

// Create Traffic Over Time chart
function createTimeChart(flowRecords) {
    // Group traffic by time intervals (5-minute buckets)
    const timeTraffic = {};
    const INTERVAL = 5 * 60 * 1000; // 5 minutes in milliseconds
    
    flowRecords.forEach(record => {
        let timestamp;
        
        // Try different time fields
        if (record.flowStartUnix) {
            timestamp = parseInt(record.flowStartUnix) * 1000;
        } else if (record.startTime) {
            timestamp = new Date(record.startTime).getTime();
        } else if (record.flowEndUnix) {
            timestamp = parseInt(record.flowEndUnix) * 1000;
        } else if (record.endTime) {
            timestamp = new Date(record.endTime).getTime();
        }
        
        if (timestamp) {
            // Round to nearest interval
            const bucket = Math.floor(timestamp / INTERVAL) * INTERVAL;
            
            if (!timeTraffic[bucket]) {
                timeTraffic[bucket] = { bytes: 0, packets: 0 };
            }
            
            timeTraffic[bucket].bytes += parseInt(record.bytes) || 0;
            timeTraffic[bucket].packets += parseInt(record.packets) || 0;
        }
    });
    
    // Sort by time and prepare data
    const sortedTimes = Object.entries(timeTraffic)
        .sort((a, b) => parseInt(a[0]) - parseInt(b[0]));
    
    const labels = sortedTimes.map(entry => new Date(parseInt(entry[0])).toLocaleTimeString());
    const byteValues = sortedTimes.map(entry => entry[1].bytes);
    const packetValues = sortedTimes.map(entry => entry[1].packets);
    
    // Create chart
    const ctx = document.getElementById('time-chart').getContext('2d');
    charts.timeChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Bytes',
                    data: byteValues,
                    yAxisID: 'bytes',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    fill: true,
                    tension: 0.1
                },
                {
                    label: 'Packets',
                    data: packetValues,
                    yAxisID: 'packets',
                    borderColor: 'rgba(255, 99, 132, 1)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    fill: true,
                    tension: 0.1
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                bytes: {
                    type: 'linear',
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Bytes'
                    },
                    ticks: {
                        callback: function(value) {
                            return formatBytes(value, 0);
                        }
                    }
                },
                packets: {
                    type: 'linear',
                    position: 'right',
                    title: {
                        display: true,
                        text: 'Packets'
                    },
                    grid: {
                        drawOnChartArea: false
                    }
                }
            }
        }
    });
}

// Generate colors for charts
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
        const colorIndex = i % baseColors.length;
        const [r, g, b] = baseColors[colorIndex];
        
        bg.push(`rgba(${r}, ${g}, ${b}, 0.7)`);
        border.push(`rgba(${r}, ${g}, ${b}, 1)`);
    }
    
    return { bg, border };
}

// Format bytes to human-readable
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Pagination setup
function setupPagination() {
    // Create pagination container if it doesn't exist
    let paginationContainer = document.getElementById('flows-pagination');
    if (!paginationContainer) {
        const tableContainer = document.querySelector('#flows-tab .table-container');
        paginationContainer = document.createElement('div');
        paginationContainer.id = 'flows-pagination';
        paginationContainer.className = 'pagination-controls';
        tableContainer.parentNode.insertBefore(paginationContainer, tableContainer.nextSibling);
    }
    
    // Clear existing pagination
    paginationContainer.innerHTML = '';
    
    // Calculate total pages
    const totalPages = Math.ceil(totalFlowRecords / recordsPerPage);
    
    // Don't show pagination if only one page
    if (totalPages <= 1) {
        return;
    }
    
    // Add first page button
    const firstBtn = document.createElement('button');
    firstBtn.innerHTML = '&laquo;';
    firstBtn.classList.add('pagination-btn');
    firstBtn.disabled = currentFlowPage === 1;
    firstBtn.addEventListener('click', () => {
        currentFlowPage = 1;
        populateFlowsTable();
    });
    paginationContainer.appendChild(firstBtn);
    
    // Add previous button
    const prevBtn = document.createElement('button');
    prevBtn.innerHTML = '&lsaquo;';
    prevBtn.classList.add('pagination-btn');
    prevBtn.disabled = currentFlowPage === 1;
    prevBtn.addEventListener('click', () => {
        if (currentFlowPage > 1) {
            currentFlowPage--;
            populateFlowsTable();
        }
    });
    paginationContainer.appendChild(prevBtn);
    
    // Add page number and total indicator
    const pageInfo = document.createElement('span');
    pageInfo.textContent = `Page ${currentFlowPage} of ${totalPages}`;
    pageInfo.style.margin = '0 10px';
    pageInfo.classList.add('pagination-info');
    paginationContainer.appendChild(pageInfo);
    
    // Add next button
    const nextBtn = document.createElement('button');
    nextBtn.innerHTML = '&rsaquo;';
    nextBtn.classList.add('pagination-btn');
    nextBtn.disabled = currentFlowPage === totalPages;
    nextBtn.addEventListener('click', () => {
        if (currentFlowPage < totalPages) {
            currentFlowPage++;
            populateFlowsTable();
        }
    });
    paginationContainer.appendChild(nextBtn);
    
    // Add last page button
    const lastBtn = document.createElement('button');
    lastBtn.innerHTML = '&raquo;';
    lastBtn.classList.add('pagination-btn');
    lastBtn.disabled = currentFlowPage === totalPages;
    lastBtn.addEventListener('click', () => {
        currentFlowPage = totalPages;
        populateFlowsTable();
    });
    paginationContainer.appendChild(lastBtn);
    
    // Add record count info
    const recordInfo = document.createElement('div');
    recordInfo.textContent = `Showing records ${(currentFlowPage - 1) * recordsPerPage + 1} to ${Math.min(currentFlowPage * recordsPerPage, totalFlowRecords)} of ${totalFlowRecords}`;
    recordInfo.classList.add('record-info');
    paginationContainer.appendChild(recordInfo);
}

// Populate flows table with pagination
function populateFlowsTable(data) {
    // If data is provided, it's the initial load
    if (data) {
        allFlowRecords = extractFlowRecords(data);
        totalFlowRecords = allFlowRecords.length;
        currentFlowPage = 1;
    }
    
    const tbody = document.querySelector('#flows-table tbody');
    tbody.innerHTML = '';
    
    // Calculate start and end indexes for current page
    const startIndex = (currentFlowPage - 1) * recordsPerPage;
    const endIndex = Math.min(startIndex + recordsPerPage, totalFlowRecords);
    
    // Get records for current page
    const recordsToShow = allFlowRecords.slice(startIndex, endIndex);
    
    if (recordsToShow.length === 0) {
        const noDataRow = document.createElement('tr');
        const noDataCell = document.createElement('td');
        noDataCell.colSpan = 9;
        noDataCell.textContent = 'No records found';
        noDataCell.style.textAlign = 'center';
        noDataCell.style.padding = '20px';
        noDataRow.appendChild(noDataCell);
        tbody.appendChild(noDataRow);
        return;
    }
    
    recordsToShow.forEach(record => {
        const row = document.createElement('tr');
        
        // Source IP
        row.appendChild(createTableCell(record.srcIP || '-'));
        
        // Source Port
        row.appendChild(createTableCell(record.srcPort || '-'));
        
        // Destination IP
        row.appendChild(createTableCell(record.dstIP || '-'));
        
        // Destination Port
        row.appendChild(createTableCell(record.dstPort || '-'));
        
        // Protocol
        const protocolNum = parseInt(record.protocol);
        const protocolName = protocolNum ? (getProtocolName(protocolNum) || protocolNum) : '-';
        row.appendChild(createTableCell(protocolName));
        
        // Bytes
        row.appendChild(createTableCell(record.bytes ? formatBytes(record.bytes) : '-'));
        
        // Packets
        row.appendChild(createTableCell(record.packets || '-'));
        
        // Start Time
        let startTime = '-';
        if (record.flowStartUnix) {
            try {
                startTime = new Date(parseInt(record.flowStartUnix) * 1000).toLocaleString();
            } catch (e) {
                startTime = record.flowStartUnix;
            }
        } else if (record.startTime) {
            try {
                startTime = new Date(record.startTime).toLocaleString();
            } catch (e) {
                startTime = record.startTime;
            }
        }
        row.appendChild(createTableCell(startTime));
        
        // End Time
        let endTime = '-';
        if (record.flowEndUnix) {
            try {
                endTime = new Date(parseInt(record.flowEndUnix) * 1000).toLocaleString();
            } catch (e) {
                endTime = record.flowEndUnix;
            }
        } else if (record.endTime) {
            try {
                endTime = new Date(record.endTime).toLocaleString();
            } catch (e) {
                endTime = record.endTime;
            }
        }
        row.appendChild(createTableCell(endTime));
        
        tbody.appendChild(row);
    });
    
    // Update pagination controls
    setupPagination();
}

// Create table cell
function createTableCell(content) {
    const cell = document.createElement('td');
    cell.textContent = content;
    return cell;
}

// Display template records
function displayTemplates(data) {
    const container = document.getElementById('templates-container');
    container.innerHTML = '';
    
    // Extract templates
    const templates = [];
    
    if (data.templates) {
        for (const sourceId in data.templates) {
            for (const templateId in data.templates[sourceId]) {
                templates.push({
                    sourceId: sourceId,
                    templateId: templateId,
                    ...data.templates[sourceId][templateId]
                });
            }
        }
    } else if (data.packets) {
        // Try to extract templates from packets
        data.packets.forEach(packet => {
            if (packet.flowSets) {
                packet.flowSets.forEach(flowSet => {
                    if (flowSet.flowSetId === 0 && flowSet.templates) {
                        flowSet.templates.forEach(template => {
                            templates.push({
                                sourceId: packet.sourceId,
                                templateId: template.templateId,
                                ...template
                            });
                        });
                    }
                });
            }
        });
    }
    
    // Display templates
    if (templates.length === 0) {
        container.innerHTML = '<p>No template records found</p>';
        return;
    }
    
    templates.forEach(template => {
        const templateDiv = document.createElement('div');
        templateDiv.classList.add('card');
        templateDiv.style.marginBottom = '15px';
        
        const header = document.createElement('h4');
        header.textContent = `Template ID: ${template.templateId}, Source ID: ${template.sourceId}`;
        templateDiv.appendChild(header);
        
        // Create table for fields
        if (template.fields && template.fields.length > 0) {
            const table = document.createElement('table');
            
            // Table header
            const thead = document.createElement('thead');
            const headerRow = document.createElement('tr');
            ['Field Type', 'Field Name', 'Length'].forEach(colName => {
                const th = document.createElement('th');
                th.textContent = colName;
                headerRow.appendChild(th);
            });
            thead.appendChild(headerRow);
            table.appendChild(thead);
            
            // Table body
            const tbody = document.createElement('tbody');
            template.fields.forEach(field => {
                const row = document.createElement('tr');
                
                // Field Type
                const typeCell = document.createElement('td');
                typeCell.textContent = field.type;
                row.appendChild(typeCell);
                
                // Field Name
                const nameCell = document.createElement('td');
                nameCell.textContent = getFieldName(field.type);
                row.appendChild(nameCell);
                
                // Length
                const lengthCell = document.createElement('td');
                lengthCell.textContent = field.length;
                row.appendChild(lengthCell);
                
                tbody.appendChild(row);
            });
            table.appendChild(tbody);
            
            templateDiv.appendChild(table);
        } else {
            const noFields = document.createElement('p');
            noFields.textContent = 'No fields defined in this template';
            templateDiv.appendChild(noFields);
        }
        
        container.appendChild(templateDiv);
    });
}