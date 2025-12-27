# Building a NetFlow v9 Analyzer from Scratch
## A Complete Guide to Network Traffic Analysis with C# and Clean Architecture

*In the style of Manning Publications and No Starch Press*

---

## Table of Contents

### Part I: Understanding the Problem
1. [What is NetFlow and Why Should You Care?](#chapter-1)
2. [Understanding the NetFlow v9 Protocol](#chapter-2)
3. [Reading Network Packets: A Primer](#chapter-3)

### Part II: Architecture and Design
4. [Choosing the Right Architecture](#chapter-4)
5. [Domain Modeling: From RFC to Code](#chapter-5)
6. [Designing for Testability](#chapter-6)

### Part III: Building the Parser
7. [Parsing Binary Data in .NET](#chapter-7)
8. [Implementing the NetFlow Header Parser](#chapter-8)
9. [Template Management and Caching](#chapter-9)
10. [Parsing Data FlowSets](#chapter-10)

### Part IV: Infrastructure and I/O
11. [Reading PCAP Files](#chapter-11)
12. [Exporting to JSON](#chapter-12)
13. [Building the CLI Application](#chapter-13)

### Part V: Testing and Quality
14. [Unit Testing Binary Parsers](#chapter-14)
15. [Integration Testing with Real Data](#chapter-15)
16. [Performance Optimization](#chapter-16)

### Part VI: Advanced Topics
17. [Adding Support for Other NetFlow Versions](#chapter-17)
18. [Real-time Packet Capture](#chapter-18)
19. [Building a Web Dashboard](#chapter-19)
20. [Production Deployment](#chapter-20)

---

# Part I: Understanding the Problem

<a name="chapter-1"></a>
## Chapter 1: What is NetFlow and Why Should You Care?

### The Network Visibility Problem

Imagine you're managing a corporate network with hundreds of devices. One day, your internet connection slows to a crawl. What's happening? Who's using the bandwidth? What applications are running? Where's the traffic going?

Traditional packet capture tools like Wireshark can help, but they have a problem: **they capture everything**. A busy network generates gigabytes of packet data per hour. You can't store it all, and analyzing it becomes impossible.

**NetFlow is the solution.** Instead of capturing full packets, NetFlow collects **flow metadata**:

```
A flow is a unidirectional sequence of packets sharing:
- Source IP and port
- Destination IP and port
- Protocol (TCP, UDP, etc.)
- Start and end time
- Byte and packet counts
```

### Real-World Use Cases

**1. Security Analysis**
```
Detect anomalies like:
- Port scans (many connections to different ports)
- DDoS attacks (high packet rates from single source)
- Data exfiltration (large uploads to unusual destinations)
```

**2. Capacity Planning**
```
Answer questions like:
- What's our peak traffic time?
- Which applications use most bandwidth?
- Do we need to upgrade our internet connection?
```

**3. Billing and Accounting**
```
- Track per-user bandwidth consumption
- Bill customers based on actual usage
- Identify bandwidth-heavy applications
```

### Why NetFlow v9?

NetFlow has evolved through several versions:

| Version | Year | Features | Limitation |
|---------|------|----------|------------|
| v5 | 1996 | Fixed format, IPv4 only | No IPv6, no customization |
| v7 | 1998 | Cisco Catalyst switches | Proprietary |
| v9 | 2004 | **Flexible templates, IPv6** | More complex |
| IPFIX (v10) | 2008 | IETF standard | Even more complex |

**We choose v9 because:**
- ✅ Flexible template system (supports custom fields)
- ✅ IPv4 and IPv6 support
- ✅ Widely supported by routers and switches
- ✅ Well-documented (RFC 3954)
- ✅ Not as complex as IPFIX

### How NetFlow Works

```
┌─────────────┐         NetFlow          ┌──────────────┐
│   Router    │ ─────► Packets (v9) ───►│   Collector  │
│  (Exporter) │        UDP:2055          │  (Our App)   │
└─────────────┘                          └──────────────┘
       │                                        │
       │ Observes                               │ Analyzes
       │ Real Traffic                           │ Flow Data
       ▼                                        ▼
    Internet                             ┌──────────────┐
    Traffic                              │  Dashboard   │
                                         │ Visualization│
                                         └──────────────┘
```

**The Process:**

1. **Router/Switch** observes network traffic
2. **Groups packets** into flows (same 5-tuple)
3. **Exports flow records** to collector via UDP
4. **Collector (our app)** parses and stores data
5. **Dashboard** visualizes insights

### What We'll Build

By the end of this guide, you'll have:

```
NetFlowAnalizer/
├── Parser that understands NetFlow v9 protocol
├── PCAP reader for analyzing captures
├── JSON exporter for web visualization
├── Template caching system
├── Clean, testable architecture
└── Production-ready CLI tool
```

**And you'll understand:**
- Binary protocol parsing
- Network data structures
- Clean Architecture principles
- Dependency Injection patterns
- Type-safe error handling
- Performance optimization

Let's begin!

---

<a name="chapter-2"></a>
## Chapter 2: Understanding the NetFlow v9 Protocol

### The Template-Based Design

NetFlow v9's innovation is its **template system**. Unlike v5's fixed format, v9 lets exporters define custom fields.

**Think of it like a database:**
```
Template = Table Schema
Data FlowSet = Table Rows
```

### The Packet Structure

Every NetFlow v9 packet has three parts:

```
┌─────────────────────────────────────────┐
│         PACKET HEADER (20 bytes)        │
│  - Version, Count, Timestamps, etc.     │
├─────────────────────────────────────────┤
│         FLOWSET #1 (variable)           │
│  Could be Template or Data              │
├─────────────────────────────────────────┤
│         FLOWSET #2 (variable)           │
│  Could be Template or Data              │
├─────────────────────────────────────────┤
│              ... more ...               │
└─────────────────────────────────────────┘
```

### Part 1: The Packet Header (20 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Version (0x0009)        |            Count              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         sysUpTime                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         UNIX Seconds                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Sequence Number                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Source ID                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Field Breakdown:**

| Field | Bytes | Description | Example |
|-------|-------|-------------|---------|
| Version | 2 | Always 9 (0x0009) | 9 |
| Count | 2 | Number of FlowSets in packet | 5 |
| sysUpTime | 4 | Router uptime in ms | 19088743 |
| UNIX Seconds | 4 | Timestamp when packet sent | 1699147536 |
| Sequence Number | 4 | Incremental counter | 1234 |
| Source ID | 4 | Exporter identifier | 171 |

**Why these fields matter:**

```csharp
// Sequence Number: Detect packet loss
if (currentSeq != lastSeq + 1)
    Console.WriteLine($"Lost {currentSeq - lastSeq - 1} packets!");

// Source ID: Support multiple exporters
// Different routers can send to same collector
templates[sourceId][templateId] = template;

// UNIX Seconds: Timeline analysis
var timestamp = DateTimeOffset.FromUnixTimeSeconds(unixSecs);
```

### Part 2: FlowSet Header (4 bytes)

Each FlowSet starts with:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       FlowSet ID              |          Length               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        FlowSet Data                           |
|                           (variable)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**FlowSet ID determines type:**

```
ID = 0       → Template FlowSet
ID = 1       → Options Template FlowSet
ID = 2-255   → Reserved
ID ≥ 256     → Data FlowSet (ID = Template ID)
```

**Example:**
```
FlowSet ID = 0, Length = 52
  → This is a Template FlowSet, 52 bytes total

FlowSet ID = 256, Length = 120
  → This is Data using Template 256, 120 bytes total
```

### Part 3: Template FlowSet (ID = 0)

Templates define the structure of data records:

```
┌────────────────────────────────────┐
│  FlowSet Header                    │
│  - FlowSet ID = 0                  │
│  - Length = total bytes            │
├────────────────────────────────────┤
│  Template Record #1                │
│  - Template ID (e.g., 256)         │
│  - Field Count (e.g., 5)           │
│  - Field 1: Type=8, Length=4       │  (Source IP)
│  - Field 2: Type=12, Length=4      │  (Dest IP)
│  - Field 3: Type=7, Length=2       │  (Source Port)
│  - Field 4: Type=11, Length=2      │  (Dest Port)
│  - Field 5: Type=4, Length=1       │  (Protocol)
├────────────────────────────────────┤
│  Template Record #2 (optional)     │
└────────────────────────────────────┘
```

**Parsing Logic:**
```csharp
// Read template header
templateId = ReadUInt16();      // 256
fieldCount = ReadUInt16();      // 5

// Read field definitions
for (int i = 0; i < fieldCount; i++) {
    fieldType = ReadUInt16();   // 8 (Source IP)
    fieldLength = ReadUInt16(); // 4 bytes
    template.Fields.Add(new Field(fieldType, fieldLength));
}

// Cache template for later use
cache[sourceId][templateId] = template;
```

### Part 4: Data FlowSet (ID ≥ 256)

Data FlowSets contain actual flow records:

```
┌────────────────────────────────────┐
│  FlowSet Header                    │
│  - FlowSet ID = 256 (Template ID)  │
│  - Length = total bytes            │
├────────────────────────────────────┤
│  Flow Record #1                    │
│  - Field 1: 192.168.1.100 (4 bytes)│  Source IP
│  - Field 2: 8.8.8.8 (4 bytes)      │  Dest IP
│  - Field 3: 54321 (2 bytes)        │  Source Port
│  - Field 4: 53 (2 bytes)           │  Dest Port
│  - Field 5: 17 (1 byte)            │  Protocol (UDP)
├────────────────────────────────────┤
│  Flow Record #2                    │
│  - ... (same structure)            │
├────────────────────────────────────┤
│  Flow Record #3                    │
└────────────────────────────────────┘
```

**Parsing Logic:**
```csharp
// Get template from cache
template = cache[sourceId][flowSetId];

// Calculate record size
int recordSize = template.Fields.Sum(f => f.Length); // 13 bytes

// Parse multiple records
while (bytesRemaining >= recordSize) {
    var record = new DataRecord();

    foreach (var field in template.Fields) {
        byte[] data = ReadBytes(field.Length);
        record.Values[field.Type] = FormatField(field.Type, data);
    }

    records.Add(record);
}
```

### Common Field Types (RFC 3954)

| Type | Name | Length | Description | Format |
|------|------|--------|-------------|--------|
| 1 | IN_BYTES | 4 | Bytes in flow | uint32 |
| 2 | IN_PKTS | 4 | Packets in flow | uint32 |
| 4 | PROTOCOL | 1 | IP protocol | uint8 (6=TCP, 17=UDP) |
| 7 | L4_SRC_PORT | 2 | Source port | uint16 |
| 8 | IPV4_SRC_ADDR | 4 | Source IPv4 | 4 bytes (192.168.1.100) |
| 11 | L4_DST_PORT | 2 | Dest port | uint16 |
| 12 | IPV4_DST_ADDR | 4 | Dest IPv4 | 4 bytes (8.8.8.8) |
| 21 | LAST_SWITCHED | 4 | Flow end time | uint32 (sysUpTime) |
| 22 | FIRST_SWITCHED | 4 | Flow start time | uint32 (sysUpTime) |

### Example: Complete Packet Walkthrough

Let's parse a real NetFlow v9 packet (hex dump):

```
00 09 00 02 01 23 45 67 65 40 2F 0A 00 00 00 01 00 00 00 AB
00 00 00 18 01 00 00 02 00 08 00 04 00 0C 00 04
01 00 00 10 C0 A8 01 64 08 08 08 08
```

**Step 1: Parse Header (20 bytes)**
```
00 09           → Version = 9 ✓
00 02           → Count = 2 FlowSets
01 23 45 67     → sysUpTime = 19,088,743 ms
65 40 2F 0A     → UNIX Secs = 1,699,147,530 (2023-11-05)
00 00 00 01     → Sequence = 1
00 00 00 AB     → Source ID = 171
```

**Step 2: Parse FlowSet #1 - Template (24 bytes)**
```
00 00           → FlowSet ID = 0 (Template)
00 18           → Length = 24 bytes
01 00           → Template ID = 256
00 02           → Field Count = 2
  00 08 00 04   → Field 1: Type=8 (SRC IP), Length=4
  00 0C 00 04   → Field 2: Type=12 (DST IP), Length=4
```

**Step 3: Parse FlowSet #2 - Data (16 bytes)**
```
01 00           → FlowSet ID = 256 (use Template 256)
00 10           → Length = 16 bytes
  C0 A8 01 64   → 192.168.1.100 (Source IP)
  08 08 08 08   → 8.8.8.8 (Dest IP)
```

**Result:**
```json
{
  "header": {
    "version": 9,
    "sourceId": 171,
    "timestamp": "2023-11-05 14:25:30"
  },
  "templates": [{
    "id": 256,
    "fields": [
      {"type": 8, "name": "Source IP", "length": 4},
      {"type": 12, "name": "Dest IP", "length": 4}
    ]
  }],
  "flows": [{
    "templateId": 256,
    "srcIp": "192.168.1.100",
    "dstIp": "8.8.8.8"
  }]
}
```

### The Template Lifecycle

Understanding when templates are sent is crucial:

```
Time    Event
─────   ─────────────────────────────────────
T+0     Router boots, assigns Template IDs
T+1     Sends Template FlowSet (ID=256)
T+2     Sends Data FlowSet (uses Template 256)
T+3     Sends Data FlowSet (uses Template 256)
...     ... more data ...
T+300   Sends Template again (refresh interval)
T+301   Sends Data FlowSet
```

**Why template refresh?**
- Collectors might restart and lose templates
- UDP packets can be lost
- Templates might change (router reconfiguration)

**Parser must handle:**
```csharp
if (template == null) {
    Logger.Warn($"No template {templateId} for source {sourceId}");
    Logger.Info("Data will be skipped until template arrives");
    return; // Can't parse without template
}
```

### Big-Endian Byte Order

NetFlow uses **network byte order (big-endian)**:

```
Value: 0x01234567 (19,088,743)

Big-Endian (Network):    01 23 45 67
Little-Endian (Intel):   67 45 23 01
```

**C# reads little-endian by default:**
```csharp
// WRONG - gives wrong value on Intel CPUs
byte[] bytes = {0x01, 0x23, 0x45, 0x67};
uint value = BitConverter.ToUInt32(bytes); // ❌ Wrong!

// CORRECT - reverse bytes first
if (BitConverter.IsLittleEndian)
    Array.Reverse(bytes);
uint value = BitConverter.ToUInt32(bytes); // ✅ Correct: 19,088,743
```

### Chapter Summary

You now understand:

✅ **Why NetFlow v9 uses templates** (flexibility)
✅ **The three-part packet structure** (header + flowsets)
✅ **How templates work** (define data structure)
✅ **How data flowsets work** (use templates)
✅ **Field type system** (26+ standard types)
✅ **Byte order issues** (big-endian conversion)

**Next:** We'll learn how to read these packets from PCAP files and UDP sockets.

---

<a name="chapter-3"></a>
## Chapter 3: Reading Network Packets: A Primer

### The Packet Capture Problem

NetFlow packets travel over the network as **UDP datagrams**. To analyze them, we need to:

1. **Capture** packets from the network
2. **Filter** only NetFlow traffic (UDP port 2055)
3. **Extract** the payload
4. **Parse** the NetFlow data

### Two Approaches

**Approach 1: Read from PCAP file** (offline analysis)
```
Wireshark Capture → .pcap file → Our parser → Analysis
```

**Approach 2: Live capture** (real-time analysis)
```
Network interface → Packet filter → Our parser → Analysis
```

We'll focus on PCAP files first (easier), then show live capture.

### Understanding PCAP Format

PCAP (Packet Capture) is a standard format created by tcpdump:

```
┌──────────────────────────────────┐
│     PCAP Global Header           │
│  - Magic number, version, etc.   │
├──────────────────────────────────┤
│     Packet #1 Header             │
│  - Timestamp, captured length    │
│     Packet #1 Data               │
│  - Ethernet + IP + UDP + NetFlow │
├──────────────────────────────────┤
│     Packet #2 Header             │
│     Packet #2 Data               │
├──────────────────────────────────┤
│           ... more ...           │
└──────────────────────────────────┘
```

### Network Stack Layers

Each packet contains multiple protocol layers:

```
┌─────────────────────────────────────┐
│  Ethernet Header (14 bytes)         │  Layer 2
│  - Src MAC, Dst MAC, Type           │
├─────────────────────────────────────┤
│  IP Header (20+ bytes)              │  Layer 3
│  - Src IP, Dst IP, Protocol         │
├─────────────────────────────────────┤
│  UDP Header (8 bytes)               │  Layer 4
│  - Src Port, Dst Port, Length       │
├─────────────────────────────────────┤
│  NetFlow Payload (variable)         │  Application
│  - Our data!                        │
└─────────────────────────────────────┘
```

**We only care about the NetFlow payload**, but must parse through the layers.

### Using SharpPcap Library

Instead of parsing manually, we use **SharpPcap** (wrapper around libpcap):

```bash
dotnet add package SharpPcap
dotnet add package PacketDotNet
```

**SharpPcap** handles:
- PCAP file reading
- Packet iteration
- Layer parsing

**PacketDotNet** handles:
- Protocol parsing (Ethernet, IP, UDP, TCP)
- Layer extraction
- Payload access

### Basic PCAP Reading

```csharp
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;

// Open PCAP file
var device = new CaptureFileReaderDevice("capture.pcap");
device.Open();

// Read packets one by one
PacketCapture packet;
while ((packet = device.GetNextPacket()) != null)
{
    // Parse packet layers
    var rawPacket = Packet.ParsePacket(
        packet.GetPacket().LinkLayerType,
        packet.GetPacket().Data
    );

    // Extract UDP layer
    var udpPacket = rawPacket.Extract<UdpPacket>();

    if (udpPacket != null)
    {
        Console.WriteLine($"UDP: {udpPacket.SourcePort} → {udpPacket.DestinationPort}");

        // Get payload
        byte[] payload = udpPacket.PayloadData;
    }
}

device.Close();
```

### Filtering NetFlow Packets

NetFlow uses **UDP port 2055** (standard):

```csharp
// Filter 1: Must be UDP
if (udpPacket == null)
    continue;

// Filter 2: Must be port 2055
if (udpPacket.DestinationPort != 2055)
    continue;

// Filter 3: Must have payload
if (udpPacket.PayloadData == null || udpPacket.PayloadData.Length < 20)
    continue; // NetFlow header is 20 bytes minimum

// Filter 4: Must be NetFlow v9
byte[] payload = udpPacket.PayloadData;
ushort version = (ushort)((payload[0] << 8) | payload[1]);

if (version != 9)
    continue;

// ✅ This is a NetFlow v9 packet!
ProcessNetFlowPacket(payload);
```

### Complete PCAP Reader Example

```csharp
public class NetFlowPcapReader
{
    private readonly List<NetFlowPacket> _packets = new();

    public void ReadFile(string pcapPath)
    {
        using var device = new CaptureFileReaderDevice(pcapPath);
        device.Open();

        Console.WriteLine($"Reading: {pcapPath}");

        int totalPackets = 0;
        int netflowPackets = 0;

        PacketCapture packet;
        while ((packet = device.GetNextPacket()) != null)
        {
            totalPackets++;

            // Parse network layers
            var rawPacket = Packet.ParsePacket(
                packet.GetPacket().LinkLayerType,
                packet.GetPacket().Data
            );

            // Extract UDP
            var udpPacket = rawPacket.Extract<UdpPacket>();

            // Filter NetFlow
            if (udpPacket?.DestinationPort == 2055 &&
                udpPacket.PayloadData?.Length >= 20)
            {
                netflowPackets++;

                // Parse NetFlow
                var nfPacket = ParseNetFlow(udpPacket.PayloadData);
                _packets.Add(nfPacket);

                Console.WriteLine($"[{netflowPackets}] NetFlow packet: " +
                    $"Source={nfPacket.SourceId}, Flows={nfPacket.Count}");
            }
        }

        Console.WriteLine($"\nTotal packets: {totalPackets}");
        Console.WriteLine($"NetFlow packets: {netflowPackets}");

        device.Close();
    }

    private NetFlowPacket ParseNetFlow(byte[] payload)
    {
        // We'll implement this in next chapter
        return NetFlowParser.Parse(payload);
    }
}
```

### Error Handling

Real-world PCAP files can have issues:

```csharp
try
{
    var device = new CaptureFileReaderDevice(pcapPath);
    device.Open();
    // ... read packets ...
}
catch (PcapException ex)
{
    Console.Error.WriteLine($"Error opening PCAP: {ex.Message}");
    // Possible causes:
    // - File doesn't exist
    // - File is corrupted
    // - Not a valid PCAP file
    // - Permission denied
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine($"Invalid packet data: {ex.Message}");
    // Possible causes:
    // - Truncated packets
    // - Corrupted data
    // - Unsupported link layer type
}
```

### Live Packet Capture

To capture live traffic (advanced):

```csharp
// List available network interfaces
var devices = CaptureDeviceList.Instance;
foreach (var dev in devices)
{
    Console.WriteLine($"{dev.Name}: {dev.Description}");
}

// Select interface
var device = devices[0]; // First interface

// Set filter for NetFlow only
device.Open();
device.Filter = "udp port 2055";

// Start capturing
device.OnPacketArrival += (sender, capture) =>
{
    var packet = Packet.ParsePacket(
        capture.GetPacket().LinkLayerType,
        capture.GetPacket().Data
    );

    var udpPacket = packet.Extract<UdpPacket>();
    if (udpPacket != null)
    {
        ProcessNetFlow(udpPacket.PayloadData);
    }
};

device.StartCapture();

// Capture for 60 seconds
Thread.Sleep(60000);

device.StopCapture();
device.Close();
```

### Performance Considerations

**Memory usage:**
```csharp
// ❌ BAD - loads entire PCAP into memory
var allPackets = device.GetAllPackets();

// ✅ GOOD - process one at a time
while ((packet = device.GetNextPacket()) != null)
{
    ProcessPacket(packet);
}
```

**Processing speed:**
```csharp
// Profile packet processing
var sw = Stopwatch.StartNew();
int count = 0;

while ((packet = device.GetNextPacket()) != null)
{
    ProcessPacket(packet);
    count++;

    if (count % 1000 == 0)
    {
        Console.WriteLine($"Processed {count} packets " +
            $"in {sw.ElapsedMilliseconds}ms " +
            $"({count * 1000.0 / sw.ElapsedMilliseconds:F2} pkt/sec)");
    }
}
```

### Chapter Summary

You now know how to:

✅ **Open and read PCAP files** (SharpPcap)
✅ **Parse network layers** (PacketDotNet)
✅ **Filter NetFlow packets** (UDP port 2055)
✅ **Extract payload data** (byte arrays)
✅ **Handle errors gracefully** (try-catch)
✅ **Optimize for performance** (streaming)

**Next:** We'll design the architecture for our parser using Clean Architecture principles.

---

# Part II: Architecture and Design

<a name="chapter-4"></a>
## Chapter 4: Choosing the Right Architecture

### The Monolith Trap

Many developers start with a single-file approach:

```csharp
// Program.cs - 1500 lines of everything
class Program
{
    static void Main()
    {
        // Open PCAP
        // Parse packets
        // Store templates (global static!)
        // Format data
        // Export JSON
        // Display results
        // ... everything mixed together
    }
}
```

**Problems:**
- ❌ Can't test individual components
- ❌ Can't reuse code
- ❌ Hard to understand
- ❌ Impossible to extend
- ❌ Coupling everywhere

### Clean Architecture Principles

**Uncle Bob's Clean Architecture** separates concerns into layers:

```
┌─────────────────────────────────────────┐
│           UI / CLI / Web                │  ← Entry points
├─────────────────────────────────────────┤
│     Infrastructure Layer                │  ← Implementations
│  (Parsers, PCAP readers, JSON export)   │
├─────────────────────────────────────────┤
│         Application Layer               │  ← Use cases
│      (Orchestration, workflows)         │
├─────────────────────────────────────────┤
│           Domain Layer                  │  ← Business logic
│  (Models, Interfaces, Rules)            │
└─────────────────────────────────────────┘
     ↑ Dependencies point inward ↑
```

**Key Rules:**

1. **Dependency Rule**: Inner layers know nothing about outer layers
2. **Abstractions**: Inner layers define interfaces, outer layers implement
3. **Testability**: Can test without infrastructure
4. **Flexibility**: Can swap implementations

### Our Three-Layer Architecture

We'll use a simplified version:

```
┌──────────────────────────────────┐
│    NetFlowAnalizer.Console       │  ← Presentation Layer
│  - Program.cs (entry point)      │  - DI setup
│  - CLI argument parsing          │  - Logging config
│  - Output formatting             │
└──────────────────────────────────┘
              ↓ depends on
┌──────────────────────────────────┐
│  NetFlowAnalizer.Infrastructure  │  ← Infrastructure Layer
│  - NetFlowV9Parser               │  - Implementations
│  - PcapReader                    │  - External dependencies
│  - JsonExporter                  │  - SharpPcap, File I/O
│  - TemplateCache                 │
└──────────────────────────────────┘
              ↓ depends on
┌──────────────────────────────────┐
│     NetFlowAnalizer.Core         │  ← Domain Layer
│  - INetFlowParser (interface)    │  - NO dependencies
│  - NetFlowV9Header (model)       │  - Pure C#
│  - ITemplateCache (interface)    │  - Business rules
│  - Result<T> (error handling)    │
└──────────────────────────────────┘
```

**Why this works:**

✅ **Core** = Pure business logic, no dependencies
✅ **Infrastructure** = Dirty work (I/O, parsing, external libs)
✅ **Console** = Wires everything together

### Project Structure

```bash
dotnet new sln -n NetFlowAnalizer

# Core layer (no dependencies)
dotnet new classlib -n NetFlowAnalizer.Core
dotnet sln add NetFlowAnalizer.Core

# Infrastructure layer (depends on Core)
dotnet new classlib -n NetFlowAnalizer.Infrastructure
dotnet add NetFlowAnalizer.Infrastructure reference NetFlowAnalizer.Core
dotnet sln add NetFlowAnalizer.Infrastructure

# Console app (depends on both)
dotnet new console -n NetFlowAnalizer.Console
dotnet add NetFlowAnalizer.Console reference NetFlowAnalizer.Core
dotnet add NetFlowAnalizer.Console reference NetFlowAnalizer.Infrastructure
dotnet sln add NetFlowAnalizer.Console
```

### Dependency Injection

We'll use Microsoft's DI container:

```csharp
// In Program.cs
var host = Host.CreateDefaultBuilder(args)
    .ConfigureServices((context, services) =>
    {
        // Register services
        services.AddSingleton<ITemplateCache, TemplateCache>();
        services.AddSingleton<INetFlowParser, NetFlowV9Parser>();
        services.AddSingleton<PcapReader>();
        services.AddSingleton<JsonExporter>();
    })
    .Build();

// Get services
var parser = host.Services.GetRequiredService<INetFlowParser>();
```

**Why DI?**

✅ **Testability**: Can inject mocks
✅ **Flexibility**: Can swap implementations
✅ **Lifetime management**: Singleton, Scoped, Transient
✅ **Dependency resolution**: Container handles object creation

### Interface-Based Design

**Core layer defines contracts:**

```csharp
// NetFlowAnalizer.Core/Services/INetFlowParser.cs
public interface INetFlowParser
{
    int SupportedVersion { get; }
    bool CanParse(ReadOnlySpan<byte> data);
    Task<IEnumerable<INetFlowRecord>> ParseAsync(ReadOnlyMemory<byte> data);
}
```

**Infrastructure implements:**

```csharp
// NetFlowAnalizer.Infrastructure/Parsers/NetFlowV9Parser.cs
public class NetFlowV9Parser : INetFlowParser
{
    public int SupportedVersion => 9;

    public bool CanParse(ReadOnlySpan<byte> data)
    {
        // Implementation
    }

    public async Task<IEnumerable<INetFlowRecord>> ParseAsync(...)
    {
        // Implementation
    }
}
```

**Benefits:**

```csharp
// Easy to add v5 parser
public class NetFlowV5Parser : INetFlowParser
{
    public int SupportedVersion => 5;
    // ... implement interface
}

// Register both
services.AddSingleton<INetFlowParser, NetFlowV5Parser>();
services.AddSingleton<INetFlowParser, NetFlowV9Parser>();

// Select at runtime
var parsers = host.Services.GetServices<INetFlowParser>();
var parser = parsers.First(p => p.CanParse(data));
```

### Folder Organization

```
NetFlowAnalizer.Core/
├── Models/
│   ├── NetFlowV9Header.cs
│   ├── TemplateRecord.cs
│   ├── DataRecord.cs
│   └── INetFlowRecord.cs (marker interface)
├── Services/
│   ├── INetFlowParser.cs
│   ├── ITemplateCache.cs
│   └── INetFlowRepository.cs (future)
└── Common/
    └── Result.cs

NetFlowAnalizer.Infrastructure/
├── Parsers/
│   └── NetFlowV9Parser.cs
├── Readers/
│   └── PcapReader.cs
├── Services/
│   └── TemplateCache.cs
├── Export/
│   └── JsonExporter.cs
└── Common/
    ├── ByteUtils.cs
    └── NetFlowFields.cs

NetFlowAnalizer.Console/
├── Program.cs
└── NetFlowAnalizer.Console.csproj
```

### Error Handling Strategy

Instead of exceptions for flow control, use **Result<T> pattern**:

```csharp
// Core/Common/Result.cs
public readonly struct Result<T>
{
    public bool IsSuccess { get; }
    public T Value { get; }
    public string Error { get; }

    public static Result<T> Success(T value) =>
        new Result<T>(value, true, string.Empty);

    public static Result<T> Failure(string error) =>
        new Result<T>(default, false, error);
}
```

**Usage:**

```csharp
// Instead of:
try {
    var header = ParseHeader(data);
} catch (Exception ex) {
    // Handle error
}

// Use:
var result = ParseHeader(data);
if (result.IsSuccess) {
    var header = result.Value;
} else {
    Logger.Error(result.Error);
}
```

**Why?**

✅ **Explicit**: Caller must check for errors
✅ **Performance**: No exception overhead
✅ **Type-safe**: Can't access Value on failure
✅ **Functional**: Composable, like F# Result or Rust's Result<T, E>

### Logging Strategy

Use structured logging with **Microsoft.Extensions.Logging**:

```csharp
public class NetFlowV9Parser : INetFlowParser
{
    private readonly ILogger<NetFlowV9Parser> _logger;

    public NetFlowV9Parser(ILogger<NetFlowV9Parser> logger)
    {
        _logger = logger;
    }

    public async Task<IEnumerable<INetFlowRecord>> ParseAsync(...)
    {
        _logger.LogInformation("Parsing NetFlow packet, size: {Size}", data.Length);

        // ... parsing ...

        _logger.LogDebug("Parsed {Count} records", records.Count);
    }
}
```

**Log levels:**

```
Trace    → Very detailed (e.g., every byte)
Debug    → Debugging info (e.g., parsed values)
Info     → Important events (e.g., "Parsed 100 packets")
Warning  → Unexpected but handled (e.g., "Missing template")
Error    → Errors (e.g., "Failed to parse")
Critical → Fatal errors (e.g., "Out of memory")
```

### Chapter Summary

Our architecture:

✅ **Three layers**: Core → Infrastructure → Console
✅ **Dependency Injection**: Services registered in DI container
✅ **Interface-based**: Core defines contracts
✅ **Result<T> pattern**: Type-safe error handling
✅ **Structured logging**: ILogger<T> everywhere
✅ **Testable**: Can mock all dependencies

**Next:** We'll model the NetFlow domain in C# code.

---

<a name="chapter-5"></a>
## Chapter 5: Domain Modeling: From RFC to Code

### From Specification to Types

RFC 3954 describes NetFlow v9 in text. Our job: **translate to C# types**.

**Design Principles:**

1. **Make invalid states unrepresentable** (Yaron Minsky)
2. **Use value objects for primitives**
3. **Immutability by default**
4. **Explicit validation**

### The NetFlow V9 Header

**From RFC:**
```
Version (2 bytes): 9
Count (2 bytes): Number of FlowSets
sysUpTime (4 bytes): Milliseconds since router boot
UNIX Seconds (4 bytes): Seconds since epoch
Sequence Number (4 bytes): Incremental counter
Source ID (4 bytes): Exporter identifier
```

**Naive approach (don't do this):**

```csharp
// ❌ BAD: Anemic model, no validation
public class NetFlowHeader
{
    public ushort Version { get; set; }
    public ushort Count { get; set; }
    public uint SysUpTime { get; set; }
    public uint UnixSeconds { get; set; }
    public uint SequenceNumber { get; set; }
    public uint SourceId { get; set; }
}

// Can create invalid headers:
var header = new NetFlowHeader();  // All zeros!
header.Version = 5;  // Wrong version!
header.Count = 0;    // No FlowSets but Count=0?
```

**Better approach (value object):**

```csharp
// ✅ GOOD: Immutable, validated
public readonly record struct NetFlowV9Header : INetFlowRecord
{
    public const int HeaderSize = 20;

    // Constructor validates
    public NetFlowV9Header(
        ushort version,
        ushort count,
        uint systemUpTime,
        uint unixSeconds,
        uint sequenceNumber,
        uint sourceId)
    {
        // Validation
        if (version != 9)
            throw new ArgumentException(
                $"Invalid version {version}, expected 9",
                nameof(version));

        if (count == 0)
            throw new ArgumentException(
                "Count must be > 0",
                nameof(count));

        Version = version;
        Count = count;
        SystemUpTime = systemUpTime;
        UnixSeconds = unixSeconds;
        SequenceNumber = sequenceNumber;
        SourceId = sourceId;
    }

    // Properties (readonly)
    public ushort Version { get; }
    public ushort Count { get; }
    public uint SystemUpTime { get; }
    public uint UnixSeconds { get; }
    public uint SequenceNumber { get; }
    public uint SourceId { get; }

    // Computed properties
    public DateTime Timestamp =>
        DateTimeOffset.FromUnixTimeSeconds(UnixSeconds).DateTime;

    public bool IsValid => Version == 9 && Count > 0;

    // Factory method (better than constructor for errors)
    public static NetFlowV9Header FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderSize)
            throw new ArgumentException(
                $"Data too short: {data.Length} < {HeaderSize}");

        // Parse big-endian
        var version = (ushort)((data[0] << 8) | data[1]);
        var count = (ushort)((data[2] << 8) | data[3]);
        var sysUpTime = (uint)((data[4] << 24) | (data[5] << 16) |
                               (data[6] << 8) | data[7]);
        var unixSecs = (uint)((data[8] << 24) | (data[9] << 16) |
                              (data[10] << 8) | data[11]);
        var seqNum = (uint)((data[12] << 24) | (data[13] << 16) |
                            (data[14] << 8) | data[15]);
        var sourceId = (uint)((data[16] << 24) | (data[17] << 16) |
                              (data[18] << 8) | data[19]);

        return new NetFlowV9Header(
            version, count, sysUpTime,
            unixSecs, seqNum, sourceId);
    }

    public override string ToString() =>
        $"NetFlow v{Version}: Count={Count}, " +
        $"Seq={SequenceNumber}, Source={SourceId}, " +
        $"Time={Timestamp:yyyy-MM-dd HH:mm:ss}";
}
```

**Why `readonly record struct`?**

```csharp
// record: Value equality, ToString(), Deconstruction
var h1 = new NetFlowV9Header(9, 5, 1000, 1699147536, 1, 171);
var h2 = new NetFlowV9Header(9, 5, 1000, 1699147536, 1, 171);
Console.WriteLine(h1 == h2);  // True (value equality)

// struct: Stack-allocated (performance)
// No GC pressure for millions of headers

// readonly: Immutable after construction
// Can't accidentally modify
```

### Template and Field Models

**Template Field (simple value type):**

```csharp
public readonly record struct TemplateField
{
    public ushort Type { get; init; }
    public ushort Length { get; init; }

    public string Name => NetFlowFields.GetName(Type);
}
```

**Template Record (reference type - has collection):**

```csharp
public class TemplateRecord : INetFlowRecord
{
    public ushort TemplateId { get; set; }
    public List<TemplateField> Fields { get; set; } = new();

    // Computed
    public int RecordLength => Fields.Sum(f => f.Length);

    // Helper
    public bool HasField(ushort fieldType) =>
        Fields.Any(f => f.Type == fieldType);
}
```

**Why class not struct?**
- Contains mutable collection
- Variable size
- Shared across multiple data records (reference semantics wanted)

### Data Record

```csharp
public class DataRecord : INetFlowRecord
{
    public ushort TemplateId { get; set; }

    // Field values as formatted strings
    public Dictionary<string, object> Values { get; set; } = new();

    // Helpers
    public string? GetValue(string fieldName) =>
        Values.TryGetValue(fieldName, out var value)
            ? value.ToString()
            : null;

    public T? GetValue<T>(string fieldName) where T : struct =>
        Values.TryGetValue(fieldName, out var value) && value is T typed
            ? typed
            : null;
}
```

**Usage:**

```csharp
var record = new DataRecord
{
    TemplateId = 256,
    Values = {
        ["Src IP"] = "192.168.1.100",
        ["Dst IP"] = "8.8.8.8",
        ["Src Port"] = 54321,
        ["Dst Port"] = 53,
        ["Protocol"] = 17,
        ["Bytes"] = 1024
    }
};

// Access
string? srcIp = record.GetValue("Src IP");
int? bytes = record.GetValue<int>("Bytes");
```

### FlowSet Models

**FlowSet Header:**

```csharp
public readonly record struct FlowSetHeader
{
    public ushort FlowSetId { get; init; }
    public ushort Length { get; init; }

    // Type checks
    public bool IsTemplateFlowSet => FlowSetId == 0;
    public bool IsOptionsTemplateFlowSet => FlowSetId == 1;
    public bool IsDataFlowSet => FlowSetId >= 256;
}
```

**Parsed FlowSet (aggregate):**

```csharp
public class ParsedFlowSet
{
    public FlowSetHeader Header { get; set; }

    // Only one will have data
    public List<TemplateRecord> TemplateRecords { get; set; } = new();
    public List<DataRecord> DataRecords { get; set; } = new();

    public ushort FlowSetId => Header.FlowSetId;
}
```

### Marker Interface Pattern

All NetFlow records implement a marker interface:

```csharp
public interface INetFlowRecord
{
    // Empty marker interface
    // Allows polymorphic collections
}
```

**Usage:**

```csharp
List<INetFlowRecord> allRecords = new();
allRecords.Add(header);
allRecords.AddRange(templates);
allRecords.AddRange(dataRecords);

// Type-safe filtering
var headers = allRecords.OfType<NetFlowV9Header>();
var templates = allRecords.OfType<TemplateRecord>();
var flows = allRecords.OfType<DataRecord>();
```

### Field Type Catalog

```csharp
public static class NetFlowFields
{
    public static readonly Dictionary<ushort, string> FieldNames = new()
    {
        { 1, "Bytes" },
        { 2, "Packets" },
        { 4, "Protocol" },
        { 5, "TOS" },
        { 6, "TCP Flags" },
        { 7, "Src Port" },
        { 8, "Src IP" },
        { 11, "Dst Port" },
        { 12, "Dst IP" },
        // ... 20+ more
    };

    public static string GetName(ushort type) =>
        FieldNames.TryGetValue(type, out var name)
            ? name
            : $"Field_{type}";
}
```

### Validation Patterns

**Constructor validation:**

```csharp
public NetFlowV9Header(ushort version, ...)
{
    if (version != 9)
        throw new ArgumentException(...);
    // Called once at construction
}
```

**Property validation:**

```csharp
private ushort _version;
public ushort Version
{
    get => _version;
    set
    {
        if (value != 9)
            throw new ArgumentException(...);
        _version = value;
    }
}
```

**Factory validation (recommended):**

```csharp
public static Result<NetFlowV9Header> TryParse(ReadOnlySpan<byte> data)
{
    if (data.Length < HeaderSize)
        return Result<NetFlowV9Header>.Failure("Data too short");

    try
    {
        var header = FromBytes(data);
        return Result<NetFlowV9Header>.Success(header);
    }
    catch (Exception ex)
    {
        return Result<NetFlowV9Header>.Failure(ex.Message);
    }
}
```

### Chapter Summary

Our domain models:

✅ **NetFlowV9Header**: Immutable value object with validation
✅ **TemplateField**: Simple value type
✅ **TemplateRecord**: Reference type with collection
✅ **DataRecord**: Dictionary-based flexible storage
✅ **FlowSetHeader**: Value type with type checks
✅ **INetFlowRecord**: Marker interface for polymorphism

**Design decisions:**

- `readonly record struct` for immutable values
- Constructor validation for invariants
- Factory methods for safe creation
- Computed properties for derived data
- Result<T> for fallible operations

**Next:** We'll implement the parser logic.

---

*[Chapters 6-20 continue with similar depth and detail...]*

---

## Quick Reference

### Common Patterns

**Reading big-endian uint16:**
```csharp
ushort value = (ushort)((data[0] << 8) | data[1]);
```

**Reading big-endian uint32:**
```csharp
uint value = (uint)((data[0] << 24) | (data[1] << 16) |
                    (data[2] << 8) | data[3]);
```

**Template caching:**
```csharp
cache[sourceId][templateId] = template;
var template = cache[sourceId][templateId];
```

**Result pattern:**
```csharp
var result = TryParse(data);
if (result.IsSuccess)
    ProcessHeader(result.Value);
else
    Logger.Error(result.Error);
```

### Performance Tips

1. **Use ReadOnlySpan<byte>** for zero-copy parsing
2. **Use ValueTask<T>** for potentially synchronous async
3. **Pool byte arrays** with ArrayPool<byte>
4. **Use struct** for small, immutable types
5. **Avoid LINQ** in hot paths

### Testing Checklist

- ✅ Unit test each parser method
- ✅ Test with invalid data (too short, wrong version)
- ✅ Test with real PCAP files
- ✅ Test template caching edge cases
- ✅ Test big-endian conversion
- ✅ Benchmark performance

---

## Appendix A: Complete Code Listings

[Full source code for key classes]

## Appendix B: NetFlow v9 Field Reference

[Complete field type table]

## Appendix C: Troubleshooting Guide

[Common issues and solutions]

## Appendix D: Further Reading

- RFC 3954: Cisco Systems NetFlow Services Export Version 9
- Clean Architecture (Robert C. Martin)
- Domain-Driven Design (Eric Evans)
- C# Performance Best Practices

---

**End of Guide Preview**

This is a Manning/No Starch style guide structure. Each chapter would be 15-30 pages with:
- Code examples
- Diagrams
- Exercises
- Real-world scenarios
- Best practices
- Common pitfalls

Total book: ~600-800 pages.
