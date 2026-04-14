# High-Performance NetFlow v9 Parser in C#

## The Complete Guide to Zero-Allocation Network Traffic Analysis with .NET 8

*A hands-on engineering guide in the style of Manning Publications and No Starch Press*

---

> **Who this book is for:** C# developers at the Junior+ level who want to reach a confident Middle/Middle+ by learning how to write code that survives production workloads — high-throughput, zero-allocation, clean architecture.
>
> **What you will build:** A streaming NetFlow v9 analyzer that parses multi-gigabyte PCAP files in constant memory using `ReadOnlySpan<byte>`, `BinaryPrimitives`, `stackalloc`, and `Utf8JsonWriter`.

---

## Table of Contents

### Part I: Understanding the Problem
- [Chapter 1. What is NetFlow and Why Should You Care?](#chapter-1)
- [Chapter 2. Understanding the NetFlow v9 Protocol (Templates, Data FlowSets, Big-Endian)](#chapter-2)
- [Chapter 3. Reading Network Packets: A Primer (Using SharpPcap)](#chapter-3)

### Part II: Architecture and Design
- [Chapter 4. Choosing the Right Architecture (Clean Architecture Setup)](#chapter-4)
- [Chapter 5. Domain Modeling: From RFC to Code (Immutable Structs, Records)](#chapter-5)
- [Chapter 6. Designing for Testability (TDD, Separating I/O from Computation)](#chapter-6)

### Part III: Building the Parser (High-Performance Edition)
- [Chapter 7. Parsing Binary Data in .NET (Span, BinaryPrimitives, stackalloc)](#chapter-7)
- [Chapter 8. The Async Over Sync Anti-Pattern (Why Parsing Must Be Synchronous)](#chapter-8)
- [Chapter 9. The Global Lock Anti-Pattern (ConcurrentDictionary for Template Caching)](#chapter-9)
- [Chapter 10. Zero-Copy Parsing with Span (The Complete Parser Code)](#chapter-10)

### Part IV: Infrastructure and I/O (Streaming Edition)
- [Chapter 11. The OutOfMemory (OOM) Catastrophe (Streaming with Callbacks)](#chapter-11)
- [Chapter 12. Streaming JSON with Utf8JsonWriter](#chapter-12)
- [Chapter 13. The Complete High-Performance Pipeline (Program.cs Integration)](#chapter-13)

### Part V: Testing and Quality
- [Chapter 14. Unit Testing Binary Parsers (Byte Array Fixtures)](#chapter-14)
- [Chapter 15. Integration Testing with Real Data](#chapter-15)
- [Chapter 16. Performance Optimization (BenchmarkDotNet Results)](#chapter-16)

---

# Part I: Understanding the Problem

<a name="chapter-1"></a>
## Chapter 1. What is NetFlow and Why Should You Care?

### The Network Visibility Problem

Imagine you manage a corporate network with hundreds of devices. One morning the internet grinds to a halt. Users complain. Your boss wants answers. **What is eating the bandwidth? Who is responsible? Where is the traffic going?**

Your first instinct might be to fire up Wireshark and capture every packet. That works on a lab bench, but a busy 10 Gbps link generates **over 1 TB of raw packet data per day**. You cannot store it, you cannot search it, and you certainly cannot analyze it in real time.

**NetFlow solves this problem.** Instead of capturing the full content of every packet, a NetFlow-enabled router or switch summarizes traffic into *flows*:

```
A flow = a unidirectional stream of packets that share:
  - Source IP address and port
  - Destination IP address and port
  - IP protocol (TCP / UDP / ICMP)
  - Type of Service (ToS)
  - Input interface
```

For each flow the device records metadata: **how many packets, how many bytes, when the flow started, when it ended**. This compresses gigabytes of raw traffic into megabytes of structured metadata — a compression ratio of 100:1 to 500:1.

### Real-World Use Cases

**1. Security Analysis (SOC / SIEM)**

NetFlow data lets security teams detect anomalies without inspecting packet payloads:

| Threat | NetFlow Signal |
|--------|---------------|
| Port scan | One source IP, hundreds of destination ports, 1-2 packets each |
| DDoS attack | Thousands of sources, one destination, high packet rate |
| Data exfiltration | Internal host uploading gigabytes to an external IP at 3 AM |
| Lateral movement | Internal-to-internal flows on unusual ports (e.g., SMB, RDP) |

**2. Capacity Planning**

```
Questions NetFlow answers:
- What is our peak traffic hour?
- Which applications consume the most bandwidth?
- Do we need a link upgrade, or just QoS tuning?
- How much traffic goes to cloud providers vs. on-premise?
```

**3. Billing and Accounting**

ISPs and cloud providers use NetFlow to bill customers based on actual bandwidth consumption, not flat rates.

### Why NetFlow v9 Specifically?

NetFlow has evolved through several generations:

| Version | Year | Key Feature | Limitation |
|---------|------|-------------|------------|
| v1 | 1996 | First implementation | No sequence numbers |
| v5 | 1996 | Fixed 48-byte records, widely deployed | IPv4 only, no extensibility |
| v7 | 1998 | Catalyst switch support | Cisco-proprietary |
| **v9** | **2004** | **Template-based, extensible, IPv6** | **More complex to parse** |
| IPFIX (v10) | 2008 | IETF standard based on v9 | Even more complex |

**Version 9 is the sweet spot.** It introduced a template system that makes the protocol extensible — the router first sends a *template* that describes the fields in the data, and then sends data records that conform to that template. This means v9 can carry any combination of fields without changing the protocol itself.

This is exactly what our parser handles: first we cache templates, then we use them to decode data records.

### What We Will Build

By the end of this guide you will have a production-grade CLI tool that:

```
NetFlowAnalizer.Console <capture.pcap>
```

1. Opens a PCAP capture file using **SharpPcap**
2. Extracts UDP payloads on port 2055 (the standard NetFlow port)
3. Parses each payload using **ReadOnlySpan&lt;byte&gt;** and **BinaryPrimitives** — zero MemoryStream, zero BinaryReader, zero Array.Reverse
4. Caches templates in a thread-safe **ITemplateCache**
5. Streams parsed flow records directly to disk as JSON via **Utf8JsonWriter**
6. Uses **O(1) memory** regardless of input file size

The project follows **Clean Architecture** with three layers:

```
NetFlowAnalizer.sln
  |
  +-- NetFlowAnalizer.Core/           # Domain models + interfaces (zero dependencies)
  +-- NetFlowAnalizer.Infrastructure/  # Parser, PCAP reader, JSON exporter
  +-- NetFlowAnalizer.Console/         # Entry point, DI wiring
```

### Summary

- NetFlow compresses raw packet captures into structured flow metadata.
- Version 9 is template-based: the router tells us what fields to expect *before* sending data.
- Our parser will be **zero-allocation in the hot path**, **streaming** (O(1) memory), and built on **Clean Architecture**.
- The entire codebase lives in a single .NET 8 solution with three projects.

> **Key takeaway:** We are not building a toy. We are building a tool that can parse a 10 GB PCAP file on a machine with 512 MB of RAM without crashing. Every design decision in this guide serves that goal.

---

<a name="chapter-2"></a>
## Chapter 2. Understanding the NetFlow v9 Protocol (Templates, Data FlowSets, Big-Endian)

Before writing a single line of C#, you must understand the wire format. This chapter is the RFC 3954 crash course you wish you had. We will walk through every byte of a NetFlow v9 packet so that when you see `BinaryPrimitives.ReadUInt16BigEndian(data[2..])` in the parser code, you know exactly *why* the offset is 2 and *why* we read big-endian.

### 2.1 The Anatomy of a NetFlow v9 Packet

Every NetFlow v9 UDP datagram has the same top-level structure:

```
+---------------------------------------------------------------+
|                      Packet Header (20 bytes)                 |
+---------------------------------------------------------------+
|                      FlowSet 1                                |
+---------------------------------------------------------------+
|                      FlowSet 2                                |
+---------------------------------------------------------------+
|                      ...                                      |
+---------------------------------------------------------------+
|                      FlowSet N                                |
+---------------------------------------------------------------+
```

A single UDP datagram can contain **multiple FlowSets**. Each FlowSet is either a Template FlowSet (describing fields) or a Data FlowSet (containing actual flow records).

### 2.2 The Packet Header (20 Bytes)

The header is always exactly 20 bytes, always big-endian:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Version (9)             |            Count              |  bytes 0-3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       System Uptime                           |  bytes 4-7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Unix Seconds                           |  bytes 8-11
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sequence Number                          |  bytes 12-15
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Source ID                              |  bytes 16-19
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Bytes | Type | Description |
|-------|-------|------|-------------|
| Version | 0-1 | uint16 | Always `9` for NetFlow v9 |
| Count | 2-3 | uint16 | Number of FlowSets in this packet (not records!) |
| System Uptime | 4-7 | uint32 | Milliseconds since the router booted |
| Unix Seconds | 8-11 | uint32 | Current time as Unix epoch seconds |
| Sequence Number | 12-15 | uint32 | Per-source packet counter (for detecting loss) |
| Source ID | 16-19 | uint32 | Identifies the exporting device / line card |

This maps directly to our domain model in `NetFlowAnalizer.Core/Models/NetFlowV9Header.cs`:

```csharp
public readonly record struct NetFlowV9Header : INetFlowRecord
{
    public const int HeaderSize = 20;

    public ushort Version { get; }       // bytes 0-1
    public ushort Count { get; }         // bytes 2-3
    public uint SystemUpTime { get; }    // bytes 4-7
    public uint UnixSeconds { get; }     // bytes 8-11
    public uint SequenceNumber { get; }  // bytes 12-15
    public uint SourceId { get; }        // bytes 16-19
}
```

### 2.3 Big-Endian: The Network Byte Order

**This is the single most common source of bugs for junior developers parsing network protocols.**

Networks transmit integers in **big-endian** (most significant byte first). Intel/AMD CPUs use **little-endian** (least significant byte first). If you read a 2-byte port number `0x01BB` (443 in decimal) without converting the byte order, you get `0xBB01` (47873) — completely wrong.

Example — the number `443` as two bytes:

```
Big-endian (network):    0x01  0xBB    →  256 + 187  = 443  ✓
Little-endian (x86):     0xBB  0x01    →  187*256+1  = 47873  ✗
```

**The wrong way** (from our legacy code in `NetFlowAnalizer/Program.cs`):

```csharp
// ❌ THE ANTI-PATTERN: BinaryReader + Array.Reverse
private static ushort ReadUInt16BigEndian(BinaryReader br)
{
    var bytes = br.ReadBytes(2);        // heap allocation!
    if (BitConverter.IsLittleEndian)
        Array.Reverse(bytes);           // mutating the array in-place
    return BitConverter.ToUInt16(bytes, 0);
}
```

This code has three problems:
1. `br.ReadBytes(2)` allocates a `byte[]` on the heap **every single call**
2. `Array.Reverse` mutates data in-place — fragile
3. `BitConverter.ToUInt16` is the old-school way that requires a byte array

**The right way** (from our parser in `NetFlowAnalizer.Infrastructure/Parsers/NetFlowV9Parser.cs`):

```csharp
// ✅ THE RIGHT WAY: BinaryPrimitives on a Span — zero allocation
BinaryPrimitives.ReadUInt16BigEndian(data[2..])
```

One line. No allocation. No mutation. The `BinaryPrimitives` class in `System.Buffers.Binary` reads big-endian integers directly from a `ReadOnlySpan<byte>`. The CPU does the byte-swap in a single instruction.

### 2.4 FlowSet Structure

After the 20-byte header, the packet contains one or more FlowSets. Each FlowSet starts with a 4-byte header:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         FlowSet ID            |          Length                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        FlowSet Content ...                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The **FlowSet ID** tells us what kind of FlowSet this is:

| FlowSet ID | Meaning |
|------------|---------|
| 0 | Template FlowSet — contains template definitions |
| 1 | Options Template FlowSet (similar, but for device metadata) |
| 256 - 65535 | Data FlowSet — the ID equals the Template ID it references |

This maps to our model in `NetFlowAnalizer.Core/Models/FlowSetHeader.cs`:

```csharp
public readonly record struct FlowSetHeader
{
    public ushort FlowSetId { get; init; }
    public ushort Length { get; init; }

    public bool IsTemplateFlowSet => FlowSetId == 0;
    public bool IsOptionsTemplateFlowSet => FlowSetId == 1;
    public bool IsDataFlowSet => FlowSetId >= 256;
}
```

The parser reads this header at the start of each FlowSet iteration:

```csharp
// From NetFlowV9Parser.ParsePacket()
while (offset + 4 <= data.Length)
{
    var flowSetId = BinaryPrimitives.ReadUInt16BigEndian(data[offset..]);
    var flowSetLength = BinaryPrimitives.ReadUInt16BigEndian(data[(offset + 2)..]);

    if (flowSetLength < 4 || offset + flowSetLength > data.Length)
        break;  // Invalid FlowSet — stop parsing

    var content = data.Slice(offset + 4, flowSetLength - 4);

    if (flowSetId == 0)
        ParseTemplateFlowSet(content, header.SourceId, packet.Templates);
    else if (flowSetId >= 256)
        ParseDataFlowSet(content, header.SourceId, flowSetId, packet.DataRecords);

    offset += flowSetLength;
}
```

### 2.5 Template FlowSets (FlowSet ID = 0)

A Template FlowSet contains one or more template definitions. Each template tells us: "When you see a Data FlowSet with ID = X, each record contains these fields in this order."

```
Template FlowSet Content:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Template ID (256+)      |         Field Count           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Field Type 1           |        Field Length 1          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Field Type 2           |        Field Length 2          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        ...                    |        ...                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

For example, a template with ID 256 might say: "Each record has: Src IP (4 bytes), Dst IP (4 bytes), Src Port (2 bytes), Dst Port (2 bytes), Protocol (1 byte), Bytes (4 bytes), Packets (4 bytes)."

Our domain models for this:

```csharp
// NetFlowAnalizer.Core/Models/TemplateField.cs
public readonly record struct TemplateField
{
    public ushort Type { get; init; }    // e.g., 8 = Src IP
    public ushort Length { get; init; }  // e.g., 4 bytes
}

// NetFlowAnalizer.Core/Models/TemplateRecord.cs
public class TemplateRecord : INetFlowRecord
{
    public ushort TemplateId { get; set; }
    public List<TemplateField> Fields { get; set; } = new();
    public int RecordLength => Fields.Sum(f => f.Length);
}
```

The parser extracts templates and immediately caches them:

```csharp
// From NetFlowV9Parser.ParseTemplateFlowSet()
var templateId = BinaryPrimitives.ReadUInt16BigEndian(content[offset..]);
var fieldCount = BinaryPrimitives.ReadUInt16BigEndian(content[(offset + 2)..]);
offset += 4;

var template = new TemplateRecord { TemplateId = templateId };
template.Fields.EnsureCapacity(fieldCount);  // avoid List resizing

for (var i = 0; i < fieldCount; i++)
{
    var fieldType   = BinaryPrimitives.ReadUInt16BigEndian(content[offset..]);
    var fieldLength = BinaryPrimitives.ReadUInt16BigEndian(content[(offset + 2)..]);
    offset += 4;

    template.Fields.Add(new TemplateField { Type = fieldType, Length = fieldLength });
}

_templateCache.AddTemplate(sourceId, template);
```

### 2.6 Data FlowSets (FlowSet ID >= 256)

A Data FlowSet contains the actual flow records. Its FlowSet ID matches the Template ID that describes the record format. To parse it, we **must** have the corresponding template in our cache:

```
Data FlowSet Content (FlowSet ID = 256, using template 256):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Src IP (4B) | Dst IP (4B) | SrcPort(2B) | DstPort(2B) | ... |  Record 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Src IP (4B) | Dst IP (4B) | SrcPort(2B) | DstPort(2B) | ... |  Record 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The parser iterates through the content, reading exactly `RecordLength` bytes per record:

```csharp
// From NetFlowV9Parser.ParseDataFlowSet()
var template = _templateCache.GetTemplate(sourceId, templateId);
if (template is null) return;  // No template cached — skip

var recordLength = template.RecordLength;
var offset = 0;

while (offset + recordLength <= content.Length)
{
    var record = new DataRecord { TemplateId = templateId };

    foreach (var field in template.Fields)
    {
        var fieldData = content.Slice(offset, field.Length);
        var value = FormatField(field.Type, fieldData);
        record.Values[field.Type.ToString()] = value;
        offset += field.Length;
    }

    outRecords.Add(record);
}
```

### 2.7 Common NetFlow v9 Field Types

RFC 3954 defines dozens of field types. Our parser handles the most important ones (from `NetFlowAnalizer.Infrastructure/Common/NetFlowFields.cs`):

| Field Type | Name | Size | Example Value |
|------------|------|------|---------------|
| 1 | IN_BYTES | 4 | `15234` |
| 2 | IN_PKTS | 4 | `12` |
| 4 | PROTOCOL | 1 | `6` (TCP) |
| 5 | SRC_TOS | 1 | `0` |
| 6 | TCP_FLAGS | 1 | `27` |
| 7 | L4_SRC_PORT | 2 | `443` |
| 8 | IPV4_SRC_ADDR | 4 | `192.168.1.100` |
| 9 | SRC_MASK | 1 | `24` |
| 10 | INPUT_SNMP | 4 | `1` |
| 11 | L4_DST_PORT | 2 | `52481` |
| 12 | IPV4_DST_ADDR | 4 | `10.0.0.1` |
| 13 | DST_MASK | 1 | `16` |
| 14 | OUTPUT_SNMP | 4 | `2` |
| 15 | IPV4_NEXT_HOP | 4 | `10.0.0.254` |
| 34 | SAMPLING_INTERVAL | 4 | timestamp |
| 35 | SAMPLING_ALGORITHM | 4 | timestamp |
| 80 | IN_SRC_TIMESTAMP | 8 | Unix ms |
| 81 | OUT_DST_TIMESTAMP | 8 | Unix ms |
| 225 | POST_NAT_SRC_IPV4 | 4 | `203.0.113.5` |
| 226 | POST_NAT_DST_IPV4 | 4 | `203.0.113.10` |
| 227 | POST_NAT_SRC_PORT | 2 | `12345` |
| 228 | POST_NAT_DST_PORT | 2 | `80` |

### 2.8 The Template-Data Dependency

This is the critical thing to understand about NetFlow v9:

```
IMPORTANT: Data FlowSets are MEANINGLESS without their Template.
```

If the parser receives a Data FlowSet with ID=256 but has never seen Template 256, it **must skip** that FlowSet. There is no way to know how many bytes each field occupies without the template.

This creates a chicken-and-egg problem:
- The router sends templates periodically (e.g., every 5 minutes)
- Data FlowSets can arrive *before* their template (e.g., after a parser restart)
- Our parser must gracefully handle missing templates

This is why we have a dedicated `ITemplateCache` interface — template caching is a first-class concern in NetFlow v9 parsing.

### Summary

- A NetFlow v9 packet = 20-byte header + N FlowSets
- All integers are **big-endian** — use `BinaryPrimitives`, never `BitConverter` + `Array.Reverse`
- FlowSet ID 0 = Template definitions, FlowSet ID >= 256 = Data records
- Templates define the field layout; data is unreadable without the corresponding template
- The parser must cache templates and handle missing templates gracefully

---

<a name="chapter-3"></a>
## Chapter 3. Reading Network Packets: A Primer (Using SharpPcap)

### 3.1 Where Do NetFlow Packets Come From?

In production, NetFlow data arrives as UDP datagrams on port **2055** (the conventional default). A network router or switch exports flow records to a *collector* — and that collector is exactly what we are building.

But for development, testing, and forensic analysis, we work with **PCAP files** — pre-recorded packet captures. Tools like `tcpdump` or Wireshark save network traffic to `.pcap` files, and our analyzer reads them.

The data flow looks like this:

```
┌──────────┐    UDP:2055    ┌──────────────┐    save     ┌───────────┐
│  Router   │ ────────────> │  tcpdump /   │ ─────────> │ file.pcap │
│ (exports) │               │  Wireshark   │            │           │
└──────────┘                └──────────────┘            └─────┬─────┘
                                                              │
                                                              │ read
                                                              v
                                                     ┌────────────────┐
                                                     │ Our Analyzer   │
                                                     │ (SharpPcap)    │
                                                     └────────────────┘
```

### 3.2 The PCAP File Format

A PCAP file is not just raw bytes dumped from the network. It has structure:

```
┌─────────────────────────────┐
│  Global Header (24 bytes)   │  magic number, version, link type
├─────────────────────────────┤
│  Packet Header (16 bytes)   │  timestamp, captured length
│  Packet Data (N bytes)      │  Ethernet → IP → UDP → Payload
├─────────────────────────────┤
│  Packet Header (16 bytes)   │
│  Packet Data (N bytes)      │
├─────────────────────────────┤
│  ...                        │
└─────────────────────────────┘
```

Each packet in the file contains the full network stack:

```
Ethernet Header (14 bytes)
  └── IP Header (20+ bytes)
       └── UDP Header (8 bytes)
            └── NetFlow v9 Payload  ← THIS is what we parse
```

We need a library that peels away the Ethernet/IP/UDP layers and gives us the raw NetFlow payload. That library is **SharpPcap** (with **PacketDotNet** for protocol dissection).

### 3.3 SharpPcap and PacketDotNet

Our project uses two NuGet packages (from `NetFlowAnalizer.Infrastructure.csproj`):

```xml
<PackageReference Include="SharpPcap" Version="6.3.1" />
<PackageReference Include="PacketDotNet" Version="1.4.8" />
```

- **SharpPcap** — opens PCAP files and reads raw captured packets
- **PacketDotNet** — parses Ethernet/IP/UDP layers to extract payloads

### 3.4 The Streaming PCAP Reader

Here is our complete PCAP reader from `NetFlowAnalizer.Infrastructure/Readers/NetFlowPcapReader.cs`. Pay attention to the **streaming design** — it never accumulates packets in a list:

```csharp
public sealed class NetFlowPcapReader
{
    private readonly INetFlowParser _parser;
    private readonly ILogger<NetFlowPcapReader> _logger;

    public const int NetFlowPort = 2055;

    // Stats from the last run
    public int TotalPackets { get; private set; }
    public int NetFlowPackets { get; private set; }
    public int TotalTemplates { get; private set; }
    public int TotalFlows { get; private set; }

    /// <summary>
    /// Process PCAP file in streaming mode.
    /// Each parsed NetFlowPacket is passed to onPacket and then discarded.
    /// No lists, no accumulation — constant memory.
    /// </summary>
    public void Process(
        string pcapFilePath,
        Action<NetFlowPacket> onPacket,
        CancellationToken cancellationToken = default)
    {
        using var device = new CaptureFileReaderDevice(pcapFilePath);
        device.Open();

        PacketCapture capture;
        GetPacketStatus status;

        while ((status = device.GetNextPacket(out capture))
                == GetPacketStatus.PacketRead)
        {
            cancellationToken.ThrowIfCancellationRequested();
            TotalPackets++;

            var rawCapture = capture.GetPacket();
            var rawPacket = Packet.ParsePacket(
                rawCapture.LinkLayerType, rawCapture.Data);
            var udpPacket = rawPacket.Extract<UdpPacket>();

            if (udpPacket is null || udpPacket.DestinationPort != NetFlowPort)
                continue;

            var payload = udpPacket.PayloadData;
            if (payload is null || payload.Length < NetFlowV9Header.HeaderSize)
                continue;

            if (!_parser.CanParse(payload))
                continue;

            NetFlowPackets++;

            // Parse on the span — synchronous, no Task overhead
            var packet = _parser.ParsePacket(payload.AsSpan());

            TotalTemplates += packet.Templates.Count;
            TotalFlows += packet.DataRecords.Count;

            // Hand off to consumer immediately.
            // After this call returns, `packet` is eligible for GC.
            onPacket(packet);
        }

        device.Close();
    }
}
```

### 3.5 Key Design Decisions

**1. Pull-based reading, not event-based**

The legacy code used the event-based API:

```csharp
// ❌ THE ANTI-PATTERN: Event-based reading
device.OnPacketArrival += Device_OnPacketArrival;
device.Capture();  // blocks until EOF, fires events
```

The problem: events make it impossible to control the flow. You cannot cancel mid-stream, you cannot apply backpressure, and exception handling is awkward.

Our code uses the **pull-based** API:

```csharp
// ✅ THE RIGHT WAY: Pull-based reading with GetNextPacket
while ((status = device.GetNextPacket(out capture))
        == GetPacketStatus.PacketRead)
{
    cancellationToken.ThrowIfCancellationRequested();
    // ... process one packet at a time
}
```

Benefits: clean `while` loop, easy cancellation via `CancellationToken`, clear control flow.

**2. Callback pattern for streaming**

The method signature is `Process(string path, Action<NetFlowPacket> onPacket)`. Instead of returning a `List<NetFlowPacket>`, it calls a callback for each packet. This is the foundation of our O(1) memory design — we will explore this deeply in Chapter 11.

**3. Synchronous parsing**

Notice that `ParsePacket` is called synchronously on `payload.AsSpan()`. There is no `await`, no `Task.Run`. This is deliberate — binary parsing is a CPU-bound operation on data already in memory. Making it async would add overhead with zero benefit. We cover this in detail in Chapter 8.

**4. Layer extraction**

SharpPcap gives us raw bytes. PacketDotNet peels the layers:

```csharp
var rawPacket = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
var udpPacket = rawPacket.Extract<UdpPacket>();
```

`Extract<UdpPacket>()` walks the protocol stack (Ethernet → IP → UDP) and returns the UDP layer, regardless of how many layers are in between (e.g., VLAN tags). We then grab `udpPacket.PayloadData` — the raw NetFlow v9 bytes.

**5. Filtering on port 2055**

```csharp
if (udpPacket.DestinationPort != NetFlowPort)
    continue;
```

A PCAP file may contain all kinds of traffic. We only care about UDP packets destined for port 2055 — the standard NetFlow collector port.

### 3.6 Extracting the Payload

After filtering, we have `udpPacket.PayloadData` — a `byte[]` containing the raw NetFlow v9 packet (header + FlowSets). We pass it to the parser:

```csharp
var payload = udpPacket.PayloadData;

// Validate minimum size
if (payload is null || payload.Length < NetFlowV9Header.HeaderSize)
    continue;

// Quick version check without full parse
if (!_parser.CanParse(payload))
    continue;

// Full parse — operates on Span<byte>
var packet = _parser.ParsePacket(payload.AsSpan());
```

Note the `.AsSpan()` call — this converts the `byte[]` to a `Span<byte>` without copying. From this point on, the parser works entirely on spans.

### Summary

- PCAP files contain full network captures (Ethernet → IP → UDP → Payload)
- **SharpPcap** reads PCAP files; **PacketDotNet** extracts protocol layers
- We use pull-based reading (`GetNextPacket`) — not events — for clean control flow
- The reader is **streaming**: it processes one packet at a time via a callback
- After extracting the UDP payload, we pass it as a `Span<byte>` to the parser
- Port 2055 is the standard NetFlow collector port

---

# Part II: Architecture and Design

<a name="chapter-4"></a>
## Chapter 4. Choosing the Right Architecture (Clean Architecture Setup)

### 4.1 The Monolith Problem

Let's look at what "bad architecture" looks like. Our legacy MVP (`NetFlowAnalizer/Program.cs`) had everything in a single file — 571 lines:

```csharp
// ❌ THE ANTI-PATTERN: God-file monolith (571 lines, one file)
//
// NetFlowAnalizer/Program.cs contains:
//   - Program.Main()            — entry point
//   - NetFlowPacket class       — domain model
//   - DataRecord class          — domain model
//   - FlowSetHeader class       — domain model
//   - TemplateField class       — domain model
//   - TemplateRecord class      — domain model
//   - CapturedPacket class      — tracking structure
//   - ParsedFlowSet class       — tracking structure
//   - TemplateInfo class        — JSON export DTO
//   - FieldInfo class           — JSON export DTO
//   - NetFlowParser class       — static parser (MemoryStream + BinaryReader)
//   - TemplateCache class       — static cache (no thread safety)
//   - CaptureSummary class      — static list (OOM risk)
//   - NetFlowJsonExporter class — static JSON serializer
//   - NetFlowPcapReader class   — PCAP reader + event handler
//   - ByteUtils class           — byte conversion helpers
//   - NetFlowFields class       — field name dictionary
```

Problems with this approach:

1. **Untestable** — Everything is `static`. You cannot mock the template cache or the parser for unit tests.
2. **Tightly coupled** — The PCAP reader directly calls the parser, which directly calls the template cache. Changing one breaks everything.
3. **No separation of concerns** — Domain models, I/O, parsing, and serialization all live together.
4. **Memory disaster** — `CaptureSummary.Packets` is a `static List<CapturedPacket>` that grows without bound. A large PCAP file will cause `OutOfMemoryException`.

### 4.2 Clean Architecture: The Solution

Clean Architecture (Robert C. Martin) separates code into concentric layers with one strict rule:

```
┌─────────────────────────────────────────────────┐
│                                                 │
│   Console (Entry Point)                         │
│   - Program.cs                                  │
│   - DI container setup                          │
│                                                 │
│   ┌─────────────────────────────────────────┐   │
│   │                                         │   │
│   │   Infrastructure (Implementations)      │   │
│   │   - NetFlowV9Parser                     │   │
│   │   - NetFlowPcapReader                   │   │
│   │   - TemplateCache                       │   │
│   │   - NetFlowJsonExporter                 │   │
│   │                                         │   │
│   │   ┌─────────────────────────────────┐   │   │
│   │   │                                 │   │   │
│   │   │   Core (Domain)                 │   │   │
│   │   │   - Models (structs, records)   │   │   │
│   │   │   - Interfaces                  │   │   │
│   │   │   - No dependencies             │   │   │
│   │   │                                 │   │   │
│   │   └─────────────────────────────────┘   │   │
│   │                                         │   │
│   └─────────────────────────────────────────┘   │
│                                                 │
└─────────────────────────────────────────────────┘

THE DEPENDENCY RULE: Dependencies point INWARD.
  - Core depends on NOTHING
  - Infrastructure depends on Core
  - Console depends on Core + Infrastructure
```

### 4.3 Our Solution Structure

```
NetFlowAnalizer.sln
│
├── NetFlowAnalizer.Core/                 # The innermost circle
│   ├── NetFlowAnalizer.Core.csproj       # net8.0, ZERO NuGet packages
│   ├── Common/
│   │   └── Result.cs                     # Functional error handling
│   ├── Models/
│   │   ├── INetFlowRecord.cs             # Marker interface
│   │   ├── NetFlowV9Header.cs            # readonly record struct
│   │   ├── FlowSetHeader.cs              # readonly record struct
│   │   ├── TemplateField.cs              # readonly record struct
│   │   ├── TemplateRecord.cs             # Template definition
│   │   ├── DataRecord.cs                 # Flow data
│   │   ├── NetFlowPacket.cs              # Complete packet
│   │   └── ParsedFlowSet.cs              # Aggregate
│   └── Services/
│       ├── INetFlowParser.cs             # Parser contract
│       ├── ITemplateCache.cs             # Cache contract
│       └── INetFlowRepository.cs         # Storage contract
│
├── NetFlowAnalizer.Infrastructure/       # The middle circle
│   ├── NetFlowAnalizer.Infrastructure.csproj  # SharpPcap, PacketDotNet, Logging
│   ├── Common/
│   │   └── NetFlowFields.cs              # RFC 3954 field names
│   ├── Parsers/
│   │   └── NetFlowV9Parser.cs            # High-perf parser (Span + BinaryPrimitives)
│   ├── Readers/
│   │   └── NetFlowPcapReader.cs          # Streaming PCAP reader
│   ├── Services/
│   │   └── TemplateCache.cs              # Thread-safe in-memory cache
│   └── Export/
│       └── NetFlowJsonExporter.cs        # Streaming JSON via Utf8JsonWriter
│
└── NetFlowAnalizer.Console/             # The outermost circle
    ├── NetFlowAnalizer.Console.csproj    # Hosting, DI
    └── Program.cs                        # Entry point + DI wiring
```

### 4.4 The Core Project: Zero Dependencies

The Core project's `.csproj` is remarkably clean:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <LangVersion>latest</LangVersion>
  </PropertyGroup>
  <!-- NO PackageReference elements. Zero external dependencies. -->
</Project>
```

**This is the most important rule of Clean Architecture: the Core project has ZERO NuGet packages.** It contains only:

- **Domain models** — `NetFlowV9Header`, `FlowSetHeader`, `TemplateField`, `TemplateRecord`, `DataRecord`, `NetFlowPacket`
- **Interfaces** — `INetFlowParser`, `ITemplateCache`, `INetFlowRepository`
- **Common utilities** — `Result<T>` for functional error handling

It knows nothing about SharpPcap, JSON, files, or network I/O. It is pure C# — portable, testable, eternal.

### 4.5 The Infrastructure Project: Implementations

The Infrastructure project references Core and adds NuGet packages:

```xml
<ItemGroup>
    <PackageReference Include="Microsoft.Extensions.Logging" Version="9.0.8" />
    <PackageReference Include="PacketDotNet" Version="1.4.8" />
    <PackageReference Include="SharpPcap" Version="6.3.1" />
</ItemGroup>

<ItemGroup>
    <ProjectReference Include="..\NetFlowAnalizer.Core\NetFlowAnalizer.Core.csproj" />
</ItemGroup>
```

It provides **concrete implementations** of the Core interfaces:

| Core Interface | Infrastructure Implementation |
|---------------|------------------------------|
| `INetFlowParser` | `NetFlowV9Parser` — Span-based zero-alloc parser |
| `ITemplateCache` | `TemplateCache` — thread-safe in-memory dictionary |
| `INetFlowRepository` | *(not yet implemented — ready for future DB storage)* |

Plus two non-interface classes:
- `NetFlowPcapReader` — reads PCAP files via SharpPcap
- `NetFlowJsonExporter` — writes streaming JSON via Utf8JsonWriter

### 4.6 The Console Project: DI Wiring

The Console project is the **composition root** — the only place where concrete types are mentioned:

```csharp
// From NetFlowAnalizer.Console/Program.cs
static IHostBuilder CreateHostBuilder(string[] args)
{
    return Host.CreateDefaultBuilder(args)
        .ConfigureServices((_, services) =>
        {
            services.AddSingleton<ITemplateCache, TemplateCache>();
            services.AddSingleton<INetFlowParser, NetFlowV9Parser>();
            services.AddSingleton<NetFlowPcapReader>();
            services.AddSingleton<NetFlowJsonExporter>();
        })
        .ConfigureLogging((_, logging) =>
        {
            logging.ClearProviders();
            logging.AddConsole();
            logging.SetMinimumLevel(LogLevel.Information);
        });
}
```

Notice:
- `ITemplateCache` → `TemplateCache` — the parser depends on the **interface**, not the implementation
- `INetFlowParser` → `NetFlowV9Parser` — same principle
- All services are **Singletons** — our parser is stateless (templates are in the cache), so one instance is fine
- We use `Microsoft.Extensions.Hosting` for structured logging and DI

### 4.7 Why This Matters: Swappability

With this architecture, you can swap implementations without changing a single line of business logic:

```
Want to add NetFlow v5 support?
  → Create NetFlowV5Parser : INetFlowParser
  → Register it in DI

Want to store templates in Redis instead of memory?
  → Create RedisTemplateCache : ITemplateCache
  → Register it in DI

Want to write to a database instead of JSON?
  → Implement INetFlowRepository
  → Register it in DI
```

The Core layer never changes. The Infrastructure layer grows. The Console layer rewires.

### Summary

- The monolithic approach (one file, static classes) is untestable, tightly coupled, and OOM-prone
- Clean Architecture separates the project into three layers: **Core** → **Infrastructure** → **Console**
- **Core** has zero NuGet dependencies — only models and interfaces
- **Infrastructure** implements Core interfaces using concrete technologies (SharpPcap, JSON, etc.)
- **Console** is the composition root — it wires interfaces to implementations via DI
- This architecture makes every component independently testable and swappable

---

<a name="chapter-5"></a>
## Chapter 5. Domain Modeling: From RFC to Code (Immutable Structs, Records)

### 5.1 The Modeling Philosophy

When you translate a network protocol into C# types, you face a choice:

```
Option A: Mutable classes with default constructors (the "easy" way)
Option B: Immutable value types that enforce invariants (the "right" way)
```

Our Core layer uses **Option B** for value objects and a pragmatic mix for entities. Let's examine each model and understand *why* it was designed that way.

### 5.2 Value Objects: `readonly record struct`

A value object has no identity — two instances with the same data are considered equal. In our domain, the packet header and field definitions are value objects.

**NetFlowV9Header** — the packet header:

```csharp
// NetFlowAnalizer.Core/Models/NetFlowV9Header.cs
public readonly record struct NetFlowV9Header : INetFlowRecord
{
    public const int HeaderSize = 20;

    public NetFlowV9Header(
        ushort version, ushort count,
        uint systemUpTime, uint unixSeconds,
        uint sequenceNumber, uint sourceId)
    {
        if (version != 9)
            throw new ArgumentException(
                $"Invalid NetFlow version {version}. Expected v9",
                nameof(version));

        Version = version;
        Count = count;
        SystemUpTime = systemUpTime;
        UnixSeconds = unixSeconds;
        SequenceNumber = sequenceNumber;
        SourceId = sourceId;
    }

    public ushort Version { get; }
    public ushort Count { get; }
    public uint SystemUpTime { get; }
    public uint UnixSeconds { get; }
    public uint SequenceNumber { get; }
    public uint SourceId { get; }

    public DateTime Timestamp =>
        DateTimeOffset.FromUnixTimeSeconds(UnixSeconds).DateTime;

    public bool IsValid => Version == 9 && Count > 0;

    public static NetFlowV9Header FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderSize)
            throw new ArgumentException(
                $"Data too short. Expected at least {HeaderSize} bytes, got {data.Length}");

        return new NetFlowV9Header(
            version:        BinaryPrimitives.ReadUInt16BigEndian(data),
            count:          BinaryPrimitives.ReadUInt16BigEndian(data[2..]),
            systemUpTime:   BinaryPrimitives.ReadUInt32BigEndian(data[4..]),
            unixSeconds:    BinaryPrimitives.ReadUInt32BigEndian(data[8..]),
            sequenceNumber: BinaryPrimitives.ReadUInt32BigEndian(data[12..]),
            sourceId:       BinaryPrimitives.ReadUInt32BigEndian(data[16..]));
    }

    public override string ToString() =>
        $"NetFlow v{Version}: Count={Count}, Seq={SequenceNumber}, " +
        $"Source={SourceId}, Time={Timestamp:yyyy-MM-dd HH:mm:ss}";
}
```

Why `readonly record struct`?

| Feature | Benefit |
|---------|---------|
| `readonly` | All fields are immutable after construction — no accidental mutation |
| `record` | Free `Equals()`, `GetHashCode()`, `ToString()`, `with` expressions |
| `struct` | Lives on the stack, not the heap — **zero GC pressure** |

The constructor validates invariants: `version` must be 9. If someone constructs a header with version 5, they get an exception **immediately**, not a silent data corruption bug downstream.

The `FromBytes` factory method is the **only** way to create a header from raw bytes. It uses `BinaryPrimitives` — no allocation, no byte reversal.

**FlowSetHeader** — the FlowSet header:

```csharp
// NetFlowAnalizer.Core/Models/FlowSetHeader.cs
public readonly record struct FlowSetHeader
{
    public ushort FlowSetId { get; init; }
    public ushort Length { get; init; }

    public bool IsTemplateFlowSet => FlowSetId == 0;
    public bool IsOptionsTemplateFlowSet => FlowSetId == 1;
    public bool IsDataFlowSet => FlowSetId >= 256;
}
```

This is a simple 4-byte value. The computed properties (`IsTemplateFlowSet`, `IsDataFlowSet`) encode the RFC rules directly into the type — the parser doesn't need to remember magic numbers.

**TemplateField** — a single field definition:

```csharp
// NetFlowAnalizer.Core/Models/TemplateField.cs
public readonly record struct TemplateField
{
    public ushort Type { get; init; }    // Field type (e.g., 8 = Src IP)
    public ushort Length { get; init; }  // Field length in bytes
}
```

Four bytes, immutable, stack-allocated. A template with 20 fields creates zero heap pressure for the field definitions themselves.

### 5.3 Entities: Classes with Identity

Unlike value objects, entities have identity and may evolve over time. Our template records and data records are entities.

**TemplateRecord** — a template definition:

```csharp
// NetFlowAnalizer.Core/Models/TemplateRecord.cs
public class TemplateRecord : INetFlowRecord
{
    public ushort TemplateId { get; set; }
    public List<TemplateField> Fields { get; set; } = new();
    public int RecordLength => Fields.Sum(f => f.Length);
}
```

Why a `class` instead of a `struct`?

1. It contains a `List<TemplateField>` — a reference type. A struct containing a reference type gains little from being on the stack.
2. Templates are cached in a `Dictionary` — they need reference semantics for efficient lookup.
3. `RecordLength` is computed on demand: it sums all field lengths to determine how many bytes one data record occupies.

**DataRecord** — a single flow record:

```csharp
// NetFlowAnalizer.Core/Models/DataRecord.cs
public class DataRecord : INetFlowRecord
{
    public ushort TemplateId { get; set; }
    public Dictionary<string, object> Values { get; set; } = new();
}
```

`Values` uses `string` keys (the field type as a string, e.g., `"8"` for Src IP) and `object` values (the formatted string). This flexible dictionary approach lets us handle any combination of fields without knowing them at compile time.

**NetFlowPacket** — the aggregate root:

```csharp
// NetFlowAnalizer.Core/Models/NetFlowPacket.cs
public class NetFlowPacket
{
    public NetFlowV9Header Header { get; set; }
    public List<TemplateRecord> Templates { get; set; } = new();
    public List<DataRecord> DataRecords { get; set; } = new();
}
```

This is the output of `ParsePacket()` — it contains the header, any templates found in this packet, and any data records. Note that the header is a `struct` (value semantics, copied into the class), while Templates and DataRecords are lists.

### 5.4 The Marker Interface Pattern

```csharp
// NetFlowAnalizer.Core/Models/INetFlowRecord.cs
public interface INetFlowRecord
{
    // Marker interface - no members
    // Allows polymorphic collections of different NetFlow record types
}
```

`INetFlowRecord` is implemented by `NetFlowV9Header`, `TemplateRecord`, and `DataRecord`. It serves as a common base type for the `INetFlowRepository.SaveRecordAsync()` method, which accepts `IEnumerable<INetFlowRecord>`:

```csharp
public interface INetFlowRepository
{
    Task SaveRecordAsync(IEnumerable<INetFlowRecord> records,
        CancellationToken cancellationToken = default);

    Task<IEnumerable<INetFlowRecord>> GetRecordsByTimeRangeAsync(
        DateTime startTime, DateTime endTime,
        CancellationToken cancellationToken = default);

    Task<long> GetTotalRecordsCountAsync(
        CancellationToken cancellationToken = default);
}
```

This interface is not yet implemented — it is a **placeholder** for future database storage (PostgreSQL, ClickHouse, etc.). The architecture is ready; the implementation can be added without changing existing code.

### 5.5 Functional Error Handling: Result&lt;T&gt;

```csharp
// NetFlowAnalizer.Core/Common/Result.cs
public readonly struct Result<T>
{
    private readonly T? _value;
    private readonly string _error;

    public bool IsSuccess { get; }
    public bool IsFailure { get; }

    public T? Value => IsSuccess
        ? _value
        : throw new InvalidOperationException(
            $"Cannot access Value when Result is failure. Error: {_error}");

    public string Error => IsFailure
        ? _error
        : throw new InvalidOperationException(
            $"Cannot access Error when Result is success");

    public static Result<T> Success(T? value) =>
        new Result<T>(value, true, string.Empty);

    public static Result<T> Failure(string error) =>
        new(default, false, error);
}
```

`Result<T>` is a value type (struct) that represents either a success with a value or a failure with an error message. It prevents the "exception as flow control" anti-pattern:

```csharp
// ❌ ANTI-PATTERN: Exceptions for expected failures
try {
    var header = ParseHeader(data);
} catch (Exception ex) {
    Console.WriteLine($"Bad packet: {ex.Message}");
}

// ✅ RIGHT WAY: Result type for expected failures
var result = ParseHeader(data);
if (result.IsFailure)
    Console.WriteLine($"Bad packet: {result.Error}");
```

### 5.6 Anti-Pattern vs. Right Way: Model Design

Let's compare the legacy models with our Clean Architecture models:

**❌ The Anti-Pattern (legacy monolith):**

```csharp
// Everything is a mutable class in one file
public class NetFlowPacket
{
    public ushort Version { get; set; }     // mutable — anyone can change it
    public ushort Count { get; set; }       // no validation
    public uint SysUptime { get; set; }
    public uint UnixSecs { get; set; }
    public uint SequenceNumber { get; set; }
    public uint SourceId { get; set; }
}

public class TemplateField
{
    public ushort Type { get; set; }       // class — allocated on the heap
    public ushort Length { get; set; }      // 4 bytes of data, 24+ bytes of overhead
}
```

Problems:
- `TemplateField` is a class holding 4 bytes of data, but on the heap it costs **24+ bytes** (object header + method table + alignment). For a template with 20 fields, that's 480 bytes of overhead for 80 bytes of data.
- No validation — you can set `Version = 42` and nothing complains.
- Mutable — any code can modify any field at any time.

**✅ The Right Way (our Clean Architecture models):**

```csharp
// Immutable value types with validation
public readonly record struct NetFlowV9Header : INetFlowRecord
{
    public NetFlowV9Header(ushort version, ...)
    {
        if (version != 9) throw new ArgumentException(...);
        // ...
    }
    // All properties are get-only
}

public readonly record struct TemplateField
{
    public ushort Type { get; init; }     // struct — lives on the stack
    public ushort Length { get; init; }    // 4 bytes of data, 4 bytes of cost
}
```

Benefits:
- `TemplateField` is a struct: 4 bytes of data, 4 bytes of cost. 20 fields = 80 bytes total.
- Constructor validates invariants at creation time.
- Immutable after construction — no accidental mutation.

### Summary

- Use `readonly record struct` for small value objects (headers, fields) — they live on the stack and create zero GC pressure
- Use `class` for entities with reference-type members (templates with Lists, records with Dictionaries)
- Validate invariants in constructors — fail fast, fail loudly
- Use marker interfaces (`INetFlowRecord`) to enable polymorphic collections
- Use `Result<T>` instead of exceptions for expected failure paths
- Design models to match the RFC structure directly — the code should read like the protocol specification

---

<a name="chapter-6"></a>
## Chapter 6. Designing for Testability (TDD, Separating I/O from Computation)

### 6.1 Why the Legacy Code Was Untestable

Look at the legacy parser in `NetFlowAnalizer/Program.cs`:

```csharp
// ❌ THE ANTI-PATTERN: Static classes everywhere
public static class NetFlowParser
{
    public static NetFlowPacket ParseHeader(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes);
        using var br = new BinaryReader(ms);
        // ...
    }
}

public static class TemplateCache
{
    private static readonly Dictionary<uint, Dictionary<ushort, TemplateRecord>> cache = new();

    public static void AddTemplate(uint sourceId, TemplateRecord template) { ... }
    public static TemplateRecord? GetTemplate(uint sourceId, ushort templateId) { ... }
}

public static class CaptureSummary
{
    public static List<CapturedPacket> Packets { get; } = new();
}
```

Why is this untestable?

1. **Static state is global state.** `TemplateCache.cache` is shared across all tests. If Test A adds a template, Test B sees it. Tests are not isolated.
2. **Static methods cannot be mocked.** You cannot replace `TemplateCache.GetTemplate()` with a test double that returns controlled data.
3. **I/O is mixed with computation.** The `Device_OnPacketArrival` event handler reads packets AND parses them AND writes to the summary — all in one method. You cannot test parsing without reading a real PCAP file.

### 6.2 The Separation Principle

Our architecture strictly separates three concerns:

```
┌──────────────────────────────────────────────────────┐
│                                                      │
│  I/O (reads bytes)     Computation (parses)   I/O    │
│  ┌──────────────┐      ┌─────────────────┐   ┌────┐ │
│  │ PcapReader   │ ───> │ NetFlowV9Parser │ > │JSON│ │
│  │ (SharpPcap)  │      │ (pure Span ops) │   │    │ │
│  └──────────────┘      └─────────────────┘   └────┘ │
│                                                      │
│  Depends on files       Depends on NOTHING   Depends │
│  and libraries          except Core models   on file │
│                                              system  │
└──────────────────────────────────────────────────────┘
```

The parser (`NetFlowV9Parser`) is the **pure computation** core. It takes a `ReadOnlySpan<byte>` and returns a `NetFlowPacket`. It does not know about PCAP files, JSON, disk, or network. It can be tested with nothing more than a `byte[]` array.

### 6.3 Interface-Driven Design

Every major component has an interface in the Core layer:

```csharp
// NetFlowAnalizer.Core/Services/INetFlowParser.cs
public interface INetFlowParser
{
    int SupportedVersion { get; }
    bool CanParse(ReadOnlySpan<byte> data);
    NetFlowPacket ParsePacket(ReadOnlySpan<byte> data);
}
```

```csharp
// NetFlowAnalizer.Core/Services/ITemplateCache.cs
public interface ITemplateCache
{
    void AddTemplate(uint sourceId, TemplateRecord template);
    TemplateRecord? GetTemplate(uint sourceId, ushort templateId);
    Dictionary<uint, Dictionary<ushort, TemplateRecord>> GetAllTemplates();
    void Clear();
}
```

Notice two critical design choices:

**1. The parser interface uses `ReadOnlySpan<byte>`, not `byte[]` or `Stream`:**

```csharp
// ❌ WRONG: Forces allocation of byte arrays
NetFlowPacket Parse(byte[] data);

// ❌ WRONG: Forces async I/O patterns for CPU-bound work
Task<NetFlowPacket> ParseAsync(Stream stream);

// ✅ RIGHT: Works on any contiguous memory without allocation
NetFlowPacket ParsePacket(ReadOnlySpan<byte> data);
```

**2. The parser is synchronous — no `async`, no `Task`:**

Parsing binary data from memory is a CPU-bound operation. Wrapping it in `Task` or `async` adds overhead (state machine allocation, thread pool scheduling) with zero benefit. We cover this in detail in Chapter 8.

### 6.4 How to Write Tests for This Architecture

With interfaces, testing becomes trivial. Here is how you would test each layer:

**Testing the parser** — no mock needed, just raw bytes:

```csharp
[Fact]
public void ParsePacket_ValidHeader_ReturnsCorrectVersion()
{
    // Arrange: construct a minimal valid NetFlow v9 packet
    var data = new byte[20];
    BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(0), 9);    // version
    BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(2), 0);    // count
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(4), 1000); // uptime
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(8), 1681234567); // unix
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(12), 1);   // seq
    BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(16), 171); // source

    var cache = new TemplateCache();
    var parser = new NetFlowV9Parser(
        NullLogger<NetFlowV9Parser>.Instance, cache);

    // Act
    var packet = parser.ParsePacket(data);

    // Assert
    Assert.Equal(9, packet.Header.Version);
    Assert.Equal((uint)171, packet.Header.SourceId);
}
```

**Testing the template cache** — pure in-memory, no I/O:

```csharp
[Fact]
public void GetTemplate_AfterAdd_ReturnsTemplate()
{
    // Arrange
    var cache = new TemplateCache();
    var template = new TemplateRecord
    {
        TemplateId = 256,
        Fields = { new TemplateField { Type = 8, Length = 4 } }
    };

    // Act
    cache.AddTemplate(sourceId: 171, template);
    var result = cache.GetTemplate(sourceId: 171, templateId: 256);

    // Assert
    Assert.NotNull(result);
    Assert.Equal(256, result.TemplateId);
    Assert.Single(result.Fields);
}
```

**Testing the PCAP reader** — mock the parser:

```csharp
// With a mocking framework (e.g., NSubstitute):
[Fact]
public void Process_CallsParserForEachNetFlowPacket()
{
    var mockParser = Substitute.For<INetFlowParser>();
    mockParser.CanParse(Arg.Any<ReadOnlySpan<byte>>()).Returns(true);
    mockParser.ParsePacket(Arg.Any<ReadOnlySpan<byte>>())
        .Returns(new NetFlowPacket { Header = ... });

    var reader = new NetFlowPcapReader(mockParser,
        NullLogger<NetFlowPcapReader>.Instance);

    var packetCount = 0;
    reader.Process("test.pcap", _ => packetCount++);

    Assert.True(packetCount > 0);
}
```

### 6.5 The Dependency Injection Advantage

Because the parser takes `ITemplateCache` via constructor injection:

```csharp
public sealed class NetFlowV9Parser : INetFlowParser
{
    private readonly ILogger<NetFlowV9Parser> _logger;
    private readonly ITemplateCache _templateCache;

    public NetFlowV9Parser(
        ILogger<NetFlowV9Parser> logger,
        ITemplateCache templateCache)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _templateCache = templateCache ?? throw new ArgumentNullException(nameof(templateCache));
    }
    // ...
}
```

...you can inject any implementation:

| Scenario | ITemplateCache Implementation |
|----------|------------------------------|
| Production | `TemplateCache` (in-memory, thread-safe) |
| Unit tests | A mock that returns pre-configured templates |
| Redis-backed | `RedisTemplateCache` (distributed cache) |
| Diagnostic | A wrapper that logs every cache hit/miss |

Compare this to the legacy static approach:

```csharp
// ❌ ANTI-PATTERN: Static dependency — cannot be replaced
var template = TemplateCache.GetTemplate(sourceId, templateId);

// ✅ RIGHT WAY: Injected dependency — can be any implementation
var template = _templateCache.GetTemplate(sourceId, templateId);
```

### 6.6 The sealed Keyword

Our parser is marked `sealed`:

```csharp
public sealed class NetFlowV9Parser : INetFlowParser
```

Why?

1. **Performance** — The JIT can devirtualize method calls on sealed classes, enabling inlining.
2. **Intent** — It communicates "this class is not designed for inheritance." If you want a different parser, implement `INetFlowParser` instead.
3. **Security** — Prevents subclasses from overriding critical parsing logic.

### 6.7 Guard Clauses

Every constructor validates its parameters:

```csharp
public NetFlowV9Parser(
    ILogger<NetFlowV9Parser> logger,
    ITemplateCache templateCache)
{
    _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    _templateCache = templateCache ?? throw new ArgumentNullException(nameof(templateCache));
}
```

This follows the **fail-fast principle**: if a dependency is null, crash immediately with a clear error message rather than producing a `NullReferenceException` ten levels deep in the call stack.

### 6.8 The Full Testing Matrix

Here is what becomes testable with our architecture:

| Component | What to Test | Dependencies Needed |
|-----------|-------------|-------------------|
| `NetFlowV9Header.FromBytes()` | Header parsing from raw bytes | None — static factory method |
| `TemplateCache` | Add/get/clear operations, thread safety | None — pure in-memory |
| `NetFlowV9Parser.CanParse()` | Version detection | `ITemplateCache` (mock) |
| `NetFlowV9Parser.ParsePacket()` | Full packet parsing | `ITemplateCache` (mock or real) |
| `NetFlowV9Parser.FormatField()` | Field formatting (IPs, ports, timestamps) | None — private, test via ParsePacket |
| `NetFlowPcapReader.Process()` | PCAP reading + callback invocation | `INetFlowParser` (mock), real PCAP file |
| `NetFlowJsonExporter` | JSON structure, streaming behavior | `ITemplateCache` (mock or real) |
| `Result<T>` | Success/Failure creation, value access | None — pure value type |

Every row in this table is possible **because we separated I/O from computation and used interfaces instead of static classes**.

### Summary

- Static classes (`static class TemplateCache`) are untestable — you cannot mock them or isolate tests
- Separate I/O (PCAP reading, JSON writing) from computation (parsing) — the parser takes `ReadOnlySpan<byte>`, not a file path
- Define interfaces in Core (`INetFlowParser`, `ITemplateCache`) and implement them in Infrastructure
- Use constructor injection with null guards for fail-fast behavior
- Mark implementation classes as `sealed` for performance and clear intent
- The parser can be fully tested with just a `byte[]` array — no PCAP files, no disk I/O, no network

---

> **End of Part II.** You now understand the protocol (Part I) and the architecture (Part II). In Part III, we will build the parser itself — diving deep into `ReadOnlySpan<byte>`, `BinaryPrimitives`, `stackalloc`, and the anti-patterns that kill performance in production.

