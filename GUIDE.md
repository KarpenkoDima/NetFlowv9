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

---

# Part III: Building the Parser (High-Performance Edition)

<a name="chapter-7"></a>
## Chapter 7. Parsing Binary Data in .NET (Span, BinaryPrimitives, stackalloc)

This is the most important chapter in the book. Everything you learned about architecture and protocols converges here into actual parsing code. We will examine three .NET primitives that separate junior-level code from production-grade code: `ReadOnlySpan<byte>`, `BinaryPrimitives`, and `stackalloc`.

### 7.1 The Three Pillars of High-Performance Binary Parsing

| Pillar | What It Does | What It Replaces |
|--------|-------------|-----------------|
| `ReadOnlySpan<byte>` | A stack-only view into contiguous memory. Slicing creates a new view, not a copy. | `MemoryStream`, `byte[]` sub-arrays, `ArraySegment<byte>` |
| `BinaryPrimitives` | Reads integers in big-endian or little-endian directly from a Span. Single CPU instruction. | `BitConverter.ToUInt16()` + `Array.Reverse()` |
| `stackalloc` | Allocates a small buffer on the stack. Zero GC pressure. Freed automatically when the method returns. | `new byte[N]` on the heap |

### 7.2 Pillar 1: ReadOnlySpan&lt;byte&gt; — Memory Without Copies

`Span<byte>` (and its read-only sibling `ReadOnlySpan<byte>`) is a **view** into existing memory. It does not own the memory — it points to it. This means:

```
byte[] array = { 0x00, 0x09, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD };
                  ↑─────────────────────────────────────────────────↑
                  array occupies 8 bytes on the heap

ReadOnlySpan<byte> span = array;
// span points to the SAME memory — no copy

ReadOnlySpan<byte> slice = span[4..];
// slice points to offset 4 of the SAME memory — still no copy
// slice sees: { 0xAA, 0xBB, 0xCC, 0xDD }
```

Compare with the old approach:

```csharp
// ❌ THE ANTI-PATTERN: Copying sub-arrays
byte[] subArray = new byte[4];
Array.Copy(array, 4, subArray, 0, 4);  // heap allocation + copy

// ❌ ALSO BAD: LINQ
byte[] subArray = array.Skip(4).Take(4).ToArray();  // even worse — iterator + allocation

// ✅ THE RIGHT WAY: Span slicing — zero copy
ReadOnlySpan<byte> slice = array.AsSpan(4, 4);  // just a pointer + length
```

In our parser, every FlowSet is a slice of the original packet data:

```csharp
// From NetFlowV9Parser.ParsePacket()
var content = data.Slice(contentStart, contentLength);
//                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//                 No copy! Just a new Span pointing into `data`
```

**The critical constraint:** `Span<T>` is a `ref struct` — it can only live on the stack. You cannot store it in a field, put it in a collection, or use it in an async method. This is a feature, not a bug: it guarantees the memory it points to is valid for the span's lifetime.

### 7.3 Pillar 2: BinaryPrimitives — The CPU Does the Work

`System.Buffers.Binary.BinaryPrimitives` provides methods that read integers from a span with explicit endianness. The JIT compiles these to a single `BSWAP` or `MOVBE` instruction on x86 — literally one CPU cycle.

```csharp
using System.Buffers.Binary;

ReadOnlySpan<byte> data = ...;

ushort version  = BinaryPrimitives.ReadUInt16BigEndian(data);       // 2 bytes
uint   uptime   = BinaryPrimitives.ReadUInt32BigEndian(data[4..]);  // 4 bytes
ulong  timestamp = BinaryPrimitives.ReadUInt64BigEndian(data[8..]); // 8 bytes
```

Let's compare this to the legacy approach step by step:

```csharp
// ❌ THE ANTI-PATTERN (from NetFlowAnalizer/Program.cs)
private static ushort ReadUInt16BigEndian(BinaryReader br)
{
    var bytes = br.ReadBytes(2);        // 1. Allocate byte[2] on the heap
    if (BitConverter.IsLittleEndian)    // 2. Runtime check (always true on x86)
        Array.Reverse(bytes);           // 3. Reverse the array in-place
    return BitConverter.ToUInt16(bytes, 0); // 4. Convert to ushort
}
// Total: 1 heap allocation + 1 branch + 1 array mutation + 1 conversion
// Called THOUSANDS of times per packet
```

```csharp
// ✅ THE RIGHT WAY (from NetFlowV9Parser)
BinaryPrimitives.ReadUInt16BigEndian(data[offset..])
// Total: 1 CPU instruction (BSWAP). Zero allocation. Zero branching.
```

The performance difference is dramatic. For a PCAP file with 100,000 NetFlow packets, each containing ~20 fields, the legacy approach creates **2,000,000+ byte[] allocations** just for reading integers. Our approach creates **zero**.

**Available methods:**

| Method | Reads |
|--------|-------|
| `ReadUInt16BigEndian(span)` | 2 bytes → `ushort` |
| `ReadUInt32BigEndian(span)` | 4 bytes → `uint` |
| `ReadUInt64BigEndian(span)` | 8 bytes → `ulong` |
| `ReadInt16BigEndian(span)` | 2 bytes → `short` |
| `ReadInt32BigEndian(span)` | 4 bytes → `int` |
| `ReadInt64BigEndian(span)` | 8 bytes → `long` |

### 7.4 Pillar 3: stackalloc — The Stack Is Your Friend

When you need a small temporary buffer (typically under 256 bytes), `stackalloc` allocates it on the stack instead of the heap:

```csharp
// ❌ THE ANTI-PATTERN: heap allocation for a 4-byte buffer
byte[] ipBytes = new byte[4];  // goes to the heap, triggers GC eventually
data.CopyTo(ipBytes);
var ip = new IPAddress(ipBytes);

// ✅ THE RIGHT WAY: stack allocation — zero GC pressure
Span<byte> ipBuf = stackalloc byte[4];  // lives on the stack, freed on method exit
data.CopyTo(ipBuf);
var ip = new IPAddress(ipBuf);
```

In our parser's `FormatField` method, we use this for IPv4 address parsing:

```csharp
// From NetFlowV9Parser.FormatField()
case 8:   // Src IP
case 12:  // Dst IP
case 15:  // Next Hop
case 225: // Post-NAT Src IP
case 226: // Post-NAT Dst IP
    if (data.Length == 4)
    {
        Span<byte> ipBuf = stackalloc byte[4];
        data.CopyTo(ipBuf);
        return new IPAddress(ipBuf).ToString();
    }
    return BitConverter.ToString(data.ToArray());
```

Why is `stackalloc` necessary here? Because `IPAddress` needs a `Span<byte>` or `byte[]` — it cannot take a `ReadOnlySpan<byte>`. We need a writable buffer. Instead of allocating `new byte[4]` on the heap (which would happen millions of times for a large capture), we allocate 4 bytes on the stack. The cost: zero. The buffer vanishes when the method returns.

**Rules for stackalloc:**
1. Only use for small, fixed-size buffers (< 256 bytes as a rule of thumb)
2. Never use in a recursive method — you'll overflow the stack
3. The buffer lives only until the method returns — do not store a reference to it

### 7.5 Putting It All Together: The Header Parser

Here is `NetFlowV9Header.FromBytes()` — a textbook example of all three pillars working together:

```csharp
// NetFlowAnalizer.Core/Models/NetFlowV9Header.cs
public static NetFlowV9Header FromBytes(ReadOnlySpan<byte> data)
{
    if (data.Length < HeaderSize)
        throw new ArgumentException(
            $"Data too short. Expected at least {HeaderSize} bytes, got {data.Length}");

    return new NetFlowV9Header(
        version:        BinaryPrimitives.ReadUInt16BigEndian(data),        // bytes 0-1
        count:          BinaryPrimitives.ReadUInt16BigEndian(data[2..]),    // bytes 2-3
        systemUpTime:   BinaryPrimitives.ReadUInt32BigEndian(data[4..]),    // bytes 4-7
        unixSeconds:    BinaryPrimitives.ReadUInt32BigEndian(data[8..]),    // bytes 8-11
        sequenceNumber: BinaryPrimitives.ReadUInt32BigEndian(data[12..]),   // bytes 12-15
        sourceId:       BinaryPrimitives.ReadUInt32BigEndian(data[16..]));  // bytes 16-19
}
```

What happens at runtime:
1. `data` is a `ReadOnlySpan<byte>` — it points to an existing `byte[]`, no copy
2. `data[2..]` creates a new span starting at offset 2 — no copy, just pointer arithmetic
3. `ReadUInt16BigEndian` reads 2 bytes and swaps them — single CPU instruction
4. The `NetFlowV9Header` is a `readonly record struct` — it lives on the stack

**Total heap allocations: zero.** The entire 20-byte header is parsed without a single `new` on the heap.

Compare with the legacy version:

```csharp
// ❌ LEGACY: NetFlowAnalizer/Program.cs
public static NetFlowPacket ParseHeader(byte[] bytes)
{
    using var ms = new MemoryStream(bytes);    // heap: MemoryStream object
    using var br = new BinaryReader(ms);       // heap: BinaryReader object

    var packet = new NetFlowPacket              // heap: NetFlowPacket object
    {
        Version = ReadUInt16BigEndian(br),      // heap: byte[2] + Array.Reverse
        Count = ReadUInt16BigEndian(br),        // heap: byte[2] + Array.Reverse
        SysUptime = ReadUInt32BigEndian(br),    // heap: byte[4] + Array.Reverse
        UnixSecs = ReadUInt32BigEndian(br),     // heap: byte[4] + Array.Reverse
        SequenceNumber = ReadUInt32BigEndian(br),// heap: byte[4] + Array.Reverse
        SourceId = ReadUInt32BigEndian(br)      // heap: byte[4] + Array.Reverse
    };
    return packet;
}
// Total: 1 MemoryStream + 1 BinaryReader + 1 NetFlowPacket + 6 byte[] arrays
// = 9 heap allocations PER HEADER PARSE
```

### 7.6 The MethodImpl Hint

You may have noticed this attribute on some methods:

```csharp
[MethodImpl(MethodImplOptions.AggressiveInlining)]
public bool CanParse(ReadOnlySpan<byte> data)
{
    return data.Length >= NetFlowV9Header.HeaderSize
        && BinaryPrimitives.ReadUInt16BigEndian(data) == 9;
}
```

`AggressiveInlining` is a hint to the JIT compiler: "This method is small and hot — please inline it at every call site." Inlining eliminates the overhead of a method call (pushing arguments, jumping, returning). For a method called once per packet, this can save microseconds that add up over millions of packets.

Use this sparingly — only on small, frequently-called methods. The JIT is usually smart enough on its own, but for the hottest paths in a parser, it is worth the hint.

### Summary

- **`ReadOnlySpan<byte>`** — view into memory without copying. Slicing is free.
- **`BinaryPrimitives`** — reads big-endian integers in a single CPU instruction. Replaces `BinaryReader` + `Array.Reverse`.
- **`stackalloc`** — allocates small buffers on the stack. Zero GC pressure. Use for temporary buffers like IPv4 parsing.
- The legacy parser creates **9+ heap allocations per header**. Our parser creates **zero**.
- Use `[MethodImpl(MethodImplOptions.AggressiveInlining)]` on small hot methods.

---

<a name="chapter-8"></a>
## Chapter 8. The Async Over Sync Anti-Pattern (Why Parsing Must Be Synchronous)

### 8.1 The Temptation

You have heard that modern C# should be async. Every tutorial tells you to `await` everything. So when you write a parser, you might be tempted to do this:

```csharp
// ❌ THE ANTI-PATTERN: async for CPU-bound work
public interface INetFlowParser
{
    Task<NetFlowPacket> ParsePacketAsync(byte[] data);
}

public class NetFlowV9Parser : INetFlowParser
{
    public async Task<NetFlowPacket> ParsePacketAsync(byte[] data)
    {
        return await Task.Run(() =>
        {
            // ... parsing logic ...
        });
    }
}
```

**This is wrong.** Not "slightly suboptimal." Wrong.

### 8.2 Why Async Parsing Is Wrong

**Reason 1: Parsing is CPU-bound, not I/O-bound.**

`async/await` exists to free threads while waiting for I/O: disk reads, network calls, database queries. When you `await` an I/O operation, the thread is returned to the thread pool to do other work.

Parsing binary data from memory is **CPU-bound**. The data is already in RAM. There is nothing to wait for. Wrapping it in `Task.Run` does not make it faster — it just moves the work from one thread to another, adding overhead:

```
Without Task.Run:
  Thread A: [parse 500 µs]

With Task.Run:
  Thread A: [queue task 10 µs] [idle, waiting] [resume 10 µs]
  Thread B:                    [parse 500 µs]

Result: Same work, 20 µs MORE overhead, one MORE thread occupied.
```

**Reason 2: `Task.Run` allocates.**

Every `Task.Run` call allocates:
- A `Task<T>` object on the heap
- A delegate (closure) on the heap
- A state machine if you use `async/await`

For a parser called 100,000 times, that is 300,000+ extra heap allocations — directly contradicting our zero-allocation goal.

**Reason 3: `ReadOnlySpan<byte>` cannot cross async boundaries.**

This is the technical knockout. `Span<T>` and `ReadOnlySpan<T>` are `ref struct` types — they can only live on the stack. You **cannot** use them inside an `async` method:

```csharp
// ❌ COMPILER ERROR: Cannot use ReadOnlySpan<byte> in async method
public async Task<NetFlowPacket> ParsePacketAsync(ReadOnlySpan<byte> data)
{
    // CS4012: Parameters of type 'ReadOnlySpan<byte>' cannot be declared
    // in async methods or async lambda expressions.
}
```

The compiler will refuse to compile this. `async` methods are transformed into state machines that store local variables in a heap-allocated class. `Span<T>` cannot be stored on the heap — so `async` and `Span<T>` are fundamentally incompatible.

### 8.3 The Right Way

Our parser interface is deliberately synchronous:

```csharp
// ✅ THE RIGHT WAY: Synchronous, Span-based
// NetFlowAnalizer.Core/Services/INetFlowParser.cs
public interface INetFlowParser
{
    int SupportedVersion { get; }
    bool CanParse(ReadOnlySpan<byte> data);
    NetFlowPacket ParsePacket(ReadOnlySpan<byte> data);
}
```

No `Task`. No `async`. No `await`. The data is in memory; the parser reads it; the result comes back immediately.

The calling code in `NetFlowPcapReader` is also synchronous:

```csharp
// From NetFlowPcapReader.Process()
var packet = _parser.ParsePacket(payload.AsSpan());
```

One line. The span lives on the stack. The parsing happens on the current thread. No thread pool, no state machine, no allocation.

### 8.4 Where Async IS Appropriate

Async belongs in the I/O layer — not the parsing layer:

| Operation | Sync or Async? | Why |
|-----------|---------------|-----|
| Parsing bytes from memory | **Sync** | CPU-bound, data already in RAM |
| Reading a PCAP file | **Sync** (pull-based) | SharpPcap provides a synchronous iterator |
| Writing JSON to disk | **Sync** (`Utf8JsonWriter.Flush`) | Writing is buffered; the 65 KB buffer handles it |
| Sending data over the network | **Async** | I/O-bound, waiting for network response |
| Querying a database | **Async** | I/O-bound, waiting for DB response |
| HTTP API calls | **Async** | I/O-bound, waiting for remote server |

Notice that our `INetFlowRepository` interface uses async correctly — because database operations are I/O-bound:

```csharp
public interface INetFlowRepository
{
    Task SaveRecordAsync(IEnumerable<INetFlowRecord> records,
        CancellationToken cancellationToken = default);
}
```

### 8.5 The Legacy Mistake

The legacy code in `NetFlowAnalizer/Program.cs` had `async Task Main`:

```csharp
// ❌ LEGACY: async Main with no actual async operations
public static async Task Main(string[] args)
{
    // ... everything here is synchronous
    NetFlowPcapReader reader = new NetFlowPcapReader();
    reader.Read(pcapFilePath);         // synchronous
    reader.ExportToJson(jsonOutputPath); // synchronous
}
```

The `async` keyword on `Main` is pointless here — there are no `await` calls. It just creates an unnecessary state machine. Our `Program.cs` returns `int` directly:

```csharp
// ✅ OUR CODE: synchronous pipeline, no false async
try
{
    exporter.BeginExport(jsonOutputPath);
    reader.Process(pcapFilePath, packet => exporter.WritePacket(in packet));
    exporter.EndExport();
    return 0;
}
catch (Exception ex)
{
    logger.LogError(ex, "Error processing NetFlow data");
    return 1;
}
```

### Summary

- `async/await` is for I/O-bound work (network, disk, database). Binary parsing is CPU-bound — keep it synchronous.
- `Task.Run` around parsing adds overhead (thread switch, allocations) with no benefit.
- `ReadOnlySpan<byte>` **cannot be used inside async methods** — the compiler enforces this.
- Our parser interface is deliberately `NetFlowPacket ParsePacket(ReadOnlySpan<byte> data)` — no Task, no async.
- Use async only in the repository layer (`INetFlowRepository`) where actual I/O occurs.

---

<a name="chapter-9"></a>
## Chapter 9. The Global Lock Anti-Pattern (ConcurrentDictionary for Template Caching)

### 9.1 The Problem: Shared Mutable State

NetFlow v9 parsing has a stateful component: the **template cache**. Templates arrive in one packet and are used to decode data in subsequent packets. This cache must be:

1. **Readable** during data FlowSet parsing (hot path)
2. **Writable** when new templates arrive
3. **Safe** if multiple threads access it (e.g., multiple exporters sending to the same collector)

### 9.2 The Legacy Approach: Static + No Locking

The original code used a static dictionary with no thread safety:

```csharp
// ❌ THE ANTI-PATTERN: Global static state, no thread safety
// From NetFlowAnalizer/Program.cs
public static class TemplateCache
{
    private static readonly Dictionary<uint, Dictionary<ushort, TemplateRecord>> cache = new();

    public static void AddTemplate(uint sourceId, TemplateRecord template)
    {
        if (!cache.ContainsKey(sourceId))
            cache[sourceId] = new Dictionary<ushort, TemplateRecord>();

        cache[sourceId][template.TemplateId] = template;
    }

    public static TemplateRecord? GetTemplate(uint sourceId, ushort templateId)
    {
        if (cache.TryGetValue(sourceId, out var templates))
            if (templates.TryGetValue(templateId, out var template))
                return template;

        return null;
    }
}
```

Three problems:

1. **Static state** — `cache` is a global singleton. You cannot run two parsers with separate caches. Tests pollute each other.
2. **Not thread-safe** — `Dictionary<K,V>` is not safe for concurrent reads and writes. If two threads call `AddTemplate` simultaneously, the dictionary can corrupt internally (duplicate keys, lost entries, infinite loops in hash chains).
3. **ContainsKey + indexer race** — The pattern `if (!cache.ContainsKey(key)) cache[key] = ...` is a classic TOCTOU (time-of-check-to-time-of-use) bug. Between the `ContainsKey` check and the assignment, another thread can insert the same key.

### 9.3 The Right Way: Instance + Lock

Our implementation in `NetFlowAnalizer.Infrastructure/Services/TemplateCache.cs`:

```csharp
// ✅ THE RIGHT WAY: Instance-based, thread-safe with lock
public class TemplateCache : ITemplateCache
{
    private readonly Dictionary<uint, Dictionary<ushort, TemplateRecord>> _cache = new();
    private readonly object _lock = new();

    public void AddTemplate(uint sourceId, TemplateRecord template)
    {
        lock (_lock)
        {
            if (!_cache.ContainsKey(sourceId))
                _cache[sourceId] = new Dictionary<ushort, TemplateRecord>();

            _cache[sourceId][template.TemplateId] = template;
        }
    }

    public TemplateRecord? GetTemplate(uint sourceId, ushort templateId)
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(sourceId, out var templates))
                if (templates.TryGetValue(templateId, out var template))
                    return template;

            return null;
        }
    }

    public Dictionary<uint, Dictionary<ushort, TemplateRecord>> GetAllTemplates()
    {
        lock (_lock)
        {
            // Return a deep copy to avoid external modifications
            var result = new Dictionary<uint, Dictionary<ushort, TemplateRecord>>();
            foreach (var kvp in _cache)
            {
                result[kvp.Key] = new Dictionary<ushort, TemplateRecord>(kvp.Value);
            }
            return result;
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _cache.Clear();
        }
    }
}
```

Key improvements:

| Legacy | Our Version |
|--------|------------|
| `static class` — one global instance | Regular `class` — injectable via DI |
| No locking — data corruption risk | `lock (_lock)` — thread-safe |
| No `Clear()` — leaks memory | `Clear()` method for reset |
| Returns internal references | `GetAllTemplates()` returns a deep copy |

### 9.4 Why lock Instead of ConcurrentDictionary?

You might ask: "Why not use `ConcurrentDictionary<K,V>` instead of `lock`?"

For our use case, `lock` is the better choice:

**1. We have a nested dictionary structure:**

```csharp
Dictionary<uint, Dictionary<ushort, TemplateRecord>>
//         ↑                  ↑
//     sourceId          templateId
```

`ConcurrentDictionary` makes individual operations atomic, but not compound operations. `GetOrAdd` on the outer dictionary does not protect the inner dictionary. You would need:

```csharp
// With ConcurrentDictionary — still needs locking for the inner dict!
var inner = _cache.GetOrAdd(sourceId, _ => new ConcurrentDictionary<ushort, TemplateRecord>());
inner[template.TemplateId] = template;  // safe for ConcurrentDictionary
```

This works, but adds complexity for no real gain in our scenario.

**2. Template updates are infrequent:**

Templates arrive once every few minutes. Data lookups happen thousands of times per second. But even during data parsing, our current design is single-threaded (one PCAP reader, one parser). The lock is uncontended — it costs ~20 nanoseconds. This is invisible compared to the microseconds spent parsing each packet.

**3. The lock is simple and correct:**

With `lock`, the semantics are obvious: one thread at a time inside each critical section. No subtle race conditions. No "I thought GetOrAdd was atomic but the factory ran twice." Simple code is correct code.

### 9.5 The Deep Copy Pattern

`GetAllTemplates()` deserves special attention:

```csharp
public Dictionary<uint, Dictionary<ushort, TemplateRecord>> GetAllTemplates()
{
    lock (_lock)
    {
        var result = new Dictionary<uint, Dictionary<ushort, TemplateRecord>>();
        foreach (var kvp in _cache)
        {
            result[kvp.Key] = new Dictionary<ushort, TemplateRecord>(kvp.Value);
        }
        return result;
    }
}
```

This returns a **deep copy** of the cache. Why?

1. The caller (JSON exporter) will iterate over the templates while writing JSON. If the cache is modified during iteration (a new template arrives), we get `InvalidOperationException: Collection was modified`.
2. A deep copy is safe to iterate outside the lock — no contention.
3. Templates are small (a few KB total), so copying is cheap.

### 9.6 The Data Structure

The cache uses a two-level dictionary:

```
_cache:
  sourceId=171:
    templateId=256: TemplateRecord { Fields: [SrcIP, DstIP, SrcPort, ...] }
    templateId=257: TemplateRecord { Fields: [Protocol, Bytes, Packets, ...] }
  sourceId=200:
    templateId=256: TemplateRecord { Fields: [SrcIP, DstIP, ...] }
```

The first level is `sourceId` — because different routers (sources) can define different templates with the same ID. Template 256 from router A might have different fields than template 256 from router B.

The second level is `templateId` — the actual template lookup.

### Summary

- Static global caches are untestable and not thread-safe — use instance-based classes with DI
- Wrap all dictionary operations in `lock` for thread safety
- For nested dictionaries, `lock` is simpler and more correct than `ConcurrentDictionary`
- Return deep copies from `GetAllTemplates()` to prevent `Collection was modified` exceptions
- Template IDs are scoped per source — the cache key is `(sourceId, templateId)`

---

<a name="chapter-10"></a>
## Chapter 10. Zero-Copy Parsing with Span (The Complete Parser Code)

This chapter presents the complete `NetFlowV9Parser` — the heart of our application. We have covered the individual techniques; now we see them working together as a cohesive unit.

### 10.1 The Class Declaration

```csharp
// NetFlowAnalizer.Infrastructure/Parsers/NetFlowV9Parser.cs
using System.Buffers.Binary;
using System.Net;
using System.Runtime.CompilerServices;

public sealed class NetFlowV9Parser : INetFlowParser
{
    private readonly ILogger<NetFlowV9Parser> _logger;
    private readonly ITemplateCache _templateCache;

    public NetFlowV9Parser(ILogger<NetFlowV9Parser> logger, ITemplateCache templateCache)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _templateCache = templateCache ?? throw new ArgumentNullException(nameof(templateCache));
    }

    public int SupportedVersion => 9;
```

Key points:
- `sealed` — enables JIT devirtualization (Chapter 6)
- Constructor injection — `ILogger` for diagnostics, `ITemplateCache` for template storage (Chapter 6)
- `SupportedVersion` — allows future multi-version dispatching

### 10.2 The Fast-Path Check

```csharp
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool CanParse(ReadOnlySpan<byte> data)
    {
        return data.Length >= NetFlowV9Header.HeaderSize
            && BinaryPrimitives.ReadUInt16BigEndian(data) == 9;
    }
```

This is called for **every UDP packet** in the PCAP file. It must be fast. Two checks:
1. Is the payload long enough to contain a header? (20 bytes)
2. Is the version field equal to 9?

`AggressiveInlining` ensures this is compiled directly into the call site — no method call overhead.

### 10.3 The Main Parse Loop

```csharp
    public NetFlowPacket ParsePacket(ReadOnlySpan<byte> data)
    {
        var header = NetFlowV9Header.FromBytes(data);
        var packet = new NetFlowPacket { Header = header };
        var offset = NetFlowV9Header.HeaderSize;  // 20

        while (offset + 4 <= data.Length)
        {
            var flowSetId     = BinaryPrimitives.ReadUInt16BigEndian(data[offset..]);
            var flowSetLength = BinaryPrimitives.ReadUInt16BigEndian(data[(offset + 2)..]);

            if (flowSetLength < 4 || offset + flowSetLength > data.Length)
            {
                _logger.LogWarning(
                    "Invalid FlowSet: ID={Id}, Length={Length}, Offset={Offset}",
                    flowSetId, flowSetLength, offset);
                break;
            }

            var contentStart  = offset + 4;
            var contentLength = flowSetLength - 4;
            var content = data.Slice(contentStart, contentLength);

            if (flowSetId == 0)
                ParseTemplateFlowSet(content, header.SourceId, packet.Templates);
            else if (flowSetId >= 256)
                ParseDataFlowSet(content, header.SourceId, flowSetId, packet.DataRecords);

            offset += flowSetLength;
        }

        return packet;
    }
```

Let's walk through this step by step:

**Step 1:** Parse the 20-byte header using `FromBytes` (zero-alloc, Chapter 7).

**Step 2:** Start iterating FlowSets at offset 20.

**Step 3:** For each FlowSet, read the 4-byte header (ID + length). Validate: length must be >= 4 (the header itself) and must not exceed the remaining data.

**Step 4:** Slice the content — `data.Slice(contentStart, contentLength)` — **zero copy**. This creates a new `ReadOnlySpan<byte>` pointing into the original `data`.

**Step 5:** Dispatch based on FlowSet ID:
- ID 0 → Template FlowSet → `ParseTemplateFlowSet`
- ID >= 256 → Data FlowSet → `ParseDataFlowSet`
- ID 1 → Options Template → skipped (not implemented)

**Step 6:** Advance `offset` by `flowSetLength` to the next FlowSet.

### 10.4 Template Parsing

```csharp
    private void ParseTemplateFlowSet(
        ReadOnlySpan<byte> content, uint sourceId, List<TemplateRecord> outTemplates)
    {
        var offset = 0;

        while (offset + 4 <= content.Length)
        {
            var templateId = BinaryPrimitives.ReadUInt16BigEndian(content[offset..]);
            var fieldCount = BinaryPrimitives.ReadUInt16BigEndian(content[(offset + 2)..]);
            offset += 4;

            var bytesNeeded = fieldCount * 4;
            if (offset + bytesNeeded > content.Length)
            {
                _logger.LogWarning(
                    "Template {TemplateId} truncated: need {Need} bytes, have {Have}",
                    templateId, bytesNeeded, content.Length - offset);
                break;
            }

            var template = new TemplateRecord { TemplateId = templateId };
            template.Fields.EnsureCapacity(fieldCount);

            for (var i = 0; i < fieldCount; i++)
            {
                var fieldType   = BinaryPrimitives.ReadUInt16BigEndian(content[offset..]);
                var fieldLength = BinaryPrimitives.ReadUInt16BigEndian(content[(offset + 2)..]);
                offset += 4;

                template.Fields.Add(new TemplateField
                {
                    Type = fieldType,
                    Length = fieldLength
                });
            }

            _templateCache.AddTemplate(sourceId, template);
            outTemplates.Add(template);
        }
    }
```

Notable details:

- **`EnsureCapacity(fieldCount)`** — pre-allocates the `List<TemplateField>` internal array. Without this, the list would resize (double) multiple times as fields are added: 4 → 8 → 16. With `EnsureCapacity`, one allocation to the right size.
- **Truncation check** — `if (offset + bytesNeeded > content.Length)` prevents reading beyond the FlowSet boundary. Real-world PCAP data is messy — packets can be truncated.
- **Dual output** — templates are added to both `_templateCache` (for future Data FlowSet parsing) and `outTemplates` (for JSON export).

### 10.5 Data FlowSet Parsing

```csharp
    private void ParseDataFlowSet(
        ReadOnlySpan<byte> content, uint sourceId,
        ushort templateId, List<DataRecord> outRecords)
    {
        var template = _templateCache.GetTemplate(sourceId, templateId);
        if (template is null)
        {
            _logger.LogWarning(
                "No template for Source={SourceId}, Template={TemplateId}",
                sourceId, templateId);
            return;
        }

        var recordLength = template.RecordLength;
        if (recordLength == 0) return;

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
    }
```

The algorithm:

1. Look up the template from the cache. No template? Log a warning and skip.
2. Compute `recordLength` — the sum of all field lengths in the template.
3. While there are enough bytes left for another complete record, parse it:
   - For each field in the template, slice `field.Length` bytes from the content
   - Format the field value using `FormatField`
   - Store in the record's dictionary

**Note:** `content.Slice(offset, field.Length)` is again zero-copy. The `fieldData` span points into the original UDP payload — we never copy the bytes.

### 10.6 The Field Formatter

```csharp
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private string FormatField(ushort fieldType, ReadOnlySpan<byte> data)
    {
        switch (fieldType)
        {
            // --- Single byte fields ---
            case 4: case 5: case 6: case 9: case 13:
                return data.Length == 1
                    ? data[0].ToString()
                    : BitConverter.ToString(data.ToArray());

            // --- IPv4 addresses (4 bytes) ---
            case 8: case 12: case 15: case 225: case 226:
                if (data.Length == 4)
                {
                    Span<byte> ipBuf = stackalloc byte[4];
                    data.CopyTo(ipBuf);
                    return new IPAddress(ipBuf).ToString();
                }
                return BitConverter.ToString(data.ToArray());

            // --- 16-bit integers ---
            case 7: case 11: case 227: case 228:
                return data.Length == 2
                    ? BinaryPrimitives.ReadUInt16BigEndian(data).ToString()
                    : BitConverter.ToString(data.ToArray());

            // --- 32-bit integers ---
            case 1: case 2: case 10: case 14: case 34: case 35:
                return data.Length == 4
                    ? BinaryPrimitives.ReadUInt32BigEndian(data).ToString()
                    : BitConverter.ToString(data.ToArray());

            // --- 64-bit timestamps ---
            case 80: case 81:
                if (data.Length == 8)
                {
                    var ms = (long)BinaryPrimitives.ReadUInt64BigEndian(data);
                    return DateTimeOffset.FromUnixTimeMilliseconds(ms)
                        .ToString("yyyy-MM-dd HH:mm:ss");
                }
                return BitConverter.ToString(data.ToArray());

            // --- Everything else → hex ---
            default:
                return BitConverter.ToString(data.ToArray());
        }
    }
```

This method converts raw bytes to human-readable strings. Unavoidably, it allocates strings — but the **reading** of bytes from the span is zero-allocation.

Techniques used:
- **Single byte:** Direct indexing `data[0]` — no span slicing needed
- **IPv4:** `stackalloc byte[4]` + `new IPAddress(ipBuf)` — the only heap alloc is the `IPAddress` object and the returned string
- **16/32-bit integers:** `BinaryPrimitives.ReadUIntXXBigEndian` — one CPU instruction
- **64-bit timestamps:** `ReadUInt64BigEndian` → `DateTimeOffset.FromUnixTimeMilliseconds` — converts Unix ms to human-readable date
- **Fallback:** `BitConverter.ToString(data.ToArray())` — hex dump for unknown fields. This calls `.ToArray()` (allocation), but only for rare/unknown field types

### 10.7 Comparison: Legacy vs. High-Performance

Let's compare parsing a single data record with 7 fields:

**Legacy (NetFlowAnalizer/Program.cs):**

```csharp
// Per record:
using var ms = new MemoryStream(data);       // 1 MemoryStream
using var br = new BinaryReader(ms);          // 1 BinaryReader
var record = new Dictionary<ushort, byte[]>();
foreach (var field in template.Fields)
{
    var bytes = br.ReadBytes(field.Length);    // 7 × byte[] allocations
    record[field.Type] = bytes;
}
// Total: 2 stream objects + 7 byte arrays = 9 heap allocations per record
```

**Our parser:**

```csharp
// Per record:
var record = new DataRecord { TemplateId = templateId };  // 1 DataRecord
foreach (var field in template.Fields)
{
    var fieldData = content.Slice(offset, field.Length);   // 0 allocations (span slice)
    var value = FormatField(field.Type, fieldData);        // 1 string (unavoidable)
    record.Values[field.Type.ToString()] = value;
    offset += field.Length;
}
// Total: 1 DataRecord + 7 strings = 8 allocations, but 0 intermediate byte arrays
```

The big wins:
- **Zero `MemoryStream`** — no stream objects
- **Zero `BinaryReader`** — no reader objects
- **Zero `byte[]` copies** — `Slice` is free
- **Zero `Array.Reverse`** — `BinaryPrimitives` handles endianness

### Summary

- The complete parser is 233 lines of code — compact and focused
- `ParsePacket` iterates FlowSets using span slicing — zero copy at every level
- `ParseTemplateFlowSet` caches templates and pre-allocates lists with `EnsureCapacity`
- `ParseDataFlowSet` looks up cached templates and iterates records using the template's field layout
- `FormatField` converts raw bytes to strings using `BinaryPrimitives` and `stackalloc`
- The parser creates zero intermediate `byte[]` arrays — all data access is through `ReadOnlySpan<byte>`

---

# Part IV: Infrastructure and I/O (Streaming Edition)

<a name="chapter-11"></a>
## Chapter 11. The OutOfMemory (OOM) Catastrophe (Streaming with Callbacks)

### 11.1 The Disaster Scenario

You have a 5 GB PCAP file containing 2 million NetFlow packets. You write a straightforward program:

```csharp
// ❌ THE ANTI-PATTERN: Accumulate everything in a list
var allPackets = new List<NetFlowPacket>();

foreach (var rawPacket in ReadPcap(filePath))
{
    var packet = parser.ParsePacket(rawPacket);
    allPackets.Add(packet);  // ← growing without bound
}

// Now export
File.WriteAllText("output.json", JsonSerializer.Serialize(allPackets));
```

What happens:
1. First 100,000 packets: memory grows to 500 MB. Fine.
2. First 500,000 packets: memory grows to 2.5 GB. Swapping begins.
3. First 1,000,000 packets: `OutOfMemoryException`. Process crashes.

The legacy code had exactly this pattern:

```csharp
// ❌ LEGACY: NetFlowAnalizer/Program.cs
public static class CaptureSummary
{
    public static List<CapturedPacket> Packets { get; } = new List<CapturedPacket>();

    public static void AddPacket(NetFlowPacket header, List<ParsedFlowSet> flowSets)
    {
        Packets.Add(new CapturedPacket  // ← NEVER released
        {
            Header = header,
            FlowSets = flowSets
        });
    }
}
```

Every parsed packet is added to `CaptureSummary.Packets` and **never released**. For the lifetime of the program, every single packet lives in memory. This is O(N) memory — where N is the number of packets in the PCAP file.

Then at the end, the entire tree is serialized at once:

```csharp
// ❌ LEGACY: Serialize EVERYTHING at once
string json = JsonSerializer.Serialize(dashboardData, options);
File.WriteAllText(outputPath, json);
// `json` is a single string with the ENTIRE JSON document in memory
```

This doubles the memory usage — the object tree AND its JSON string representation exist simultaneously.

### 11.2 The Solution: O(1) Memory with Callbacks

Our design eliminates accumulation entirely:

```
┌─────────────┐     callback      ┌──────────────┐     flush     ┌──────┐
│ PcapReader   │ ──────────────> │ JsonExporter   │ ───────────> │ Disk │
│ (reads 1     │  Action<packet> │ (writes 1      │  every 100   │      │
│  packet)     │                 │  packet to     │  packets     │      │
│              │                 │  Utf8JsonWriter)│              │      │
└─────────────┘                  └──────────────┘               └──────┘
       ↑                                ↑
       │ After callback returns,        │ After flush,
       │ packet is eligible for GC      │ writer buffer is cleared
       │                                │
       └── O(1) memory ────────────────-┘
```

The `Process` method signature tells the whole story:

```csharp
// ✅ THE RIGHT WAY: Callback pattern — process one, discard, repeat
public void Process(
    string pcapFilePath,
    Action<NetFlowPacket> onPacket,    // ← callback, not return value
    CancellationToken cancellationToken = default)
```

Instead of returning `List<NetFlowPacket>`, the method takes an `Action<NetFlowPacket>` callback. For each packet:
1. Parse it
2. Call the callback (which writes it to JSON)
3. The callback returns
4. The `packet` variable goes out of scope
5. GC can reclaim it

At any point in time, only **one packet** exists in memory. The 5 GB PCAP file? Still O(1) memory.

### 11.3 How It's Wired in Program.cs

```csharp
// From NetFlowAnalizer.Console/Program.cs

// 1. Open JSON file, write preamble
exporter.BeginExport(jsonOutputPath);

// 2. For each packet: parse → write → discard
reader.Process(pcapFilePath, packet =>
{
    exporter.WritePacket(in packet);
});

// 3. Write templates + close JSON
exporter.EndExport();
```

Three lines. The lambda `packet => exporter.WritePacket(in packet)` is the callback. Note `in packet` — the `in` keyword passes the `NetFlowPacket` by readonly reference, avoiding a copy of the struct-containing object.

### 11.4 Memory Profile Comparison

| Approach | 10K packets | 100K packets | 1M packets | 10M packets |
|----------|-------------|-------------|------------|------------|
| ❌ `List<T>` accumulation | 50 MB | 500 MB | 5 GB (OOM) | impossible |
| ✅ Callback streaming | ~50 MB | ~50 MB | ~50 MB | ~50 MB |

The ~50 MB is the baseline: .NET runtime, SharpPcap buffers, the 65 KB JSON write buffer, and one packet's worth of parsed data. It does not grow with input size.

### 11.5 The Callback Pattern vs. Other Approaches

Why did we use `Action<T>` instead of other patterns?

| Pattern | Pros | Cons | Our Choice |
|---------|------|------|-----------|
| `Action<T>` callback | Simple, synchronous, zero overhead | Not composable | **Yes** |
| `IEnumerable<T>` (yield return) | Composable with LINQ | Cannot use `Span<T>` inside iterators | No |
| `IAsyncEnumerable<T>` | Async-friendly | Overhead for sync work, cannot use Span | No |
| `IObservable<T>` (Rx) | Rich operators | Heavy dependency, overkill for our use | No |
| `Channel<T>` | Producer-consumer, backpressure | Thread overhead, more complex | No |

The `Action<T>` callback is the simplest pattern that achieves O(1) memory. And since our parsing is synchronous (Chapter 8), we don't need async patterns.

### Summary

- Accumulating packets in `List<T>` causes `OutOfMemoryException` on large files — memory grows as O(N)
- The callback pattern (`Action<NetFlowPacket>`) processes one packet at a time — memory is O(1)
- After the callback returns, the packet is eligible for GC — no accumulation
- The legacy code stored all packets in a static `List<CapturedPacket>` — guaranteed OOM on large inputs
- Our pipeline: `BeginExport` → `Process(callback)` → `EndExport` — three lines, constant memory

---

<a name="chapter-12"></a>
## Chapter 12. Streaming JSON with Utf8JsonWriter

### 12.1 The Serialization Anti-Pattern

The legacy code serialized the entire object tree into a single JSON string:

```csharp
// ❌ THE ANTI-PATTERN: Serialize everything at once
// From NetFlowAnalizer/Program.cs → NetFlowJsonExporter.ExportToJson()

var dashboardData = new
{
    version = 9,
    exportTime = DateTime.UtcNow,
    packets = CaptureSummary.Packets.Select(p => new  // ← ALL packets in memory
    {
        version = p.Header.Version,
        count = p.Header.Count,
        // ... more LINQ projections creating anonymous objects ...
        flowSets = p.FlowSets.Select(fs => new { ... }).ToArray()
    }).ToArray(),
    templates = TemplateCache.GetAllTemplates()
};

var options = new JsonSerializerOptions { WriteIndented = true };
string json = JsonSerializer.Serialize(dashboardData, options);
//     ^^^^
//     A SINGLE STRING with the ENTIRE JSON document.
//     For 1 million records, this string alone can be hundreds of MB.

File.WriteAllText(outputPath, json);
```

Memory usage for this approach:
1. `CaptureSummary.Packets` — all parsed packets (let's say 500 MB)
2. Anonymous objects from LINQ — mirrors of the above (another 500 MB)
3. `json` string — the serialized output (another 500 MB)
4. **Total: ~1.5 GB for data that could be written in 50 MB of RAM**

### 12.2 The Solution: Utf8JsonWriter

`System.Text.Json.Utf8JsonWriter` writes JSON **directly to a stream** — one token at a time. It never builds the entire document in memory.

Here is our complete exporter from `NetFlowAnalizer.Infrastructure/Export/NetFlowJsonExporter.cs`:

**Phase 1: Open the file and write the preamble**

```csharp
public sealed class NetFlowJsonExporter : IDisposable
{
    private FileStream? _fileStream;
    private Utf8JsonWriter? _writer;
    private int _packetCount;

    public void BeginExport(string outputPath)
    {
        _fileStream = new FileStream(
            outputPath, FileMode.Create, FileAccess.Write,
            FileShare.None, bufferSize: 65536);  // 64 KB buffer

        _writer = new Utf8JsonWriter(_fileStream, new JsonWriterOptions
        {
            Indented = true
        });

        _packetCount = 0;

        // Write: { "version": 9, "exportTime": "...", "packets": [
        _writer.WriteStartObject();
        _writer.WriteNumber("version", 9);
        _writer.WriteString("exportTime", DateTime.UtcNow);
        _writer.WriteStartArray("packets");
    }
```

Key detail: **`bufferSize: 65536`**. The `FileStream` accumulates writes in a 64 KB buffer before flushing to disk. This means thousands of `_writer.WriteXxx()` calls produce only a few disk writes — efficient I/O.

**Phase 2: Write one packet at a time (called from the callback)**

```csharp
    public void WritePacket(in NetFlowPacket packet)
    {
        if (_writer is null)
            throw new InvalidOperationException("Call BeginExport first");

        _packetCount++;

        _writer.WriteStartObject();

        // Header fields
        _writer.WriteNumber("version", packet.Header.Version);
        _writer.WriteNumber("count", packet.Header.Count);
        _writer.WriteNumber("sysUptime", packet.Header.SystemUpTime);
        _writer.WriteNumber("unixSecs", packet.Header.UnixSeconds);
        _writer.WriteNumber("sequenceNumber", packet.Header.SequenceNumber);
        _writer.WriteNumber("sourceId", packet.Header.SourceId);

        // FlowSets
        _writer.WriteStartArray("flowSets");
        WriteFlowSets(packet);
        _writer.WriteEndArray();

        _writer.WriteEndObject();

        // Flush every 100 packets to keep memory bounded
        if (_packetCount % 100 == 0)
        {
            _writer.Flush();
        }
    }
```

The `in` keyword on `in NetFlowPacket packet` passes the parameter by readonly reference — no copying the object.

**The periodic flush** (`_packetCount % 100 == 0`) is important: `Utf8JsonWriter` buffers its output internally. Without periodic flushes, the buffer would grow indefinitely. Flushing every 100 packets keeps the buffer bounded while avoiding the overhead of flushing after every single packet.

**Phase 3: Write FlowSets (templates and data records)**

```csharp
    private void WriteFlowSets(in NetFlowPacket packet)
    {
        // Template flowset (flowSetId = 0)
        if (packet.Templates.Count > 0)
        {
            _writer.WriteStartObject();
            _writer.WriteNumber("flowSetId", 0);

            var totalLength = 0;
            foreach (var t in packet.Templates)
                totalLength += 4 + 4 + t.Fields.Count * 4;
            _writer.WriteNumber("length", totalLength);

            _writer.WriteStartArray("templates");
            foreach (var template in packet.Templates)
            {
                _writer.WriteStartObject();
                _writer.WriteNumber("templateId", template.TemplateId);

                _writer.WriteStartArray("fields");
                foreach (var field in template.Fields)
                {
                    _writer.WriteStartObject();
                    _writer.WriteNumber("type", field.Type);
                    _writer.WriteNumber("length", field.Length);
                    _writer.WriteEndObject();
                }
                _writer.WriteEndArray();
                _writer.WriteEndObject();
            }
            _writer.WriteEndArray();
            _writer.WriteEndObject();
        }

        // Data flowsets grouped by template ID
        var groupStart = 0;
        while (groupStart < packet.DataRecords.Count)
        {
            var templateId = packet.DataRecords[groupStart].TemplateId;
            var groupEnd = groupStart + 1;

            while (groupEnd < packet.DataRecords.Count
                && packet.DataRecords[groupEnd].TemplateId == templateId)
                groupEnd++;

            _writer.WriteStartObject();
            _writer.WriteNumber("flowSetId", templateId);

            _writer.WriteStartArray("records");
            for (var i = groupStart; i < groupEnd; i++)
            {
                _writer.WriteStartObject();
                foreach (var kvp in packet.DataRecords[i].Values)
                    _writer.WriteString(kvp.Key, kvp.Value?.ToString() ?? string.Empty);
                _writer.WriteEndObject();
            }
            _writer.WriteEndArray();
            _writer.WriteEndObject();

            groupStart = groupEnd;
        }
    }
```

Data records are grouped by template ID — all records from template 256 appear in one FlowSet block, then all records from template 257, and so on. This matches the wire format structure.

**Phase 4: Close the document**

```csharp
    public void EndExport()
    {
        if (_writer is null) return;

        _writer.WriteEndArray();  // close "packets" array

        // Write all cached templates
        WriteTemplatesFromCache();

        _writer.WriteEndObject();  // close root object
        _writer.Flush();
    }

    private void WriteTemplatesFromCache()
    {
        var allTemplates = _templateCache.GetAllTemplates();

        _writer!.WriteStartObject("templates");

        foreach (var (sourceId, templates) in allTemplates)
        {
            _writer.WriteStartObject(sourceId.ToString());

            foreach (var (templateId, template) in templates)
            {
                _writer.WriteStartObject(templateId.ToString());
                _writer.WriteNumber("TemplateId", template.TemplateId);

                _writer.WriteStartArray("Fields");
                foreach (var field in template.Fields)
                {
                    _writer.WriteStartObject();
                    _writer.WriteNumber("Type", field.Type);
                    _writer.WriteNumber("Length", field.Length);
                    _writer.WriteEndObject();
                }
                _writer.WriteEndArray();
                _writer.WriteEndObject();
            }
            _writer.WriteEndObject();
        }

        _writer.WriteEndObject();
    }

    public void Dispose()
    {
        _writer?.Dispose();
        _fileStream?.Dispose();
    }
```

Templates are written at the end because they accumulate over the lifetime of the PCAP processing (via the `ITemplateCache`). This is the one piece of state that grows — but templates are small (typically a few KB total, regardless of how many packets were processed).

### 12.3 The Output JSON Structure

```json
{
  "version": 9,
  "exportTime": "2025-04-13T07:38:00Z",
  "packets": [
    {
      "version": 9,
      "count": 2,
      "sysUptime": 12345678,
      "unixSecs": 1681234567,
      "sequenceNumber": 1,
      "sourceId": 171,
      "flowSets": [
        {
          "flowSetId": 0,
          "length": 48,
          "templates": [
            {
              "templateId": 256,
              "fields": [
                { "type": 8, "length": 4 },
                { "type": 12, "length": 4 }
              ]
            }
          ]
        },
        {
          "flowSetId": 256,
          "records": [
            { "8": "192.168.1.100", "12": "10.0.0.1" }
          ]
        }
      ]
    }
  ],
  "templates": {
    "171": {
      "256": {
        "TemplateId": 256,
        "Fields": [
          { "Type": 8, "Length": 4 },
          { "Type": 12, "Length": 4 }
        ]
      }
    }
  }
}
```

### 12.4 Why Utf8JsonWriter Instead of JsonSerializer

| Feature | `JsonSerializer.Serialize` | `Utf8JsonWriter` |
|---------|--------------------------|-------------------|
| Memory model | Builds entire document in memory | Streams token by token |
| Memory usage | O(N) — proportional to data size | O(1) — bounded buffer |
| Encoding | Serializes to UTF-16 string, then writes | Writes UTF-8 directly to stream |
| Flexibility | Needs a complete object tree | Can write incrementally (begin/write/end) |
| Performance | Reflects over types, creates intermediate strings | Direct byte writes, no reflection |

`Utf8JsonWriter` writes **UTF-8 bytes directly** to the underlying stream. It never creates a `string` in memory. For large outputs, this saves both memory (no UTF-16 string) and CPU (no encoding conversion).

### Summary

- `JsonSerializer.Serialize` builds the entire JSON document as a `string` in memory — O(N) memory
- `Utf8JsonWriter` writes JSON token by token directly to a `FileStream` — O(1) memory
- Use a 64 KB `FileStream` buffer to batch disk writes efficiently
- Flush `Utf8JsonWriter` periodically (every 100 packets) to keep its internal buffer bounded
- Write templates at the end from the cache — they are the only accumulated state
- The `in` keyword passes `NetFlowPacket` by readonly reference, avoiding copies

---

<a name="chapter-13"></a>
## Chapter 13. The Complete High-Performance Pipeline (Program.cs Integration)

### 13.1 Bringing It All Together

We have built four components:
1. **NetFlowV9Parser** — zero-alloc binary parser (Chapter 10)
2. **TemplateCache** — thread-safe template storage (Chapter 9)
3. **NetFlowPcapReader** — streaming PCAP reader (Chapter 3)
4. **NetFlowJsonExporter** — streaming JSON writer (Chapter 12)

Now we wire them together in `Program.cs` — the composition root.

### 13.2 The Complete Program.cs

Here is the full entry point from `NetFlowAnalizer.Console/Program.cs`:

```csharp
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core;
using NetFlowAnalizer.Core.Services;
using NetFlowAnalizer.Infrastructure.Export;
using NetFlowAnalizer.Infrastructure.Parsers;
using NetFlowAnalizer.Infrastructure.Readers;
using NetFlowAnalizer.Infrastructure.Services;

// --- Argument validation ---
if (args.Length < 1)
{
    Console.WriteLine("NetFlow Analyzer v9 (High-Performance Edition)");
    Console.WriteLine();
    Console.WriteLine("Usage: NetFlowAnalizer.Console <pcapFilePath>");
    Console.WriteLine();
    Console.WriteLine("Features:");
    Console.WriteLine("  - Zero-copy parsing via Span<byte> + BinaryPrimitives");
    Console.WriteLine("  - Streaming JSON export via Utf8JsonWriter");
    Console.WriteLine("  - O(1) memory — handles multi-GB PCAP files");
    return 1;
}

string pcapFilePath = args[0];

if (!File.Exists(pcapFilePath))
{
    Console.WriteLine($"Error: File not found: {pcapFilePath}");
    return 1;
}

string jsonOutputPath = Path.ChangeExtension(pcapFilePath, ".json");

// --- DI container setup ---
using var host = CreateHostBuilder(args).Build();

var logger = host.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("=== NetFlow Analyzer v9 (High-Performance) ===");
logger.LogInformation("Input PCAP: {PcapPath}", pcapFilePath);
logger.LogInformation("Output JSON: {JsonPath}", jsonOutputPath);

try
{
    var reader   = host.Services.GetRequiredService<NetFlowPcapReader>();
    var exporter = host.Services.GetRequiredService<NetFlowJsonExporter>();

    // --- THE STREAMING PIPELINE ---
    //
    // 1. Open JSON file, write preamble
    // 2. For each PCAP packet:
    //      parse(Span) → NetFlowPacket → Utf8JsonWriter → flush → GC
    // 3. Write templates + close JSON
    //
    // Memory usage: ~50 MB regardless of PCAP size.

    exporter.BeginExport(jsonOutputPath);

    reader.Process(pcapFilePath, packet =>
    {
        exporter.WritePacket(in packet);
    });

    exporter.EndExport();

    // --- Print summary ---
    logger.LogInformation("");
    logger.LogInformation("=== RESULTS ===");
    logger.LogInformation("Total packets scanned: {Total}", reader.TotalPackets);
    logger.LogInformation("NetFlow v9 packets:    {NetFlow}", reader.NetFlowPackets);
    logger.LogInformation("Templates found:       {Templates}", reader.TotalTemplates);
    logger.LogInformation("Flow records:          {Flows}", reader.TotalFlows);
    logger.LogInformation("");
    logger.LogInformation("=== SUCCESS ===");
    logger.LogInformation("Results saved to: {JsonPath}", jsonOutputPath);

    return 0;
}
catch (Exception ex)
{
    logger.LogError(ex, "Error processing NetFlow data");
    return 1;
}
finally
{
    var exporter = host.Services.GetService<NetFlowJsonExporter>();
    exporter?.Dispose();
}

// --- DI configuration ---
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

### 13.3 The Pipeline in Detail

The three critical lines are:

```csharp
exporter.BeginExport(jsonOutputPath);            // Phase 1: Open file
reader.Process(pcapFilePath, packet =>            // Phase 2: Stream
{
    exporter.WritePacket(in packet);
});
exporter.EndExport();                             // Phase 3: Close file
```

Here is the data flow for a single packet:

```
                        Time →

PCAP file  ──read──►  SharpPcap  ──extract UDP──►  payload (byte[])
                                                        │
                                                   .AsSpan()
                                                        │
                                                        ▼
                                                  ReadOnlySpan<byte>
                                                        │
                                               ParsePacket(span)
                                                        │
                                                        ▼
                                                  NetFlowPacket
                                                  (on the heap,
                                                   one instance)
                                                        │
                                              onPacket(packet)
                                                        │
                                                        ▼
                                              Utf8JsonWriter
                                              writes JSON tokens
                                              to 64 KB buffer
                                                        │
                                              (every 100 packets)
                                                        │
                                                  Flush to disk
                                                        │
                                              packet goes out
                                              of scope → GC
```

At no point does more than one packet exist in memory. The 64 KB write buffer is the only long-lived allocation.

### 13.4 DI Container Walkthrough

```csharp
services.AddSingleton<ITemplateCache, TemplateCache>();
```
One `TemplateCache` instance for the entire application. The parser writes to it; the JSON exporter reads from it at the end.

```csharp
services.AddSingleton<INetFlowParser, NetFlowV9Parser>();
```
One parser instance. It is stateless (all state is in the `ITemplateCache`), so singleton is correct.

```csharp
services.AddSingleton<NetFlowPcapReader>();
```
The reader gets `INetFlowParser` injected. It calls `_parser.ParsePacket()` for each UDP payload.

```csharp
services.AddSingleton<NetFlowJsonExporter>();
```
The exporter gets `ITemplateCache` injected. It reads all templates at the end for the `"templates"` section of the JSON.

**The dependency graph:**

```
Program.cs
    │
    ├── NetFlowPcapReader
    │       └── INetFlowParser → NetFlowV9Parser
    │                                └── ITemplateCache → TemplateCache
    │
    └── NetFlowJsonExporter
            └── ITemplateCache → TemplateCache  (same instance!)
```

Both `NetFlowV9Parser` and `NetFlowJsonExporter` share the **same** `TemplateCache` instance (because it is registered as a Singleton). The parser adds templates; the exporter reads them. They never need to communicate directly.

### 13.5 Error Handling and Resource Cleanup

```csharp
try
{
    // ... pipeline ...
    return 0;
}
catch (Exception ex)
{
    logger.LogError(ex, "Error processing NetFlow data");
    return 1;
}
finally
{
    var exporter = host.Services.GetService<NetFlowJsonExporter>();
    exporter?.Dispose();
}
```

The `finally` block ensures the `FileStream` and `Utf8JsonWriter` are disposed even if an exception occurs. Without this, the output JSON file could be left open (locked) or partially written without proper closing brackets.

### 13.6 Comparison: Legacy vs. High-Performance Pipeline

**❌ Legacy pipeline (NetFlowAnalizer/Program.cs):**

```csharp
NetFlowPcapReader reader = new NetFlowPcapReader();  // no DI
reader.Read(pcapFilePath);                            // accumulates ALL packets
reader.ExportToJson(jsonOutputPath);                  // serializes ALL at once
```

| Aspect | Legacy | Our Version |
|--------|--------|------------|
| Memory model | O(N) — all packets in memory | O(1) — one packet at a time |
| JSON serialization | `JsonSerializer.Serialize` (full string in memory) | `Utf8JsonWriter` (streaming to disk) |
| DI | None — static classes | `IHost` + `IServiceProvider` |
| Logging | `Console.WriteLine` | `ILogger<T>` with structured logging |
| Error handling | None | `try/catch/finally` with proper disposal |
| Testability | Impossible (static everything) | Full (interfaces + DI) |
| Exit codes | None (void Main) | `return 0` (success) / `return 1` (failure) |

### 13.7 Running the Application

```bash
dotnet run --project NetFlowAnalizer.Console -- capture.pcap
```

Output:

```
info: Program[0]
      === NetFlow Analyzer v9 (High-Performance) ===
info: Program[0]
      Input PCAP: capture.pcap
info: Program[0]
      Output JSON: capture.json
info: NetFlowPcapReader[0]
      Opening PCAP: capture.pcap
info: NetFlowPcapReader[0]
      PCAP done: 4215 packets, 731 NetFlow, 12 templates, 2847 flows
info: Program[0]
      === RESULTS ===
info: Program[0]
      Total packets scanned: 4215
info: Program[0]
      NetFlow v9 packets:    731
info: Program[0]
      Templates found:       12
info: Program[0]
      Flow records:          2847
info: Program[0]
      === SUCCESS ===
info: Program[0]
      Results saved to: capture.json
```

### Summary

- `Program.cs` is the composition root — the only place where concrete types are mentioned
- The streaming pipeline is three lines: `BeginExport` → `Process(callback)` → `EndExport`
- All four components share state through the DI container (the `ITemplateCache` singleton)
- The `finally` block ensures file handles are released even on exceptions
- The legacy pipeline was O(N) memory with no DI, no logging, and no error handling
- Our pipeline is O(1) memory with full DI, structured logging, and proper resource cleanup

---

> **End of Part IV.** You now have a complete, production-grade NetFlow v9 analyzer. In Part V, we will cover testing strategies and performance benchmarking to ensure the code is correct and fast.

