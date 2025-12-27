# NetFlow Analyzer v9

NetFlow v9 packet analyzer with PCAP parsing and web-based visualization.

## Features

- ✅ Full NetFlow v9 parsing (RFC 3954 compliant)
- ✅ PCAP file support (Wireshark captures)
- ✅ Template FlowSet parsing and caching
- ✅ Data FlowSet parsing with 26+ field types
- ✅ JSON export for visualization
- ✅ Clean Architecture (Core/Infrastructure/Console layers)
- ✅ Dependency Injection
- ✅ Structured logging
- ✅ Type-safe error handling with Result<T> pattern

## Architecture

```
NetFlowAnalizer/
├── NetFlowAnalizer.Core/          # Business logic & interfaces
│   ├── Models/                    # Value objects & entities
│   ├── Services/                  # Service interfaces
│   └── Common/                    # Result<T> pattern
├── NetFlowAnalizer.Infrastructure/# Implementation
│   ├── Parsers/                   # NetFlow v9 parser
│   ├── Readers/                   # PCAP reader
│   ├── Services/                  # Template cache
│   ├── Export/                    # JSON exporter
│   └── Common/                    # Utilities
└── NetFlowAnalizer.Console/       # CLI application
```

## Requirements

- .NET 8.0 SDK
- Wireshark (for capturing NetFlow traffic)
- Network device with NetFlow v9 support (e.g., MikroTik)

## Quick Start

### 1. Capture NetFlow Traffic

**On MikroTik router:**
```
IP → Traffic Flow
- Enable NetFlow v9
- Set collector IP address
- Set port: 2055
```

**On collector machine:**
```bash
# Capture UDP traffic on port 2055 using Wireshark
# Save capture as netflow_data.pcap
```

### 2. Build the Project

```bash
cd NetFlowAnalizer
dotnet restore
dotnet build
```

### 3. Parse PCAP File

```bash
dotnet run --project NetFlowAnalizer.Console/NetFlowAnalizer.Console.csproj /path/to/netflow_data.pcap
```

**Example:**
```bash
dotnet run --project NetFlowAnalizer.Console/NetFlowAnalizer.Console.csproj ../pcapfiles/sample.pcap
```

This will:
1. Parse NetFlow v9 packets from the PCAP file
2. Extract headers, templates, and flow records
3. Export results to `sample.json` (same directory as PCAP)

### 4. Visualize Results

Open `view/index.html` in your browser and load the generated JSON file.

The dashboard shows:
- Traffic summary statistics
- Traffic by IP address
- Traffic by port
- Protocol distribution
- Traffic over time
- Detailed flow records
- Template definitions

## Supported NetFlow Fields

The parser supports 26+ field types including:

| Field Type | Name | Description |
|------------|------|-------------|
| 1 | Bytes | Bytes in flow |
| 2 | Packets | Packets in flow |
| 4 | Protocol | IP protocol (TCP=6, UDP=17) |
| 7 | Src Port | Source port |
| 8 | Src IP | Source IPv4 address |
| 11 | Dst Port | Destination port |
| 12 | Dst IP | Destination IPv4 address |
| 80 | Flow Start (Unix) | Flow start time (Unix timestamp) |
| 81 | Flow End (Unix) | Flow end time (Unix timestamp) |
| 225 | Post-NAT Src IP | Source IP after NAT |
| 226 | Post-NAT Dst IP | Destination IP after NAT |

...and 15+ more fields (see NetFlowFields.cs for full list)

## Development

### Project Structure

**Core Layer:**
- `INetFlowParser` - Parser interface
- `INetFlowRepository` - Repository pattern (future)
- `ITemplateCache` - Template caching interface
- `Result<T>` - Functional error handling
- `NetFlowV9Header` - RFC 3954 compliant header model

**Infrastructure Layer:**
- `NetFlowV9Parser` - Full parser implementation
- `NetFlowPcapReader` - PCAP file reader with UDP:2055 filtering
- `TemplateCache` - Thread-safe in-memory cache
- `NetFlowJsonExporter` - JSON export functionality
- `ByteUtils` - Big-endian conversion utilities
- `NetFlowFields` - Field type definitions

**Console Layer:**
- Command-line interface
- Dependency injection setup
- Structured logging configuration

### Adding Support for Other NetFlow Versions

```csharp
// 1. Create new parser class
public class NetFlowV5Parser : INetFlowParser
{
    public int SupportedVersion => 5;
    // Implement CanParse and ParseAsync
}

// 2. Register in DI container
services.AddSingleton<INetFlowParser, NetFlowV5Parser>();
```

### Running Tests

```bash
# TODO: Add unit tests
dotnet test
```

## Example Output

```
=== NetFlow Analyzer v9 ===
Input PCAP: ../pcapfiles/netflow_data.pcap
Output JSON: ../pcapfiles/netflow_data.json
Using NetFlow Parser v9
Starting PCAP processing...
PCAP file opened successfully. Starting packet capture...

=== Parsing Results ===
Total records: 1523
  Headers: 156
  Templates: 12
  Data records (flows): 1355

=== Sample Headers ===
  NetFlow v9: Count=8, Seq=1234, source=171, Time=2024-11-05 14:23:45

=== Templates ===
  Template ID: 256, Fields: 18, Record Length: 68 bytes
  Template ID: 257, Fields: 12, Record Length: 44 bytes

=== Sample Flow Records ===
  Flow (Template 256):
    Src IP: 192.168.1.100
    Dst IP: 8.8.8.8
    Src Port: 54321
    Dst Port: 443
    Protocol: 6
    Bytes: 15420
    Packets: 12

=== SUCCESS ===
Results saved to: ../pcapfiles/netflow_data.json
```

## Troubleshooting

**"No template found" warning:**
- Templates must be received before data records
- Capture NetFlow traffic from the beginning
- Ensure template refresh interval is set on your router

**Empty data records:**
- Check if PCAP contains UDP port 2055 traffic
- Verify NetFlow version is 9 (not v5 or v10)
- Use Wireshark filter: `udp.port == 2055`

**Build errors:**
- Ensure .NET 8.0 SDK is installed: `dotnet --version`
- Run `dotnet restore` before building

## Contributing

Contributions are welcome! Areas for improvement:
- [ ] Add unit tests (xUnit)
- [ ] Add integration tests
- [ ] Implement INetFlowRepository (database storage)
- [ ] Add support for NetFlow v5
- [ ] Add support for IPFIX (NetFlow v10)
- [ ] Add real-time capture (not just PCAP files)
- [ ] Add performance benchmarks
- [ ] Add Docker support

## License

MIT License

## References

- [RFC 3954 - NetFlow v9](https://www.rfc-editor.org/rfc/rfc3954)
- [Cisco NetFlow Documentation](https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-netflow/index.html)
