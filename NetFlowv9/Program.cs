using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetFlowParserApp;

public static class Program
{
    public static async Task Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: NetFlowParserApp <pcapFilePath>");
            return;
        }

        string pcapFilePath = args[0];
        if (!File.Exists(pcapFilePath))
        {
            Console.WriteLine($"Error: The file at '{pcapFilePath}' does not exist.");
            return;
        }

        string jsonOutputPath = Path.ChangeExtension(pcapFilePath, ".json");

        NetFlowPcapReader reader = new NetFlowPcapReader();
        reader.Read(pcapFilePath);

        // After parsing is complete, export to JSON
        reader.ExportToJson(jsonOutputPath);
    }
}

// Core NetFlow packet structure
public class NetFlowPacket
{
    public ushort Version { get; set; }
    public ushort Count { get; set; }
    public uint SysUptime { get; set; }
    public uint UnixSecs { get; set; }
    public uint SequenceNumber { get; set; }
    public uint SourceId { get; set; }
}

public class DataRecord
{
    public ushort TemplateId { get; set; }
    public Dictionary<string, object> Values { get; set; } = new();
}

// FlowSet structures
public class FlowSetHeader
{
    public ushort FlowSetId { get; set; }
    public ushort Length { get; set; }
}

public class TemplateField
{
    public ushort Type { get; set; }
    public ushort Length { get; set; }
}

public class TemplateRecord
{
    public ushort TemplateId { get; set; }
    public List<TemplateField> Fields { get; set; } = new List<TemplateField>();
}

// Capture tracking structures
public class CapturedPacket
{
    public NetFlowPacket Header { get; set; }
    public List<ParsedFlowSet> FlowSets { get; set; } = new List<ParsedFlowSet>();
}

public class ParsedFlowSet
{
    public FlowSetHeader Header { get; set; }
    public ushort FlowSetId => Header.FlowSetId;
    public List<TemplateRecord> TemplateRecords { get; set; } = new List<TemplateRecord>();
    public List<DataRecord> DataRecords { get; set; } = new List<DataRecord>();
}

// JSON export structures
public class TemplateInfo
{
    public ushort TemplateId { get; set; }
    public List<FieldInfo> Fields { get; set; } = new List<FieldInfo>();
}

public class FieldInfo
{
    public ushort Type { get; set; }
    public ushort Length { get; set; }
}

// Main parser class
public static class NetFlowParser
{
    public static NetFlowPacket ParseHeader(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes);
        using var br = new BinaryReader(ms);

        var packet = new NetFlowPacket
        {
            Version = ReadUInt16BigEndian(br),
            Count = ReadUInt16BigEndian(br),
            SysUptime = ReadUInt32BigEndian(br),
            UnixSecs = ReadUInt32BigEndian(br),
            SequenceNumber = ReadUInt32BigEndian(br),
            SourceId = ReadUInt32BigEndian(br)
        };

        return packet;
    }

    public static List<TemplateRecord> ParseTemplateFlowSet(byte[] flowSetContent)
    {
        var templates = new List<TemplateRecord>();

        using var ms = new MemoryStream(flowSetContent);
        using var br = new BinaryReader(ms);

        while (ms.Position < ms.Length)
        {
            var templateId = ReadUInt16BigEndian(br);
            var fieldCount = ReadUInt16BigEndian(br);

            var template = new TemplateRecord
            {
                TemplateId = templateId
            };

            for (int i = 0; i < fieldCount; i++)
            {
                var fieldType = ReadUInt16BigEndian(br);
                var fieldLength = ReadUInt16BigEndian(br);

                template.Fields.Add(new TemplateField
                {
                    Type = fieldType,
                    Length = fieldLength
                });
            }

            templates.Add(template);
        }

        return templates;
    }

    public static FlowSetHeader ParseFlowSetHeader(BinaryReader br)
    {
        return new FlowSetHeader
        {
            FlowSetId = ReadUInt16BigEndian(br),
            Length = ReadUInt16BigEndian(br)
        };
    }

    private static ushort ReadUInt16BigEndian(BinaryReader br)
    {
        var bytes = br.ReadBytes(2);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        return BitConverter.ToUInt16(bytes, 0);
    }

    private static uint ReadUInt32BigEndian(BinaryReader br)
    {
        var bytes = br.ReadBytes(4);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        return BitConverter.ToUInt32(bytes, 0);
    }
}

// Template cache with JSON export support
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

    public static Dictionary<string, Dictionary<string, TemplateInfo>> GetAllTemplates()
    {
        var result = new Dictionary<string, Dictionary<string, TemplateInfo>>();

        foreach (var sourceEntry in cache)
        {
            var sourceId = sourceEntry.Key.ToString();
            result[sourceId] = new Dictionary<string, TemplateInfo>();

            foreach (var templateEntry in sourceEntry.Value)
            {
                var templateId = templateEntry.Key.ToString();
                var template = templateEntry.Value;

                result[sourceId][templateId] = new TemplateInfo
                {
                    TemplateId = template.TemplateId,
                    Fields = template.Fields.Select(f => new FieldInfo
                    {
                        Type = f.Type,
                        Length = f.Length
                    }).ToList()
                };
            }
        }

        return result;
    }
}

// Capture summary for export
public static class CaptureSummary
{
    public static List<CapturedPacket> Packets { get; } = new List<CapturedPacket>();

    public static void AddPacket(NetFlowPacket header, List<ParsedFlowSet> flowSets)
    {
        Packets.Add(new CapturedPacket
        {
            Header = header,
            FlowSets = flowSets
        });
    }
}

// JSON export functionality
public static class NetFlowJsonExporter
{
    public static void ExportToJson(string outputPath)
    {
        var dashboardData = new
        {
            version = 9,
            exportTime = DateTime.UtcNow,
            packets = CaptureSummary.Packets.Select(p => new
            {
                version = p.Header.Version,
                count = p.Header.Count,
                sysUptime = p.Header.SysUptime,
                unixSecs = p.Header.UnixSecs,
                sequenceNumber = p.Header.SequenceNumber,
                sourceId = p.Header.SourceId,
                flowSets = p.FlowSets.Select(fs => new
                {
                    flowSetId = fs.Header.FlowSetId,
                    length = fs.Header.Length,
                    templates = fs.FlowSetId == 0 ? fs.TemplateRecords?.Select(t => new
                    {
                        templateId = t.TemplateId,
                        fields = t.Fields.Select(f => new
                        {
                            type = f.Type,
                            length = f.Length
                        }).ToArray()
                    }).ToArray() : null,
                    records = fs.FlowSetId >= 256 ? fs.DataRecords?.Select(r => ConvertDataRecord(r)).ToArray() : null
                }).ToArray()
            }).ToArray(),
            templates = TemplateCache.GetAllTemplates()
        };

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        string json = JsonSerializer.Serialize(dashboardData, options);
        File.WriteAllText(outputPath, json);

        Console.WriteLine($"Exported NetFlow data to {outputPath}");
    }

    private static Dictionary<string, object> ConvertDataRecord(DataRecord record)
    {
        var result = new Dictionary<string, object>();

        foreach (var kvp in record.Values)
        {
            result[kvp.Key] = kvp.Value;
        }

        return result;
    }
}

// Main PCAP reader with integrated export
public class NetFlowPcapReader
{
    public void Read(string pcapFile)
    {
        var device = new CaptureFileReaderDevice(pcapFile);
        device.Open();

        device.OnPacketArrival += Device_OnPacketArrival;
        device.Capture();

        device.Close();
    }

    private void Device_OnPacketArrival(object sender, PacketCapture e)
    {
        var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);

        var udpPacket = packet.Extract<UdpPacket>();
        if (udpPacket == null || udpPacket.DestinationPort != 2055)
            return;

        var payload = udpPacket.PayloadData;
        if (payload == null || payload.Length < 20)
            return;

        var header = NetFlowParser.ParseHeader(payload);
        if (header.Version != 9)
        {
            Console.WriteLine($"Пропущен пакет с неподдерживаемой версией {header.Version}");
            return;
        }

        Console.WriteLine($"NetFlow v9: Count={header.Count}, Seq={header.SequenceNumber}, SourceId={header.SourceId}");

        var parsedFlowSets = new List<ParsedFlowSet>();

        using var ms = new MemoryStream(payload, 20, payload.Length - 20);
        using var br = new BinaryReader(ms);

        while (ms.Position < ms.Length)
        {
            var flowSetHeader = NetFlowParser.ParseFlowSetHeader(br);

            if (flowSetHeader.Length < 4)
            {
                Console.WriteLine($"Некорректная длина FlowSet: {flowSetHeader.Length}");
                break;
            }

            Console.WriteLine($"  FlowSet ID: {flowSetHeader.FlowSetId}, Length: {flowSetHeader.Length}");

            var flowSetContent = br.ReadBytes(flowSetHeader.Length - 4);
            var parsedFlowSet = new ParsedFlowSet { Header = flowSetHeader };

            if (flowSetHeader.FlowSetId == 0)
            {
                Console.WriteLine("    -> Это Template FlowSet");
                var templates = NetFlowParser.ParseTemplateFlowSet(flowSetContent);
                parsedFlowSet.TemplateRecords.AddRange(templates);

                foreach (var template in templates)
                {
                    TemplateCache.AddTemplate(header.SourceId, template);
                    Console.WriteLine($"      TemplateID: {template.TemplateId}, Полей: {template.Fields.Count}");
                    foreach (var field in template.Fields)
                    {
                        Console.WriteLine($"        FieldType: {field.Type}, Length: {field.Length}");
                    }
                }
            }
            else if (flowSetHeader.FlowSetId >= 256)
            {
                Console.WriteLine("    -> Это Data FlowSet");

                var template = TemplateCache.GetTemplate(header.SourceId, flowSetHeader.FlowSetId);
                if (template == null)
                {
                    Console.WriteLine($"      ❌ Нет шаблона для TemplateId {flowSetHeader.FlowSetId}");
                    continue;
                }

                var records = ParseDataFlowSet(flowSetContent, template);
                foreach (var record in records)
                {
                    var dataRecord = new DataRecord
                    {
                        TemplateId = flowSetHeader.FlowSetId
                    };

                    Console.WriteLine("      ✔ Flow Record:");
                    foreach (var kvp in record)
                    {
                        string fieldName = NetFlowFields.FieldNames.TryGetValue(kvp.Key, out var name) ? name : $"Field {kvp.Key}";
                        string value = FormatField(kvp.Key, kvp.Value);
                        dataRecord.Values[kvp.Key.ToString()] = value;
                        Console.WriteLine($"  {fieldName}: {value}");
                    }

                    parsedFlowSet.DataRecords.Add(dataRecord);
                }
            }

            parsedFlowSets.Add(parsedFlowSet);
        }

        CaptureSummary.AddPacket(header, parsedFlowSets);
    }

    public static string FormatField(ushort fieldType, byte[] data)
    {
        try
        {
            switch (fieldType)
            {
                case 4:  // Protocol (1 byte)
                case 5:  // TOS (1 byte)
                case 6:  // TCP Flags (1 byte)
                    return data.Length == 1 ? data[0].ToString() : $"[Invalid length: {data.Length}]";

                case 8:  // Src IP
                case 12: // Dst IP
                case 15:
                case 225:
                case 226:
                    return ByteUtils.ToIpAddress(data);

                case 7:  // Src Port
                case 11: // Dst Port
                case 227:
                case 228:
                    return ByteUtils.ToUInt16Safe(data).ToString();

                case 1:  // Bytes
                case 2:  // Packets
                case 10: // Input IF
                case 14: // Output IF
                case 34: // Start Time
                case 35: // End Time
                    return ByteUtils.ToUInt32Safe(data).ToString();

                case 80: // Unix Start
                case 81: // Unix End
                    return DateTimeOffset.FromUnixTimeMilliseconds((long)ByteUtils.ToUInt64Safe(data)).ToString();

                default:
                    return BitConverter.ToString(data);
            }
        }
        catch (Exception ex)
        {
            return $"[Error: {ex.Message}]";
        }
    }

    public static List<Dictionary<ushort, byte[]>> ParseDataFlowSet(byte[] data, TemplateRecord template)
    {
        var result = new List<Dictionary<ushort, byte[]>>();

        using var ms = new MemoryStream(data);
        using var br = new BinaryReader(ms);

        int recordLength = template.Fields.Sum(f => f.Length);

        while (ms.Position + recordLength <= ms.Length)
        {
            var record = new Dictionary<ushort, byte[]>();
            foreach (var field in template.Fields)
            {
                var bytes = br.ReadBytes(field.Length);
                record[field.Type] = bytes;
            }

            result.Add(record);
        }

        return result;
    }

    public void ExportToJson(string outputPath)
    {
        NetFlowJsonExporter.ExportToJson(outputPath);
    }
}

// NetFlow field definitions
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
        { 9, "Src Mask" },
        { 10, "Input IF" },
        { 11, "Dst Port" },
        { 12, "Dst IP" },
        { 13, "Dst Mask" },
        { 14, "Output IF" },
        { 15, "Next Hop" },
        { 21, "Src MAC" },
        { 22, "Dst MAC" },
        { 34, "Start Time" },
        { 35, "End Time" },
        { 56, "Flow Start (SysUptime)" },
        { 57, "Flow End (SysUptime)" },
        { 80, "Flow Start (Unix)" },
        { 81, "Flow End (Unix)" },
        { 225, "Post-NAT Src IP" },
        { 226, "Post-NAT Dst IP" },
        { 227, "Post-NAT Src Port" },
        { 228, "Post-NAT Dst Port" }
    };
}

// Utility functions for byte conversion
public static class ByteUtils
{
    public static ushort ToUInt16Safe(byte[] data)
    {
        if (data.Length != 2)
            throw new ArgumentException($"Expected 2 bytes, got {data.Length}");
        return BitConverter.ToUInt16(ToLittleEndian(data), 0);
    }

    public static uint ToUInt32Safe(byte[] data)
    {
        if (data.Length != 4)
            throw new ArgumentException($"Expected 4 bytes, got {data.Length}");
        return BitConverter.ToUInt32(ToLittleEndian(data), 0);
    }

    public static ulong ToUInt64Safe(byte[] data)
    {
        if (data.Length != 8)
            throw new ArgumentException($"Expected 8 bytes, got {data.Length}");
        return BitConverter.ToUInt64(ToLittleEndian(data), 0);
    }

    public static string ToIpAddress(byte[] data)
    {
        if (data.Length != 4)
            throw new ArgumentException($"Expected 4 bytes for IPv4, got {data.Length}");
        return new IPAddress(data).ToString();
    }

    private static byte[] ToLittleEndian(byte[] data)
    {
        if (BitConverter.IsLittleEndian)
        {
            var copy = (byte[])data.Clone();
            Array.Reverse(copy);
            return copy;
        }
        return data;
    }
}