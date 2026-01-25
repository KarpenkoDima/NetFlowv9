using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core;
using NetFlowAnalizer.Core.Models;
using NetFlowAnalizer.Core.Services;
using NetFlowAnalizer.Infrastructure.Common;

namespace NetFlowAnalizer.Infrastructure.Parsers;

/// <summary>
/// Full NetFlow v9 parser implementation (RFC 3954)
/// </summary>
public class NetFlowV9Parser : INetFlowParser
{
    private readonly ILogger<NetFlowV9Parser> _logger;
    private readonly ITemplateCache _templateCache;

    public NetFlowV9Parser(ILogger<NetFlowV9Parser> logger, ITemplateCache templateCache)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _templateCache = templateCache ?? throw new ArgumentNullException(nameof(templateCache));
    }

    public int SupportedVersion => 9;

    public bool CanParse(ReadOnlySpan<byte> data)
    {
        _logger.LogDebug("Checking if data can be parsed as NetFlow v9");

        if (data.Length < NetFlowV9Header.HeaderSize)
        {
            _logger.LogDebug("Data too small: {Size} < {Required}", data.Length, NetFlowV9Header.HeaderSize);
            return false;
        }

        var version = (ushort)((data[0] << 8) | data[1]);
        var canParse = version == SupportedVersion;

        _logger.LogDebug("NetFlow version: {Version}, can parse: {CanParse}", version, canParse);
        return canParse;
    }

    public async Task<IEnumerable<INetFlowRecord>> ParseAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Starting NetFlow v9 parsing, data size: {DataSize} bytes", data.Length);

        try
        {
            await Task.CompletedTask; // Make it async-ready

            var records = new List<INetFlowRecord>();
            var span = data.Span;

            // Parse header
            var headerResult = ParseHeader(span);
            if (!headerResult.IsSuccess)
            {
                _logger.LogError("Failed to parse header: {Error}", headerResult.Error);
                return Array.Empty<INetFlowRecord>();
            }

            var header = headerResult.Value;
            records.Add(header);

            _logger.LogInformation("Parsed header: {Header}", header);

            // Parse FlowSets
            var flowSetData = span.Slice(NetFlowV9Header.HeaderSize);
            var flowSetRecords = ParseFlowSets(flowSetData, header.SourceId);
            records.AddRange(flowSetRecords);

            _logger.LogInformation("Parsing completed. Total records: {Count}", records.Count);
            return records;
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Parsing was cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during NetFlow parsing");
            return Array.Empty<INetFlowRecord>();
        }
    }

    private Result<NetFlowV9Header> ParseHeader(ReadOnlySpan<byte> data)
    {
        try
        {
            _logger.LogDebug("Parsing NetFlow v9 header from {Size} bytes", data.Length);

            var header = NetFlowV9Header.FromBytes(data);

            _logger.LogInformation("Successfully parsed header: {Header}", header);

            if (!header.IsValid)
            {
                var error = $"Invalid NetFlow header: Version={header.Version}, Count={header.Count}";
                _logger.LogError(error);
                return Result<NetFlowV9Header>.Failure(error);
            }

            return Result<NetFlowV9Header>.Success(header);
        }
        catch (ArgumentException ex)
        {
            var error = $"Failed to parse NetFlow header: {ex.Message}";
            _logger.LogError(ex, error);
            return Result<NetFlowV9Header>.Failure(error);
        }
        catch (Exception ex)
        {
            var error = $"Unexpected error parsing header: {ex.Message}";
            _logger.LogError(ex, error);
            return Result<NetFlowV9Header>.Failure(error);
        }
    }

    private List<INetFlowRecord> ParseFlowSets(ReadOnlySpan<byte> data, uint sourceId)
    {
        var records = new List<INetFlowRecord>();

        using var ms = new MemoryStream(data.ToArray());
        using var br = new BinaryReader(ms);

        while (ms.Position < ms.Length)
        {
            try
            {
                // Parse FlowSet header
                var flowSetHeader = ParseFlowSetHeader(br);

                if (flowSetHeader.Length < 4)
                {
                    _logger.LogWarning("Invalid FlowSet length: {Length}", flowSetHeader.Length);
                    break;
                }

                _logger.LogDebug("FlowSet ID: {Id}, Length: {Length}", flowSetHeader.FlowSetId, flowSetHeader.Length);

                // Read FlowSet content
                var contentLength = flowSetHeader.Length - 4; // Subtract header size
                var flowSetContent = br.ReadBytes(contentLength);

                // Parse based on FlowSet type
                if (flowSetHeader.IsTemplateFlowSet)
                {
                    _logger.LogDebug("Parsing Template FlowSet");
                    var templates = ParseTemplateFlowSet(flowSetContent, sourceId);
                    records.AddRange(templates);
                }
                else if (flowSetHeader.IsDataFlowSet)
                {
                    _logger.LogDebug("Parsing Data FlowSet with Template ID: {TemplateId}", flowSetHeader.FlowSetId);
                    var dataRecords = ParseDataFlowSet(flowSetContent, sourceId, flowSetHeader.FlowSetId);
                    records.AddRange(dataRecords);
                }
                else
                {
                    _logger.LogDebug("Skipping FlowSet ID: {Id} (Options Template or unknown)", flowSetHeader.FlowSetId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing FlowSet at position {Position}", ms.Position);
                break;
            }
        }

        return records;
    }

    private FlowSetHeader ParseFlowSetHeader(BinaryReader br)
    {
        return new FlowSetHeader
        {
            FlowSetId = ByteUtils.ReadUInt16BigEndian(br),
            Length = ByteUtils.ReadUInt16BigEndian(br)
        };
    }

    private List<TemplateRecord> ParseTemplateFlowSet(byte[] flowSetContent, uint sourceId)
    {
        var templates = new List<TemplateRecord>();

        using var ms = new MemoryStream(flowSetContent);
        using var br = new BinaryReader(ms);

        while (ms.Position < ms.Length)
        {
            try
            {
                var templateId = ByteUtils.ReadUInt16BigEndian(br);
                var fieldCount = ByteUtils.ReadUInt16BigEndian(br);

                var template = new TemplateRecord
                {
                    TemplateId = templateId
                };

                _logger.LogDebug("Template ID: {TemplateId}, Field Count: {FieldCount}", templateId, fieldCount);

                for (int i = 0; i < fieldCount; i++)
                {
                    var fieldType = ByteUtils.ReadUInt16BigEndian(br);
                    var fieldLength = ByteUtils.ReadUInt16BigEndian(br);

                    template.Fields.Add(new TemplateField
                    {
                        Type = fieldType,
                        Length = fieldLength
                    });

                    _logger.LogTrace("  Field {Index}: Type={Type}, Length={Length}", i, fieldType, fieldLength);
                }

                // Cache the template
                _templateCache.AddTemplate(sourceId, template);
                templates.Add(template);

                _logger.LogInformation("Cached template {TemplateId} for source {SourceId} with {FieldCount} fields",
                    templateId, sourceId, fieldCount);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing template at position {Position}", ms.Position);
                break;
            }
        }

        return templates;
    }

    private List<DataRecord> ParseDataFlowSet(byte[] flowSetContent, uint sourceId, ushort templateId)
    {
        var dataRecords = new List<DataRecord>();

        // Get template from cache
        var template = _templateCache.GetTemplate(sourceId, templateId);
        if (template == null)
        {
            _logger.LogWarning("No template found for Source ID: {SourceId}, Template ID: {TemplateId}", sourceId, templateId);
            return dataRecords;
        }

        using var ms = new MemoryStream(flowSetContent);
        using var br = new BinaryReader(ms);

        int recordLength = template.RecordLength;
        int recordIndex = 0;

        while (ms.Position + recordLength <= ms.Length)
        {
            try
            {
                var dataRecord = new DataRecord
                {
                    TemplateId = templateId
                };

                foreach (var field in template.Fields)
                {
                    var fieldData = br.ReadBytes(field.Length);
                    var formattedValue = FormatField(field.Type, fieldData);

                    // Use field type as key (dashboard expects numeric keys like "8", "12")
                    dataRecord.Values[field.Type.ToString()] = formattedValue;
                }

                dataRecords.Add(dataRecord);
                recordIndex++;

                _logger.LogTrace("Parsed data record {Index} with {FieldCount} fields", recordIndex, template.Fields.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing data record at position {Position}", ms.Position);
                break;
            }
        }

        _logger.LogDebug("Parsed {Count} data records for template {TemplateId}", dataRecords.Count, templateId);
        return dataRecords;
    }

    private string FormatField(ushort fieldType, byte[] data)
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
                case 15: // Next Hop
                case 225: // Post-NAT Src IP
                case 226: // Post-NAT Dst IP
                    return ByteUtils.ToIpAddress(data);

                case 7:  // Src Port
                case 11: // Dst Port
                case 227: // Post-NAT Src Port
                case 228: // Post-NAT Dst Port
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
                    // Flexible handling: template may define 6 or 8 bytes
                    return data.Length == 8
                        ? DateTimeOffset.FromUnixTimeMilliseconds((long)ByteUtils.ToUInt64Safe(data)).ToString("yyyy-MM-dd HH:mm:ss")
                        : BitConverter.ToString(data);

                default:
                    // For all other fields (MAC addresses, SysUptime, etc) - return hex
                    return BitConverter.ToString(data);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error formatting field {FieldType}", fieldType);
            return $"[Error: {ex.Message}]";
        }
    }
}
