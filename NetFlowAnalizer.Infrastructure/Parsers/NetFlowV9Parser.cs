using System.Buffers.Binary;
using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core;
using NetFlowAnalizer.Core.Models;
using NetFlowAnalizer.Core.Services;

namespace NetFlowAnalizer.Infrastructure.Parsers;

/// <summary>
/// High-performance NetFlow v9 parser (RFC 3954).
/// Zero MemoryStream, zero BinaryReader, zero Array.Reverse.
/// All parsing via ReadOnlySpan&lt;byte&gt; + BinaryPrimitives.
/// </summary>
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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool CanParse(ReadOnlySpan<byte> data)
    {
        return data.Length >= NetFlowV9Header.HeaderSize
            && BinaryPrimitives.ReadUInt16BigEndian(data) == 9;
    }

    public NetFlowPacket ParsePacket(ReadOnlySpan<byte> data)
    {
        var header = NetFlowV9Header.FromBytes(data);

        var packet = new NetFlowPacket { Header = header };

        var offset = NetFlowV9Header.HeaderSize;

        while (offset + 4 <= data.Length)
        {
            var flowSetId = BinaryPrimitives.ReadUInt16BigEndian(data[offset..]);
            var flowSetLength = BinaryPrimitives.ReadUInt16BigEndian(data[(offset + 2)..]);

            if (flowSetLength < 4 || offset + flowSetLength > data.Length)
            {
                _logger.LogWarning(
                    "Invalid FlowSet: ID={Id}, Length={Length}, Offset={Offset}, DataLength={DataLength}",
                    flowSetId, flowSetLength, offset, data.Length);
                break;
            }

            // Content starts after 4-byte FlowSet header
            var contentStart = offset + 4;
            var contentLength = flowSetLength - 4;
            var content = data.Slice(contentStart, contentLength);

            if (flowSetId == 0)
            {
                ParseTemplateFlowSet(content, header.SourceId, packet.Templates);
            }
            else if (flowSetId >= 256)
            {
                ParseDataFlowSet(content, header.SourceId, flowSetId, packet.DataRecords);
            }
            // flowSetId == 1 → Options Template, skip for now

            offset += flowSetLength;
        }

        return packet;
    }

    private void ParseTemplateFlowSet(
        ReadOnlySpan<byte> content,
        uint sourceId,
        List<TemplateRecord> outTemplates)
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
                var fieldType = BinaryPrimitives.ReadUInt16BigEndian(content[offset..]);
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

            _logger.LogDebug(
                "Template {TemplateId}: {FieldCount} fields, RecordLength={RecordLength}",
                templateId, fieldCount, template.RecordLength);
        }
    }

    private void ParseDataFlowSet(
        ReadOnlySpan<byte> content,
        uint sourceId,
        ushort templateId,
        List<DataRecord> outRecords)
    {
        var template = _templateCache.GetTemplate(sourceId, templateId);
        if (template is null)
        {
            _logger.LogWarning(
                "No template for Source={SourceId}, Template={TemplateId} — skipping data FlowSet",
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

    /// <summary>
    /// Format a single field value from raw bytes.
    /// Operates on ReadOnlySpan — no heap allocation for the read itself.
    /// String allocation is unavoidable for the return value.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private string FormatField(ushort fieldType, ReadOnlySpan<byte> data)
    {
        switch (fieldType)
        {
            // --- Single byte fields ---
            case 4:   // Protocol
            case 5:   // TOS
            case 6:   // TCP Flags
            case 9:   // Src Mask
            case 13:  // Dst Mask
                return data.Length == 1
                    ? data[0].ToString()
                    : BitConverter.ToString(data.ToArray());

            // --- IPv4 addresses (4 bytes) ---
            case 8:   // Src IP
            case 12:  // Dst IP
            case 15:  // Next Hop
            case 225: // Post-NAT Src IP
            case 226: // Post-NAT Dst IP
                if (data.Length == 4)
                {
                    // Read as raw 4 bytes, pass to IPAddress without reversal
                    // IPAddress(byte[]) expects network byte order — which is what we have
                    Span<byte> ipBuf = stackalloc byte[4];
                    data.CopyTo(ipBuf);
                    return new IPAddress(ipBuf).ToString();
                }
                return BitConverter.ToString(data.ToArray());

            // --- 16-bit integers ---
            case 7:   // Src Port
            case 11:  // Dst Port
            case 227: // Post-NAT Src Port
            case 228: // Post-NAT Dst Port
                return data.Length == 2
                    ? BinaryPrimitives.ReadUInt16BigEndian(data).ToString()
                    : BitConverter.ToString(data.ToArray());

            // --- 32-bit integers ---
            case 1:   // Bytes
            case 2:   // Packets
            case 10:  // Input IF
            case 14:  // Output IF
            case 34:  // Start Time
            case 35:  // End Time
                return data.Length == 4
                    ? BinaryPrimitives.ReadUInt32BigEndian(data).ToString()
                    : BitConverter.ToString(data.ToArray());

            // --- 64-bit timestamps ---
            case 80:  // Flow Start (Unix ms)
            case 81:  // Flow End (Unix ms)
                if (data.Length == 8)
                {
                    var ms = (long)BinaryPrimitives.ReadUInt64BigEndian(data);
                    return DateTimeOffset.FromUnixTimeMilliseconds(ms)
                        .ToString("yyyy-MM-dd HH:mm:ss");
                }
                return BitConverter.ToString(data.ToArray());

            // --- Everything else (MAC, SysUptime, unknown) → hex ---
            default:
                return BitConverter.ToString(data.ToArray());
        }
    }
}
