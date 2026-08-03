using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core.Models;
using NetFlowAnalizer.Core.Services;
using NetFlowAnalizer.LivePipeline.Models;

namespace NetFlowAnalizer.LivePipeline.Parsers;

/// <summary>
/// Zero-allocation NetFlow v9 parser for the live UDP pipeline (RFC 3954).
///
/// Hot-path guarantees (data FlowSet loop):
///   - No `new` on the managed heap.
///   - No string formatting (IPs stored as uint, counters as ulong).
///   - All integer reads via BinaryPrimitives (Big-Endian / network byte order).
///   - Records written directly into a caller-supplied Span&lt;InboundFlowRecord&gt;.
///
/// One-time allocations (acceptable):
///   - TemplateRecord + TemplateField[] objects created once per new template.
///     Templates arrive rarely (router startup / reconnect) and are cached forever.
/// </summary>
public sealed class LiveNetFlowV9Parser
{
    /// <summary>
    /// Maximum InboundFlowRecord values TryParseRecords can write.
    /// Callers must size their output buffer to at least this value.
    /// Rationale: largest practical UDP payload / smallest flow record ≈ 200 records;
    /// 256 gives a safe margin without wasting ArrayPool memory.
    /// </summary>
    public const int MaxRecordsPerPacket = 256;

    private readonly ILogger<LiveNetFlowV9Parser> _log;
    private readonly ITemplateCache _templateCache;

    public LiveNetFlowV9Parser(
        ILogger<LiveNetFlowV9Parser> log,
        ITemplateCache templateCache)
    {
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _templateCache = templateCache ?? throw new ArgumentNullException(nameof(templateCache));
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Parses one raw NetFlow v9 UDP packet.
    /// </summary>
    /// <param name="data">Raw bytes from RawPacketBuffer.Span — no copy needed.</param>
    /// <param name="receivedAtTicks">
    ///   RawPacketBuffer.TimestampUtcTicks — used as fallback when the packet
    ///   carries unix_secs == 0 (some embedded exporters).
    /// </param>
    /// <param name="outputBuf">
    ///   Caller-supplied buffer; must have Length ≥ MaxRecordsPerPacket.
    ///   Written records occupy outputBuf[0..returnValue-1].
    /// </param>
    /// <returns>Number of InboundFlowRecord values written into outputBuf.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int TryParseRecords(
        ReadOnlySpan<byte>      data,
        long                    receivedAtTicks,
        Span<InboundFlowRecord> outputBuf)
    {
        // ── Minimum sanity check ──────────────────────────────────────────────
        if (data.Length < NetFlowV9Header.HeaderSize)
            return 0;

        // ── Header: 20 bytes, Big-Endian, parsed inline (zero struct new) ─────
        //
        //  Offset  Size  Field
        //  ──────  ────  ──────────────────────────────
        //    0      2    Version  (must be 9)
        //    2      2    Count    (number of FlowSets — informational only)
        //    4      4    SysUptime (ms since router boot — not used here)
        //    8      4    UnixSecs  (export timestamp, Unix epoch seconds)
        //   12      4    SequenceNumber
        //   16      4    SourceId (Observation Domain)

        if (BinaryPrimitives.ReadUInt16BigEndian(data) != 9)
            return 0;

        uint unixSecs        = BinaryPrimitives.ReadUInt32BigEndian(data[8..]);
        uint sequenceNumber  = BinaryPrimitives.ReadUInt32BigEndian(data[12..]);
        uint sourceId        = BinaryPrimitives.ReadUInt32BigEndian(data[16..]);

        // Prefer the router's own export timestamp; fall back to socket receive time.
        DateTimeOffset flowTimestamp = unixSecs > 0
            ? DateTimeOffset.FromUnixTimeSeconds(unixSecs)
            : new DateTimeOffset(receivedAtTicks, TimeSpan.Zero);

        // ── FlowSet loop ──────────────────────────────────────────────────────
        int offset  = NetFlowV9Header.HeaderSize;
        int written = 0;

        while (offset + 4 <= data.Length && written < outputBuf.Length)
        {
            ushort flowSetId     = BinaryPrimitives.ReadUInt16BigEndian(data[offset..]);
            ushort flowSetLength = BinaryPrimitives.ReadUInt16BigEndian(data[(offset + 2)..]);

            // Length < 4 means the header itself is corrupt; stop parsing.
            if (flowSetLength < 4 || offset + flowSetLength > data.Length)
            {
                _log.LogWarning(
                    "Bad FlowSet header: ID={Id} Len={Len} Offset={Off} DataLen={DLen}",
                    flowSetId, flowSetLength, offset, data.Length);
                break;
            }

            // Content = FlowSet bytes minus its own 4-byte header.
            var content = data.Slice(offset + 4, flowSetLength - 4);

            if (flowSetId == 0)
            {
                // Template FlowSet — register templates into cache.
                // May allocate TemplateRecord objects (one-time, not per-packet).
                ParseTemplateFlowSet(content, sourceId);
            }
            else if (flowSetId >= 256)
            {
                // Data FlowSet — hot path, zero managed-heap allocation.
                written += ParseDataFlowSet(
                    content,
                    sourceId,
                    flowSetId,
                    sequenceNumber,
                    flowTimestamp,
                    outputBuf[written..]);
            }
            // flowSetId == 1 → Options Template FlowSet (RFC 3954 §6.2) — skip.

            offset += flowSetLength;
        }

        return written;
    }

    // ── Template FlowSet (ID = 0) ─────────────────────────────────────────────
    //
    // Allocates TemplateRecord / TemplateField[] once per new template.
    // Subsequent packets with the same SourceId+TemplateId are cache hits.

    private void ParseTemplateFlowSet(ReadOnlySpan<byte> content, uint sourceId)
    {
        int offset = 0;

        while (offset + 4 <= content.Length)
        {
            ushort templateId = BinaryPrimitives.ReadUInt16BigEndian(content[offset..]);
            ushort fieldCount = BinaryPrimitives.ReadUInt16BigEndian(content[(offset + 2)..]);
            offset += 4;

            int bytesNeeded = fieldCount * 4;
            if (offset + bytesNeeded > content.Length)
            {
                _log.LogWarning(
                    "Template {Id} truncated: need {Need}B, have {Have}B",
                    templateId, bytesNeeded, content.Length - offset);
                break;
            }

            // One-time allocation — acceptable outside the hot path.
            var template = new TemplateRecord { TemplateId = templateId };
            template.Fields.EnsureCapacity(fieldCount);

            for (int i = 0; i < fieldCount; i++)
            {
                template.Fields.Add(new TemplateField
                {
                    Type   = BinaryPrimitives.ReadUInt16BigEndian(content[offset..]),
                    Length = BinaryPrimitives.ReadUInt16BigEndian(content[(offset + 2)..])
                });
                offset += 4;
            }

            _templateCache.AddTemplate(sourceId, template);

            _log.LogDebug(
                "Template registered: Source={SId} ID={TId} Fields={FC} RecordLen={RL}B",
                sourceId, templateId, fieldCount, template.RecordLength);
        }
    }

    // ── Data FlowSet (ID ≥ 256) — ZERO-ALLOCATION HOT PATH ───────────────────
    //
    // NetFlow field type reference (RFC 3954 §8):
    //
    //   Type  Len  Meaning
    //   ────  ───  ──────────────────────────────────────────
    //      1  4/8  IN_BYTES      — octets in the flow
    //      2  4/8  IN_PKTS       — packets in the flow
    //      4    1  PROTOCOL      — IP protocol number (IANA)
    //      7    2  L4_SRC_PORT   — TCP/UDP source port
    //      8    4  IPV4_SRC_ADDR — source IPv4 address
    //     11    2  L4_DST_PORT   — TCP/UDP destination port
    //     12    4  IPV4_DST_ADDR — destination IPv4 address
    //
    // All other field types are skipped (fieldOffset advances, no read).

    private int ParseDataFlowSet(
        ReadOnlySpan<byte>      content,
        uint                    sourceId,
        ushort                  templateId,
        uint                    sequenceNumber,
        DateTimeOffset          flowTimestamp,
        Span<InboundFlowRecord> outputBuf)
    {
        var template = _templateCache.GetTemplate(sourceId, templateId);
        if (template is null)
        {
            _log.LogDebug(
                "Unknown template: Source={SId} ID={TId} — buffering until template arrives",
                sourceId, templateId);
            return 0;
        }

        int recordLength = template.RecordLength;
        if (recordLength == 0)
            return 0;

        var  fields  = template.Fields;
        int  offset  = 0;
        int  written = 0;

        while (offset + recordLength <= content.Length && written < outputBuf.Length)
        {
            var recordSpan = content.Slice(offset, recordLength);

            // Local scalars — live on the stack, no heap touch.
            uint   srcAddr  = 0;
            uint   dstAddr  = 0;
            ushort srcPort  = 0;
            ushort dstPort  = 0;
            byte   protocol = 0;
            ulong  bytes    = 0;
            ulong  packets  = 0;

            int fieldOffset = 0;

            for (int i = 0; i < fields.Count; i++)
            {
                ushort fType   = fields[i].Type;
                ushort fLength = fields[i].Length;
                var    fSpan   = recordSpan.Slice(fieldOffset, fLength);

                switch (fType)
                {
                    case 8:  // IPV4_SRC_ADDR — 4 bytes, Big-Endian uint = host-order IPv4
                        if (fLength == 4)
                            srcAddr = BinaryPrimitives.ReadUInt32BigEndian(fSpan);
                        break;

                    case 12: // IPV4_DST_ADDR
                        if (fLength == 4)
                            dstAddr = BinaryPrimitives.ReadUInt32BigEndian(fSpan);
                        break;

                    case 7:  // L4_SRC_PORT
                        if (fLength == 2)
                            srcPort = BinaryPrimitives.ReadUInt16BigEndian(fSpan);
                        break;

                    case 11: // L4_DST_PORT
                        if (fLength == 2)
                            dstPort = BinaryPrimitives.ReadUInt16BigEndian(fSpan);
                        break;

                    case 4:  // PROTOCOL — single byte
                        if (fLength == 1)
                            protocol = fSpan[0];
                        break;

                    case 1:  // IN_BYTES — 4 or 8 bytes depending on exporter config
                        bytes = fLength switch
                        {
                            4 => BinaryPrimitives.ReadUInt32BigEndian(fSpan),
                            8 => BinaryPrimitives.ReadUInt64BigEndian(fSpan),
                            _ => 0
                        };
                        break;

                    case 2:  // IN_PKTS
                        packets = fLength switch
                        {
                            4 => BinaryPrimitives.ReadUInt32BigEndian(fSpan),
                            8 => BinaryPrimitives.ReadUInt64BigEndian(fSpan),
                            _ => 0
                        };
                        break;

                    // All other fields: advance fieldOffset, no allocation.
                }

                fieldOffset += fLength;
            }

            // Value-type write — no heap allocation, copied directly into the Span slot.
            outputBuf[written++] = new InboundFlowRecord
            {
                SrcAddr        = srcAddr,
                DstAddr        = dstAddr,
                SrcPort        = srcPort,
                DstPort        = dstPort,
                Protocol       = protocol,
                Bytes          = bytes,
                Packets        = packets,
                FlowTimestamp  = flowTimestamp,
                SourceId       = sourceId,
                SequenceNumber = sequenceNumber,
            };

            offset += recordLength;
        }

        return written;
    }
}
