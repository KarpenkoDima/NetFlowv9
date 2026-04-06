using System.Buffers.Binary;

namespace NetFlowAnalizer.Core.Models;

/// <summary>
/// Header NetFlow v9 packet (RFC 3954). 20 bytes, big-endian.
/// </summary>
public readonly record struct NetFlowV9Header : INetFlowRecord
{
    public const int HeaderSize = 20;

    public NetFlowV9Header(
        ushort version,
        ushort count,
        uint systemUpTime,
        uint unixSeconds,
        uint sequenceNumber,
        uint sourceId)
    {
        if (version != 9)
            throw new ArgumentException(
                $"Invalid NetFlow version {version}. Expected v9", nameof(version));

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

    /// <summary>
    /// Zero-copy parse from ReadOnlySpan. Uses BinaryPrimitives — no allocations.
    /// </summary>
    public static NetFlowV9Header FromBytes(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderSize)
            throw new ArgumentException(
                $"Data too short. Expected at least {HeaderSize} bytes, got {data.Length}");

        return new NetFlowV9Header(
            version: BinaryPrimitives.ReadUInt16BigEndian(data),
            count: BinaryPrimitives.ReadUInt16BigEndian(data[2..]),
            systemUpTime: BinaryPrimitives.ReadUInt32BigEndian(data[4..]),
            unixSeconds: BinaryPrimitives.ReadUInt32BigEndian(data[8..]),
            sequenceNumber: BinaryPrimitives.ReadUInt32BigEndian(data[12..]),
            sourceId: BinaryPrimitives.ReadUInt32BigEndian(data[16..]));
    }

    public override string ToString() =>
        $"NetFlow v{Version}: Count={Count}, Seq={SequenceNumber}, Source={SourceId}, Time={Timestamp:yyyy-MM-dd HH:mm:ss}";
}
