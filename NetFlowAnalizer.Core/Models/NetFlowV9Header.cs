
namespace NetFlowAnalizer.Core.Models;

/// <summary>
/// Header NetFlow v9 packet RFC 3954
/// </summary>
public readonly record struct NetFlowV9Header : INetFlowRecord
{
    public const int HeaderSize = 20;

    
    public NetFlowV9Header(ushort versioon,
        ushort count,
        uint systemUpTime,
        uint unixSeconds,
        uint sequenceNumber,
        uint sourceId)
    {
        if (versioon != 9) throw new ArgumentException($"Invalid NetFlow version {versioon}. Expected v9", nameof(versioon));
        if (count == 0) throw new ArgumentException("count must be greater than 0" , nameof(count));
        Version = versioon;
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

    public DateTime Timestamp => DateTimeOffset.FromUnixTimeSeconds(UnixSeconds).DateTime;
    public uint SequenceNumber { get; }
    public uint SourceId { get; }
    public bool IsValid => Version == 9 && Count > 0;


    public static NetFlowV9Header FromBytes(ReadOnlySpan<Byte> data)
    {
        if (data.Length < HeaderSize)
        {
            throw new ArgumentException($"Data too short. Expected at least {HeaderSize} bytes");
        }

        var version = (ushort)((data[0] << 8 | data[1]));
        var count = (ushort)((data[2] << 8 | data[3]));
        var systemUpTime = (uint)((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]);
        var unixSeconds = (uint)((data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11]);
        var sequenceNumber = (uint)((data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15]);
        var sourceId = (uint)((data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19]);

        return new NetFlowV9Header(version, count, systemUpTime, unixSeconds, sequenceNumber, sourceId);
    }

    public override string ToString()
    {
        return $"NetFlow v{Version}: Count={Count}, Seq={SequenceNumber}, source={SourceId}, Time={Timestamp:yyyy-MM-dd HH:mm:ss}";
    }
}
