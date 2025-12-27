using System.Net;

namespace NetFlowAnalizer.Infrastructure.Common;

/// <summary>
/// Utility functions for byte conversion (Big-Endian to Little-Endian)
/// </summary>
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

    public static ushort ReadUInt16BigEndian(BinaryReader br)
    {
        var bytes = br.ReadBytes(2);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        return BitConverter.ToUInt16(bytes, 0);
    }

    public static uint ReadUInt32BigEndian(BinaryReader br)
    {
        var bytes = br.ReadBytes(4);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        return BitConverter.ToUInt32(bytes, 0);
    }
}
