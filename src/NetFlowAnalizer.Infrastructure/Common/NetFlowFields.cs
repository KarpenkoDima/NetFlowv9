namespace NetFlowAnalizer.Infrastructure.Common;

/// <summary>
/// NetFlow v9 field type definitions (RFC 3954)
/// </summary>
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
