namespace NetFlowAnalizer.Core.Models;

/// <summary>
/// Represents a complete NetFlow v9 packet with header and flowsets
/// </summary>
public class NetFlowPacket
{
    /// <summary>
    /// Packet header
    /// </summary>
    public NetFlowV9Header Header { get; set; }

    /// <summary>
    /// Template records in this packet
    /// </summary>
    public List<TemplateRecord> Templates { get; set; } = new();

    /// <summary>
    /// Data records in this packet
    /// </summary>
    public List<DataRecord> DataRecords { get; set; } = new();
}
