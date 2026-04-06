namespace NetFlowAnalizer.Core.Models;

/// <summary>
/// Template record containing field definitions (RFC 3954)
/// </summary>
public class TemplateRecord : INetFlowRecord
{
    /// <summary>
    /// Template ID (256-65535)
    /// </summary>
    public ushort TemplateId { get; set; }

    /// <summary>
    /// List of fields in this template
    /// </summary>
    public List<TemplateField> Fields { get; set; } = new();

    /// <summary>
    /// Total length of one record in bytes
    /// </summary>
    public int RecordLength => Fields.Sum(f => f.Length);
}
