namespace NetFlowAnalizer.Core.Models;

/// <summary>
/// Data record containing actual flow data
/// </summary>
public class DataRecord : INetFlowRecord
{
    /// <summary>
    /// Template ID this record corresponds to
    /// </summary>
    public ushort TemplateId { get; set; }

    /// <summary>
    /// Field values: key = field type, value = formatted string value
    /// </summary>
    public Dictionary<string, object> Values { get; set; } = new();
}
