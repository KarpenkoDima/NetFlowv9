namespace NetFlowAnalizer.Core.Models;

/// <summary>
/// Template field definition (RFC 3954)
/// </summary>
public readonly record struct TemplateField
{
    /// <summary>
    /// Field type (e.g., 8 = Source IP, 12 = Destination IP)
    /// </summary>
    public ushort Type { get; init; }

    /// <summary>
    /// Field length in bytes
    /// </summary>
    public ushort Length { get; init; }
}
