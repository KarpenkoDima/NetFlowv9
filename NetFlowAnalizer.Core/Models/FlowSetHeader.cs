namespace NetFlowAnalizer.Core.Models;

/// <summary>
/// FlowSet header structure (RFC 3954)
/// </summary>
public readonly record struct FlowSetHeader
{
    /// <summary>
    /// FlowSet ID:
    /// - 0: Template FlowSet
    /// - 1: Options Template FlowSet
    /// - 256-65535: Data FlowSet (corresponds to Template ID)
    /// </summary>
    public ushort FlowSetId { get; init; }

    /// <summary>
    /// Total length of this FlowSet in bytes (including header)
    /// </summary>
    public ushort Length { get; init; }

    public bool IsTemplateFlowSet => FlowSetId == 0;
    public bool IsOptionsTemplateFlowSet => FlowSetId == 1;
    public bool IsDataFlowSet => FlowSetId >= 256;
}
