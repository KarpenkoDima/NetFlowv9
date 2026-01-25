namespace NetFlowAnalizer.Core.Models;

/// <summary>
/// Represents a parsed FlowSet with its header and records
/// </summary>
public class ParsedFlowSet
{
    public FlowSetHeader Header { get; set; }

    public List<TemplateRecord> TemplateRecords { get; set; } = new();

    public List<DataRecord> DataRecords { get; set; } = new();

    public ushort FlowSetId => Header.FlowSetId;
}
