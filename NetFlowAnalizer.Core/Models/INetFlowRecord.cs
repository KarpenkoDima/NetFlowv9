namespace NetFlowAnalizer.Core.Models;

/// <summary>
/// Marker interface for all NetFlow record types
/// (Header, Template, Data records)
/// </summary>
public interface INetFlowRecord
{
    // Marker interface - no members
    // Allows polymorphic collections of different NetFlow record types
}
