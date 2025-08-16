namespace NetFlowAnalizer.Core.Models;

/// <summary>
/// base interface for all NetFlow records type
/// </summary>
public interface INetFlowRecord
{
    ushort Version { get; }
    DateTime Timestamp { get; }
}
