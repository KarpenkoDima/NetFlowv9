using NetFlowAnalizer.Core.Models;

namespace NetFlowAnalizer.Core;

/// <summary>
/// Interface for parsing NetFlow data.
/// Synchronous, Span-based — no heap allocations in hot path.
/// </summary>
public interface INetFlowParser
{
    /// <summary>
    /// Supported NetFlow protocol version
    /// </summary>
    int SupportedVersion { get; }

    /// <summary>
    /// Check whether this parser can handle the given packet
    /// </summary>
    bool CanParse(ReadOnlySpan<byte> data);

    /// <summary>
    /// Parse a single NetFlow UDP payload into a <see cref="NetFlowPacket"/>.
    /// Purely synchronous — no async, no Task, no MemoryStream.
    /// </summary>
    NetFlowPacket ParsePacket(ReadOnlySpan<byte> data);
}
