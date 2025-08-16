using NetFlowAnalizer.Core.Models;

namespace NetFlowAnalizer.Core;
/*
 * Interface for parsing Net Flow data
 * 
 */

/// <summary>
/// Interface for parsing Net Flow data
/// </summary>
public interface INetFlowParser
{
    /// <summary>
    /// Supported version NetFlow protocol
    /// </summary>
    int SupportedVersion { get;  }

    /// <summary>
    /// Verify, Parser can been to parse data
    /// </summary>
    /// <param name="data">Data for parsing</param>
    /// <returns>true, if parser can to parsing data</returns>
    bool CanParse(ReadOnlySpan<byte> data);

    /// <summary>
    /// Async parsing NetFlow data 
    /// </summary>
    /// <param name="data">Binary data for parsing</param>
    /// <param name="cancellationToken">Token for cancelation</param>
    /// <returns>Collection NetFlow data</returns>
    Task<IEnumerable<INetFlowRecord>> ParseAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default);

}
