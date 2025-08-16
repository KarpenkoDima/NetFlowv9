using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core;
using NetFlowAnalizer.Core.Models;

namespace NetFlowAnalizer.Infrastructure;

/// <summary>
/// Stub for parser NetFlow v9
/// </summary>
public class NetFlowV9ParserStub : INetFlowParser
{

    private readonly ILogger<NetFlowV9ParserStub> _logger;

    public NetFlowV9ParserStub(ILogger<NetFlowV9ParserStub> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public int SupportedVersion => 9;

    public bool CanParse(ReadOnlySpan<byte> data)
    {
        _logger.LogDebug("Checking if data can be parsed (stub implementation");

        return data.Length >= 20;
    }

    public async Task<IEnumerable<INetFlowRecord>> ParseAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation($"Parsinhg {data.Length} bytes with NetFlow v9 parser (stu)");

        await Task.Delay(10, cancellationToken);

        _logger.LogInformation($"Parsing completed (stub implementation)");

        // return empty collection then is stub
        return Array.Empty<INetFlowRecord>();
    }
}
