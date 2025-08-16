using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core;
using NetFlowAnalizer.Core.Models;
using System.Text.RegularExpressions;

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

        if (data.Length < NetFlowV9Header.HeaderSize)
        {
            _logger.LogDebug($"Data too small {data.Length} < {NetFlowV9Header.HeaderSize}");
            return false;
        }

        var version = (ushort)((data[0] << 8) | data[1]);
        var canParse = version == SupportedVersion;

        _logger.LogDebug($"NetFlow version: {version}, can parse: {canParse}");
        return canParse;
    }

    public async Task<IEnumerable<INetFlowRecord>> ParseAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Starting NetFlow v9 parsing, data size: {DataSize} bytes", data.Length);

        try
        {
            await Task.Delay(1, cancellationToken);

            var result = ParseHeader(data.Span);
            return result.IsSuccess ? new INetFlowRecord[] { result.Value} : Array.Empty<INetFlowRecord>();
        }
        catch(OperationCanceledException)
        {
            _logger.LogWarning("Parsing was cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during NetFlow parsing");
        }
        await Task.Delay(10, cancellationToken);

        _logger.LogInformation($"Parsing completed (stub implementation)");

        // return empty collection then is stub
        return Array.Empty<INetFlowRecord>();
    }

    private Result<NetFlowV9Header> ParseHeader(ReadOnlySpan<byte> data)
    {
        try
        {
            _logger.LogDebug($"Parsing NetFlow v9 header from {data.Length} bytes");

            var header = NetFlowV9Header.FromBytes(data);

            _logger.LogInformation($"Successfully parsed header: {header}");
            _logger.LogDebug($"Header details - Count: {header.Count}, Sequence: {header.SequenceNumber}, Source: {header.SourceId}");

            if (false == header.IsValid)
            {
                var error = $"Invalid NetFlow header: Version={header.Version}, Count={header.Count}"; ;
                _logger.LogError(error);
                return Result<NetFlowV9Header>.Failure(error);
            }

            return Result<NetFlowV9Header>.Success(header);
        }
        catch (ArgumentException ex)
        {
            var error = $"Failed to parse NetFlow header: {ex.Message}";
            _logger.LogError(ex, error);
            return Result<NetFlowV9Header>.Failure(error);
        }
        catch (Exception ex)
        {
            var error = $"Unexpected error parsing header: {ex.Message}";
            _logger.LogError(ex, error);
            return Result<NetFlowV9Header>.Failure(error);
        }
    }
}
