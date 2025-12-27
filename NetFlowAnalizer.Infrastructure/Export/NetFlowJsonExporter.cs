using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core.Models;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetFlowAnalizer.Infrastructure.Export;

/// <summary>
/// Exports NetFlow data to JSON format
/// </summary>
public class NetFlowJsonExporter
{
    private readonly ILogger<NetFlowJsonExporter> _logger;

    public NetFlowJsonExporter(ILogger<NetFlowJsonExporter> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Export NetFlow records to JSON file
    /// </summary>
    public async Task ExportToJsonAsync(
        IEnumerable<INetFlowRecord> records,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Exporting NetFlow data to {OutputPath}", outputPath);

        var headers = records.OfType<NetFlowV9Header>().ToList();
        var templates = records.OfType<TemplateRecord>().ToList();
        var dataRecords = records.OfType<DataRecord>().ToList();

        var exportData = new
        {
            version = 9,
            exportTime = DateTime.UtcNow,
            summary = new
            {
                totalHeaders = headers.Count,
                totalTemplates = templates.Count,
                totalDataRecords = dataRecords.Count
            },
            headers = headers.Select(h => new
            {
                version = h.Version,
                count = h.Count,
                systemUpTime = h.SystemUpTime,
                unixSeconds = h.UnixSeconds,
                timestamp = h.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                sequenceNumber = h.SequenceNumber,
                sourceId = h.SourceId
            }).ToArray(),
            templates = templates.Select(t => new
            {
                templateId = t.TemplateId,
                fieldCount = t.Fields.Count,
                recordLength = t.RecordLength,
                fields = t.Fields.Select(f => new
                {
                    type = f.Type,
                    length = f.Length
                }).ToArray()
            }).ToArray(),
            flows = dataRecords.Select(d => new
            {
                templateId = d.TemplateId,
                values = d.Values
            }).ToArray()
        };

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        var json = JsonSerializer.Serialize(exportData, options);
        await File.WriteAllTextAsync(outputPath, json, cancellationToken);

        _logger.LogInformation("Successfully exported {RecordCount} records to {OutputPath}",
            records.Count(), outputPath);
    }
}
