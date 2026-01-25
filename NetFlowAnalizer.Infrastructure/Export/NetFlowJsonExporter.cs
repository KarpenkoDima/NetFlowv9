using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core.Models;
using NetFlowAnalizer.Core.Services;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetFlowAnalizer.Infrastructure.Export;

/// <summary>
/// Exports NetFlow data to JSON format compatible with original dashboard
/// </summary>
public class NetFlowJsonExporter
{
    private readonly ILogger<NetFlowJsonExporter> _logger;
    private readonly ITemplateCache _templateCache;

    public NetFlowJsonExporter(ILogger<NetFlowJsonExporter> logger, ITemplateCache templateCache)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _templateCache = templateCache ?? throw new ArgumentNullException(nameof(templateCache));
    }

    /// <summary>
    /// Export NetFlow packets to JSON file (MVP-compatible format)
    /// </summary>
    public async Task ExportToJsonAsync(
        IEnumerable<NetFlowPacket> packets,
        string outputPath,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Exporting NetFlow data to {OutputPath}", outputPath);

        var packetList = packets.ToList();

        // Build packets array in MVP format
        var packetsArray = packetList.Select(p => new
        {
            version = p.Header.Version,
            count = p.Header.Count,
            sysUptime = p.Header.SystemUpTime,
            unixSecs = p.Header.UnixSeconds,
            sequenceNumber = p.Header.SequenceNumber,
            sourceId = p.Header.SourceId,
            flowSets = BuildFlowSets(p).ToArray()
        }).ToArray();

        // Build templates dictionary in MVP format
        var allTemplates = _templateCache.GetAllTemplates();
        var templatesDict = new Dictionary<string, Dictionary<string, object>>();

        foreach (var sourceKvp in allTemplates)
        {
            var sourceId = sourceKvp.Key.ToString();
            templatesDict[sourceId] = new Dictionary<string, object>();

            foreach (var templateKvp in sourceKvp.Value)
            {
                var templateId = templateKvp.Key.ToString();
                var template = templateKvp.Value;

                templatesDict[sourceId][templateId] = new
                {
                    TemplateId = template.TemplateId,
                    Fields = template.Fields.Select(f => new
                    {
                        Type = f.Type,
                        Length = f.Length
                    }).ToArray()
                };
            }
        }

        // Create final export structure (MVP-compatible)
        var exportData = new
        {
            version = 9,
            exportTime = DateTime.UtcNow,
            packets = packetsArray,
            templates = templatesDict
        };

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        var json = JsonSerializer.Serialize(exportData, options);
        await File.WriteAllTextAsync(outputPath, json, cancellationToken);

        var totalTemplates = packetList.Sum(p => p.Templates.Count);
        var totalFlows = packetList.Sum(p => p.DataRecords.Count);

        _logger.LogInformation("Successfully exported {PacketCount} packets, {TemplateCount} templates, {FlowCount} flows to {OutputPath}",
            packetsArray.Length, totalTemplates, totalFlows, outputPath);
    }

    /// <summary>
    /// Build flowSets array for a packet in MVP format
    /// </summary>
    private IEnumerable<object> BuildFlowSets(NetFlowPacket packet)
    {
        var flowSets = new List<object>();

        // Add template flowset if there are templates (flowSetId = 0)
        if (packet.Templates.Any())
        {
            flowSets.Add(new
            {
                flowSetId = 0,
                length = packet.Templates.Sum(t => 4 + 4 + t.Fields.Count * 4),
                templates = packet.Templates.Select(t => new
                {
                    templateId = t.TemplateId,
                    fields = t.Fields.Select(f => new
                    {
                        type = f.Type,
                        length = f.Length
                    }).ToArray()
                }).ToArray()
            });
        }

        // Add data flowsets grouped by template ID
        var dataGroups = packet.DataRecords.GroupBy(d => d.TemplateId);
        foreach (var group in dataGroups)
        {
            flowSets.Add(new
            {
                flowSetId = group.Key,
                length = group.Sum(d => d.Values.Count * 4), // approximate
                records = group.Select(d => d.Values).ToArray()
            });
        }

        return flowSets;
    }
}
