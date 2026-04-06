using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core.Models;
using NetFlowAnalizer.Core.Services;

namespace NetFlowAnalizer.Infrastructure.Export;

/// <summary>
/// Streaming JSON exporter using Utf8JsonWriter over FileStream.
/// Writes packets on-the-fly — memory usage is O(1) regardless of data size.
///
/// Usage:
///   exporter.BeginExport("output.json");
///   reader.Process(pcapPath, packet => exporter.WritePacket(packet));
///   exporter.EndExport();
/// </summary>
public sealed class NetFlowJsonExporter : IDisposable
{
    private readonly ILogger<NetFlowJsonExporter> _logger;
    private readonly ITemplateCache _templateCache;

    private FileStream? _fileStream;
    private Utf8JsonWriter? _writer;
    private bool _firstPacket;
    private int _packetCount;

    public NetFlowJsonExporter(ILogger<NetFlowJsonExporter> logger, ITemplateCache templateCache)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _templateCache = templateCache ?? throw new ArgumentNullException(nameof(templateCache));
    }

    /// <summary>
    /// Open output file and write JSON preamble.
    /// </summary>
    public void BeginExport(string outputPath)
    {
        _logger.LogInformation("Opening JSON export: {Path}", outputPath);

        _fileStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write,
            FileShare.None, bufferSize: 65536);

        _writer = new Utf8JsonWriter(_fileStream, new JsonWriterOptions
        {
            Indented = true
        });

        _firstPacket = true;
        _packetCount = 0;

        // { "version": 9, "exportTime": "...", "packets": [
        _writer.WriteStartObject();
        _writer.WriteNumber("version", 9);
        _writer.WriteString("exportTime", DateTime.UtcNow);
        _writer.WriteStartArray("packets");
    }

    /// <summary>
    /// Write a single packet to the JSON stream.
    /// Called from the PCAP reader callback — no buffering.
    /// </summary>
    public void WritePacket(in NetFlowPacket packet)
    {
        if (_writer is null)
            throw new InvalidOperationException("Call BeginExport first");

        _packetCount++;

        _writer.WriteStartObject();

        // Header fields
        _writer.WriteNumber("version", packet.Header.Version);
        _writer.WriteNumber("count", packet.Header.Count);
        _writer.WriteNumber("sysUptime", packet.Header.SystemUpTime);
        _writer.WriteNumber("unixSecs", packet.Header.UnixSeconds);
        _writer.WriteNumber("sequenceNumber", packet.Header.SequenceNumber);
        _writer.WriteNumber("sourceId", packet.Header.SourceId);

        // FlowSets
        _writer.WriteStartArray("flowSets");
        WriteFlowSets(packet);
        _writer.WriteEndArray(); // flowSets

        _writer.WriteEndObject(); // packet

        // Flush periodically to keep memory bounded
        if (_packetCount % 100 == 0)
        {
            _writer.Flush();
        }
    }

    /// <summary>
    /// Write closing JSON: end packets array, write templates, close root object.
    /// </summary>
    public void EndExport()
    {
        if (_writer is null) return;

        _writer.WriteEndArray(); // packets

        // Write templates from cache
        WriteTemplatesFromCache();

        _writer.WriteEndObject(); // root
        _writer.Flush();

        _logger.LogInformation(
            "JSON export complete: {PacketCount} packets written", _packetCount);
    }

    private void WriteFlowSets(in NetFlowPacket packet)
    {
        // Template flowset (flowSetId = 0)
        if (packet.Templates.Count > 0)
        {
            _writer.WriteStartObject();
            _writer.WriteNumber("flowSetId", 0);

            var totalLength = 0;
            foreach (var t in packet.Templates)
                totalLength += 4 + 4 + t.Fields.Count * 4;
            _writer.WriteNumber("length", totalLength);

            _writer.WriteStartArray("templates");
            foreach (var template in packet.Templates)
            {
                _writer.WriteStartObject();
                _writer.WriteNumber("templateId", template.TemplateId);

                _writer.WriteStartArray("fields");
                foreach (var field in template.Fields)
                {
                    _writer.WriteStartObject();
                    _writer.WriteNumber("type", field.Type);
                    _writer.WriteNumber("length", field.Length);
                    _writer.WriteEndObject();
                }
                _writer.WriteEndArray(); // fields

                _writer.WriteEndObject(); // template
            }
            _writer.WriteEndArray(); // templates

            _writer.WriteEndObject(); // template flowset
        }

        // Data flowsets grouped by template ID
        var groupStart = 0;
        while (groupStart < packet.DataRecords.Count)
        {
            var templateId = packet.DataRecords[groupStart].TemplateId;
            var groupEnd = groupStart + 1;

            while (groupEnd < packet.DataRecords.Count
                && packet.DataRecords[groupEnd].TemplateId == templateId)
            {
                groupEnd++;
            }

            _writer.WriteStartObject();
            _writer.WriteNumber("flowSetId", templateId);

            // Approximate length
            var approxLength = 0;
            for (var i = groupStart; i < groupEnd; i++)
                approxLength += packet.DataRecords[i].Values.Count * 4;
            _writer.WriteNumber("length", approxLength);

            _writer.WriteStartArray("records");
            for (var i = groupStart; i < groupEnd; i++)
            {
                _writer.WriteStartObject();
                foreach (var kvp in packet.DataRecords[i].Values)
                {
                    _writer.WriteString(kvp.Key, kvp.Value?.ToString() ?? string.Empty);
                }
                _writer.WriteEndObject();
            }
            _writer.WriteEndArray(); // records

            _writer.WriteEndObject(); // data flowset

            groupStart = groupEnd;
        }
    }

    private void WriteTemplatesFromCache()
    {
        var allTemplates = _templateCache.GetAllTemplates();

        _writer!.WriteStartObject("templates");

        foreach (var (sourceId, templates) in allTemplates)
        {
            _writer.WriteStartObject(sourceId.ToString());

            foreach (var (templateId, template) in templates)
            {
                _writer.WriteStartObject(templateId.ToString());
                _writer.WriteNumber("TemplateId", template.TemplateId);

                _writer.WriteStartArray("Fields");
                foreach (var field in template.Fields)
                {
                    _writer.WriteStartObject();
                    _writer.WriteNumber("Type", field.Type);
                    _writer.WriteNumber("Length", field.Length);
                    _writer.WriteEndObject();
                }
                _writer.WriteEndArray(); // Fields

                _writer.WriteEndObject(); // template entry
            }

            _writer.WriteEndObject(); // source entry
        }

        _writer.WriteEndObject(); // templates
    }

    public void Dispose()
    {
        _writer?.Dispose();
        _fileStream?.Dispose();
    }
}
