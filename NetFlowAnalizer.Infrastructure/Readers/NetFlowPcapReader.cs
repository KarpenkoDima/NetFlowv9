using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core;
using NetFlowAnalizer.Core.Models;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetFlowAnalizer.Infrastructure.Readers;

/// <summary>
/// Reads NetFlow packets from PCAP files
/// </summary>
public class NetFlowPcapReader
{
    private readonly INetFlowParser _parser;
    private readonly ILogger<NetFlowPcapReader> _logger;
    private readonly List<INetFlowRecord> _allRecords = new();

    public const int NetFlowPort = 2055;

    public NetFlowPcapReader(INetFlowParser parser, ILogger<NetFlowPcapReader> logger)
    {
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// All parsed NetFlow records
    /// </summary>
    public IReadOnlyList<INetFlowRecord> AllRecords => _allRecords.AsReadOnly();

    /// <summary>
    /// Read and parse NetFlow packets from PCAP file
    /// </summary>
    public async Task ReadAsync(string pcapFilePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(pcapFilePath))
        {
            throw new FileNotFoundException($"PCAP file not found: {pcapFilePath}");
        }

        _logger.LogInformation("Opening PCAP file: {FilePath}", pcapFilePath);

        _allRecords.Clear();

        using var device = new CaptureFileReaderDevice(pcapFilePath);
        device.Open();

        _logger.LogInformation("PCAP file opened successfully. Starting packet capture...");

        int totalPackets = 0;
        int netflowPackets = 0;

        PacketCapture packet;
        while ((packet = device.GetNextPacket()) != null)
        {
            cancellationToken.ThrowIfCancellationRequested();
            totalPackets++;

            try
            {
                var rawPacket = Packet.ParsePacket(packet.GetPacket().LinkLayerType, packet.GetPacket().Data);
                var udpPacket = rawPacket.Extract<UdpPacket>();

                // Filter only NetFlow packets (UDP port 2055)
                if (udpPacket == null || udpPacket.DestinationPort != NetFlowPort)
                    continue;

                var payload = udpPacket.PayloadData;
                if (payload == null || payload.Length < 20)
                {
                    _logger.LogDebug("Skipping packet with insufficient payload length: {Length}", payload?.Length ?? 0);
                    continue;
                }

                // Check if parser can handle this packet
                if (!_parser.CanParse(payload))
                {
                    _logger.LogDebug("Parser cannot handle this packet (wrong version)");
                    continue;
                }

                netflowPackets++;
                _logger.LogDebug("Processing NetFlow packet {Index}", netflowPackets);

                // Parse the packet
                var records = await _parser.ParseAsync(payload, cancellationToken);
                _allRecords.AddRange(records);

                _logger.LogInformation("Parsed NetFlow packet {Index}, extracted {RecordCount} records",
                    netflowPackets, records.Count());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing packet {Index}", totalPackets);
            }
        }

        device.Close();

        _logger.LogInformation("PCAP processing completed. Total packets: {Total}, NetFlow packets: {NetFlow}, Total records: {Records}",
            totalPackets, netflowPackets, _allRecords.Count);
    }

    /// <summary>
    /// Get all headers from parsed records
    /// </summary>
    public IEnumerable<NetFlowV9Header> GetHeaders()
    {
        return _allRecords.OfType<NetFlowV9Header>();
    }

    /// <summary>
    /// Get all template records
    /// </summary>
    public IEnumerable<TemplateRecord> GetTemplates()
    {
        return _allRecords.OfType<TemplateRecord>();
    }

    /// <summary>
    /// Get all data records
    /// </summary>
    public IEnumerable<DataRecord> GetDataRecords()
    {
        return _allRecords.OfType<DataRecord>();
    }
}
