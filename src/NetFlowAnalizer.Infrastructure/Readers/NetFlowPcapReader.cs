using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core;
using NetFlowAnalizer.Core.Models;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace NetFlowAnalizer.Infrastructure.Readers;

/// <summary>
/// Streaming PCAP reader. Processes one packet at a time —
/// never accumulates all records in memory.
/// Memory usage is O(1) regardless of PCAP file size.
/// </summary>
public sealed class NetFlowPcapReader
{
    private readonly INetFlowParser _parser;
    private readonly ILogger<NetFlowPcapReader> _logger;

    public const int NetFlowPort = 2055;

    public NetFlowPcapReader(INetFlowParser parser, ILogger<NetFlowPcapReader> logger)
    {
        _parser = parser ?? throw new ArgumentNullException(nameof(parser));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Stats from the last run
    /// </summary>
    public int TotalPackets { get; private set; }
    public int NetFlowPackets { get; private set; }
    public int TotalTemplates { get; private set; }
    public int TotalFlows { get; private set; }

    /// <summary>
    /// Process PCAP file in streaming mode.
    /// Each parsed NetFlowPacket is passed to <paramref name="onPacket"/> and then discarded.
    /// No lists, no accumulation — constant memory.
    /// </summary>
    public void Process(
        string pcapFilePath,
        Action<NetFlowPacket> onPacket,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(pcapFilePath))
            throw new FileNotFoundException($"PCAP file not found: {pcapFilePath}");

        _logger.LogInformation("Opening PCAP: {FilePath}", pcapFilePath);

        TotalPackets = 0;
        NetFlowPackets = 0;
        TotalTemplates = 0;
        TotalFlows = 0;

        using var device = new CaptureFileReaderDevice(pcapFilePath);
        device.Open();

        PacketCapture capture;
        GetPacketStatus status;

        while ((status = device.GetNextPacket(out capture)) == GetPacketStatus.PacketRead)
        {
            cancellationToken.ThrowIfCancellationRequested();
            TotalPackets++;

            try
            {
                var rawCapture = capture.GetPacket();
                var rawPacket = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
                var udpPacket = rawPacket.Extract<UdpPacket>();

                if (udpPacket is null || udpPacket.DestinationPort != NetFlowPort)
                    continue;

                var payload = udpPacket.PayloadData;
                if (payload is null || payload.Length < NetFlowV9Header.HeaderSize)
                    continue;

                if (!_parser.CanParse(payload))
                    continue;

                NetFlowPackets++;

                // Parse on the span — synchronous, no Task overhead
                var packet = _parser.ParsePacket(payload.AsSpan());

                TotalTemplates += packet.Templates.Count;
                TotalFlows += packet.DataRecords.Count;

                // Hand off to consumer (JSON writer) immediately.
                // After this call returns, `packet` is eligible for GC.
                onPacket(packet);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing packet #{Index}", TotalPackets);
            }
        }

        device.Close();

        _logger.LogInformation(
            "PCAP done: {Total} packets, {NetFlow} NetFlow, {Templates} templates, {Flows} flows",
            TotalPackets, NetFlowPackets, TotalTemplates, TotalFlows);
    }
}
