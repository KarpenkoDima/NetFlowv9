using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core;
using NetFlowAnalizer.Core.Services;
using NetFlowAnalizer.Infrastructure.Export;
using NetFlowAnalizer.Infrastructure.Parsers;
using NetFlowAnalizer.Infrastructure.Readers;
using NetFlowAnalizer.Infrastructure.Services;

if (args.Length < 1)
{
    Console.WriteLine("NetFlow Analyzer v9 (High-Performance Edition)");
    Console.WriteLine();
    Console.WriteLine("Usage: NetFlowAnalizer.Console <pcapFilePath>");
    Console.WriteLine();
    Console.WriteLine("Features:");
    Console.WriteLine("  - Zero-copy parsing via Span<byte> + BinaryPrimitives");
    Console.WriteLine("  - Streaming JSON export via Utf8JsonWriter");
    Console.WriteLine("  - O(1) memory — handles multi-GB PCAP files");
    return 1;
}

string pcapFilePath = args[0];

if (!File.Exists(pcapFilePath))
{
    Console.WriteLine($"Error: File not found: {pcapFilePath}");
    return 1;
}

string jsonOutputPath = Path.ChangeExtension(pcapFilePath, ".json");

using var host = CreateHostBuilder(args).Build();

var logger = host.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("=== NetFlow Analyzer v9 (High-Performance) ===");
logger.LogInformation("Input PCAP: {PcapPath}", pcapFilePath);
logger.LogInformation("Output JSON: {JsonPath}", jsonOutputPath);

try
{
    var reader = host.Services.GetRequiredService<NetFlowPcapReader>();
    var exporter = host.Services.GetRequiredService<NetFlowJsonExporter>();

    // --- Streaming pipeline ---
    //
    // 1. Open JSON file, write preamble
    // 2. For each PCAP packet:
    //      parse(Span) → NetFlowPacket → Utf8JsonWriter → flush → GC
    // 3. Write templates + close JSON
    //
    // Memory usage: ~50 MB regardless of PCAP size.

    exporter.BeginExport(jsonOutputPath);

    reader.Process(pcapFilePath, packet =>
    {
        exporter.WritePacket(in packet);
    });

    exporter.EndExport();

    // Print summary
    logger.LogInformation("");
    logger.LogInformation("=== RESULTS ===");
    logger.LogInformation("Total packets scanned: {Total}", reader.TotalPackets);
    logger.LogInformation("NetFlow v9 packets:    {NetFlow}", reader.NetFlowPackets);
    logger.LogInformation("Templates found:       {Templates}", reader.TotalTemplates);
    logger.LogInformation("Flow records:          {Flows}", reader.TotalFlows);
    logger.LogInformation("");
    logger.LogInformation("=== SUCCESS ===");
    logger.LogInformation("Results saved to: {JsonPath}", jsonOutputPath);
    logger.LogInformation("Open view/index.html and load the JSON file for visualization");

    return 0;
}
catch (Exception ex)
{
    logger.LogError(ex, "Error processing NetFlow data");
    return 1;
}
finally
{
    // Ensure exporter file handles are released
    var exporter = host.Services.GetService<NetFlowJsonExporter>();
    exporter?.Dispose();
}

static IHostBuilder CreateHostBuilder(string[] args)
{
    return Host.CreateDefaultBuilder(args)
        .ConfigureServices((_, services) =>
        {
            services.AddSingleton<ITemplateCache, TemplateCache>();
            services.AddSingleton<INetFlowParser, NetFlowV9Parser>();
            services.AddSingleton<NetFlowPcapReader>();
            services.AddSingleton<NetFlowJsonExporter>();
        })
        .ConfigureLogging((_, logging) =>
        {
            logging.ClearProviders();
            logging.AddConsole();
            logging.SetMinimumLevel(LogLevel.Information);
        });
}
