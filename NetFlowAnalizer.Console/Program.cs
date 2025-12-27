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
    Console.WriteLine("NetFlow Analyzer v9");
    Console.WriteLine();
    Console.WriteLine("Usage: NetFlowAnalizer.Console <pcapFilePath>");
    Console.WriteLine();
    Console.WriteLine("Example:");
    Console.WriteLine("  NetFlowAnalizer.Console /path/to/netflow_data.pcap");
    Console.WriteLine();
    Console.WriteLine("The tool will:");
    Console.WriteLine("  1. Parse NetFlow v9 packets from the PCAP file");
    Console.WriteLine("  2. Export results to JSON file (same name as PCAP with .json extension)");
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
logger.LogInformation("=== NetFlow Analyzer v9 ===");
logger.LogInformation("Input PCAP: {PcapPath}", pcapFilePath);
logger.LogInformation("Output JSON: {JsonPath}", jsonOutputPath);

try
{
    // Get services
    var parser = host.Services.GetRequiredService<INetFlowParser>();
    var pcapReader = host.Services.GetRequiredService<NetFlowPcapReader>();
    var jsonExporter = host.Services.GetRequiredService<NetFlowJsonExporter>();

    logger.LogInformation("Using NetFlow Parser v{Version}", parser.SupportedVersion);

    // Read PCAP file
    logger.LogInformation("Starting PCAP processing...");
    await pcapReader.ReadAsync(pcapFilePath);

    var allRecords = pcapReader.AllRecords;
    var headers = pcapReader.GetHeaders().ToList();
    var templates = pcapReader.GetTemplates().ToList();
    var dataRecords = pcapReader.GetDataRecords().ToList();

    logger.LogInformation("=== Parsing Results ===");
    logger.LogInformation("Total records: {Total}", allRecords.Count);
    logger.LogInformation("  Headers: {Count}", headers.Count);
    logger.LogInformation("  Templates: {Count}", templates.Count);
    logger.LogInformation("  Data records (flows): {Count}", dataRecords.Count);

    if (headers.Any())
    {
        logger.LogInformation("");
        logger.LogInformation("=== Sample Headers ===");
        foreach (var header in headers.Take(3))
        {
            logger.LogInformation("  {Header}", header);
        }
    }

    if (templates.Any())
    {
        logger.LogInformation("");
        logger.LogInformation("=== Templates ===");
        foreach (var template in templates)
        {
            logger.LogInformation("  Template ID: {TemplateId}, Fields: {FieldCount}, Record Length: {RecordLength} bytes",
                template.TemplateId, template.Fields.Count, template.RecordLength);
        }
    }

    if (dataRecords.Any())
    {
        logger.LogInformation("");
        logger.LogInformation("=== Sample Flow Records ===");
        foreach (var record in dataRecords.Take(5))
        {
            logger.LogInformation("  Flow (Template {TemplateId}):", record.TemplateId);
            foreach (var kvp in record.Values.Take(8))
            {
                logger.LogInformation("    {Key}: {Value}", kvp.Key, kvp.Value);
            }
        }
    }

    // Export to JSON
    logger.LogInformation("");
    logger.LogInformation("Exporting results to JSON...");
    await jsonExporter.ExportToJsonAsync(allRecords, jsonOutputPath);

    logger.LogInformation("");
    logger.LogInformation("=== SUCCESS ===");
    logger.LogInformation("Results saved to: {JsonPath}", jsonOutputPath);
    logger.LogInformation("You can now open view/index.html and load the JSON file for visualization");

    return 0;
}
catch (Exception ex)
{
    logger.LogError(ex, "Error processing NetFlow data");
    return 1;
}

static IHostBuilder CreateHostBuilder(string[] args)
{
    return Host.CreateDefaultBuilder(args)
        .ConfigureServices((context, services) =>
        {
            RegisterApplicationServices(services);
        })
        .ConfigureLogging((context, logging) =>
        {
            logging.ClearProviders();
            logging.AddConsole();
            logging.SetMinimumLevel(LogLevel.Information);
        });
}

static void RegisterApplicationServices(IServiceCollection services)
{
    // Register NetFlow services
    services.AddSingleton<ITemplateCache, TemplateCache>();
    services.AddSingleton<INetFlowParser, NetFlowV9Parser>();
    services.AddSingleton<NetFlowPcapReader>();
    services.AddSingleton<NetFlowJsonExporter>();
}
