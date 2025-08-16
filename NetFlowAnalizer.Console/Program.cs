using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core;
using NetFlowAnalizer.Core.Models;
using NetFlowAnalizer.Infrastructure;


	using var host = CreateHostBuilder(args).Build();

	var logger = host.Services.GetRequiredService<ILogger<Program>>();
	logger.LogInformation("NetFlow Analizer starting ...");

	var parser = host.Services.GetRequiredService<INetFlowParser>();
	logger.LogInformation($"Using Parser: v{parser.SupportedVersion}");
try
{
	var netflowPacket = new byte[] { 0x00, 0x09, // v9
		0x00, 0x02, // Count =2
		0x01, 0x23, 0x45, 0x67, // SystemUpTime = 19088743
		0x65, 0x40, 0x2F, 0x0A, // UnuxSeconds = 1699147536 (~2023)
		0x00, 0x00, 0x00, 0x01, // Sequence Number = 1
		0x00, 0x00, 0x00, 0xAB, // Source Id = 171

		// added mock bytes for immitation FlowSet data
		0x00, 0x00, 0x00, 0x08, // FlowSet ID = 8 (Template FlowSet)
		0x00, 0x10, // Length = 16 bytes
		0x01, 0x02, 0x03, 0x04 // Dummy template data
	};

    logger.LogInformation("Testing parser with {PacketSize} byte NetFlow packet", netflowPacket.Length);
	var canParsePacket = parser.CanParse(netflowPacket);
	logger.LogInformation($"CanParse handle packet: {canParsePacket}");

	if (canParsePacket)
	{
		var records = await parser.ParseAsync(netflowPacket);
		var recordList = records.ToList();

		logger.LogInformation($"Parsed {recordList.Count()}");

		foreach (var rec in recordList)
		{
			logger.LogInformation($"Record: {rec}");

			if (rec is NetFlowV9Header header)
			{
                logger.LogInformation("  Version: {Version}", header.Version);
                logger.LogInformation("  Count: {Count}", header.Count);
                logger.LogInformation("  Timestamp: {Timestamp}", header.Timestamp);
                logger.LogInformation("  Source ID: {SourceId}", header.SourceId);
                logger.LogInformation("  Sequence: {Sequence}", header.SequenceNumber);
                logger.LogInformation("  System Uptime: {Uptime} ms", header.SystemUpTime);
            }
		}
	}

	return 0;
}
catch (Exception ex)
{
	logger.LogError(ex, "Error testing parser");
	return 1;
}

static IHostBuilder CreateHostBuilder(string[] args)
{
	return Host.CreateDefaultBuilder(args)
		.ConfigureServices((context, services) =>
		{
			// register our services
			RegisterApplicationServices(services);
		})
		.ConfigureLogging((context, logging) =>
		{
			// Setting logging
			logging.ClearProviders();
			logging.AddConsole();
			logging.SetMinimumLevel(LogLevel.Information);
		});
}

static void RegisterApplicationServices(IServiceCollection services)
{
	// Register parser NetFlow v9
	services.AddSingleton<INetFlowParser, NetFlowV9ParserStub>();
}