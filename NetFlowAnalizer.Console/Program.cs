using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetFlowAnalizer.Core;
using NetFlowAnalizer.Infrastructure;

try
{
	using var host = CreateHostBuilder(args).Build();

	var logger = host.Services.GetRequiredService<ILogger<Program>>();
	logger.LogInformation("NetFlow Analizer starting ...");

	var parser = host.Services.GetRequiredService<INetFlowParser>();
	logger.LogInformation($"Using Parser: v{parser.SupportedVersion}");

	var testData = new byte[] { 0x00, 0x09 }; // v9
	var canParse = parser.CanParse(testData);
	logger.LogInformation($"Can parse test data:{canParse}");

	logger.LogInformation("NetFlow Analizer completed successfully");
	return 0;
}
catch (Exception ex)
{
	System.Console.WriteLine($"Fatal error: {ex.Message}");
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