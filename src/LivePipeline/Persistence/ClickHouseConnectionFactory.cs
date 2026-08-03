using ClickHouse.Driver.ADO;
using Microsoft.Extensions.Options;
using NetFlowAnalizer.LivePipeline.Models;

namespace NetFlowAnalizer.LivePipeline.Persistence;

public sealed class ClickHouseConnectionFactory : IClickHouseConnectionFactory
{
    public const string HttpClientName = "ClickHouse";

    private readonly string _connectionString;
    private readonly IHttpClientFactory _httpClientFactory;

    public ClickHouseConnectionFactory(
        IOptions<ClickHouseOptions> options,
        IHttpClientFactory httpClientFactory)
    {
        _connectionString  = options.Value.ConnectionString;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<ClickHouseConnection> CreateOpenConnectionAsync(CancellationToken ct)
    {
        // IHttpClientFactory keeps the underlying SocketsHttpHandler/connection pool
        // alive across calls — without it, ClickHouseConnection(string) creates a
        // brand-new HttpClient+handler per flush (every 1s/1min), exhausting sockets
        // and generating significant GC pressure.
        var connection = new ClickHouseConnection(_connectionString, _httpClientFactory, HttpClientName);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        return connection;
    }
}
