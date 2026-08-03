using ClickHouse.Driver.ADO;

namespace NetFlowAnalizer.LivePipeline.Persistence;

/// <summary>
/// Фабрика подключений к ClickHouse. Каждый вызов создаёт новое
/// (открытое) соединение — ClickHouseConnection не потокобезопасен
/// для конкурентного использования, поэтому каждый writer держит своё.
/// </summary>
public interface IClickHouseConnectionFactory
{
    Task<ClickHouseConnection> CreateOpenConnectionAsync(CancellationToken ct);
}
