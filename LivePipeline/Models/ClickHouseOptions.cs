namespace NetFlowAnalizer.LivePipeline.Models;

/// <summary>
/// Конфигурация подключения и батчинга для записи в ClickHouse.
/// Читается из appsettings.json, секция "ClickHouse".
/// </summary>
public sealed class ClickHouseOptions
{
    public const string Section = "ClickHouse";

    /// <summary>Connection string для ClickHouse.Driver (HTTP, порт 8123 по умолчанию).</summary>
    public string ConnectionString { get; set; } = "Host=localhost;Port=8123;Database=netflow";

    /// <summary>Имя таблицы для сырых flow-записей.</summary>
    public string RawTableName { get; set; } = "flows_raw";

    /// <summary>Имя таблицы для минутных трендов.</summary>
    public string TrendsTableName { get; set; } = "flows_trends_1m";

    /// <summary>Размер батча для bulk-insert в flows_raw.</summary>
    public int BatchSize { get; set; } = 50_000;

    /// <summary>Интервал принудительного флаша батча, даже если BatchSize не достигнут.</summary>
    public TimeSpan FlushInterval { get; set; } = TimeSpan.FromSeconds(1);
}
