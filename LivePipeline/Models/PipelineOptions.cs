namespace NetFlowAnalizer.LivePipeline.Models;

/// <summary>
/// Конфигурация живого конвейера. Читается из appsettings.json, секция "Pipeline".
/// </summary>
public sealed class PipelineOptions
{
    public const string Section = "Pipeline";

    // ── UDP Receiver ─────────────────────────────────────────────────────────
    /// <summary>UDP-порт для приёма NetFlow-экспорта (стандарт: 2055 или 9995).</summary>
    public int  UdpPort           { get; set; } = 2055;

    /// <summary>
    /// Максимальный размер UDP-датаграммы (байт).
    /// NetFlow v9 не превышает ~1500 байт на роутерах с MTU 1500,
    /// но для джамбо-фреймов ставь 9000+.
    /// </summary>
    public int  MaxUdpPacketSize  { get; set; } = 65_535;

    // ── Channel 1: Raw (UDP → Parser) ─────────────────────────────────────────
    /// <summary>
    /// Ёмкость ограниченного канала сырых буферов.
    /// При заполнении Receiver блокируется (BoundedChannelFullMode.Wait) —
    /// это и есть backpressure: роутер не получит ACK на UDP,
    /// а сокет накапливает пакеты в SO_RCVBUF ядра.
    /// </summary>
    public int  RawChannelCapacity    { get; set; } = 1_024;

    // ── Channel 2: Parsed (Parser → Aggregator) ──────────────────────────────
    /// <summary>
    /// Ёмкость канала распарсенных записей.
    /// Делаем крупнее, т.к. один UDP-пакет порождает N flow-записей.
    /// </summary>
    public int  ParsedChannelCapacity { get; set; } = 16_384;

    // ── Channel 3: Persistence (Aggregator → ClickHouse Writer) ─────────────
    /// <summary>
    /// Ёмкость канала для записей, идущих на персист в ClickHouse.
    /// FullMode=DropWrite — персист best-effort, не блокирует live-метрики.
    /// </summary>
    public int  Channel3Capacity { get; set; } = 100_000;

    // ── Worker Pool ───────────────────────────────────────────────────────────
    /// <summary>
    /// Количество воркеров-парсеров. По умолчанию — число логических ядер.
    /// При CPU-bound парсинге значения > Environment.ProcessorCount бесполезны.
    /// </summary>
    public int  ParserWorkerCount     { get; set; } = Environment.ProcessorCount;

    // ── Aggregator / WebSocket ────────────────────────────────────────────────
    /// <summary>Интервал публикации метрик через WebSocket (мс).</summary>
    public int  MetricFlushIntervalMs { get; set; } = 1_000;

    /// <summary>WebSocket endpoint path.</summary>
    public string WebSocketPath       { get; set; } = "/ws/metrics";
}
