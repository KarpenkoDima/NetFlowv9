namespace NetFlowAnalizer.LivePipeline.Aggregation;

// ─────────────────────────────────────────────────────────────────────────────
// Эти типы намеренно являются классами, а не readonly struct/record struct,
// потому что System.Text.Json Source Generation требует изменяемые свойства
// с публичным сеттером (или init) и ссылочный тип для сложных графов объектов.
// ─────────────────────────────────────────────────────────────────────────────

/// <summary>
/// Полный JSON-срез метрик за один тик (1 секунда).
/// Отправляется клиентам по WebSocket через IMetricsWebSocketHub.
///
/// JSON-контракт (camelCase):
/// {
///   "timestamp":    "2026-06-09T12:00:00Z",
///   "totalFlows":   12345,
///   "totalBytes":   98765432,
///   "totalPackets": 54321,
///   "bitsPerSecond": 790123456.0,
///   "packetsPerSec": 54321.0,
///   "topSrcIPs": [{"ip":"192.168.1.1","bytes":1234567},...],
///   "topDstIPs": [{"ip":"8.8.8.8","bytes":9876543},...],
///   "protocols":  [{"name":"TCP","bytes":8765432,"packets":43210},...]
/// }
/// </summary>
public sealed class MetricSnapshot
{
    public DateTimeOffset  Timestamp     { get; init; }

    /// <summary>Количество flow-записей за секунду.</summary>
    public long            TotalFlows    { get; init; }

    /// <summary>Суммарный объём трафика за секунду (байт).</summary>
    public long            TotalBytes    { get; init; }

    /// <summary>Суммарное число пакетов за секунду.</summary>
    public long            TotalPackets  { get; init; }

    /// <summary>Трафик в битах в секунду (TotalBytes × 8).</summary>
    public double          BitsPerSecond { get; init; }

    /// <summary>Пакетов в секунду.</summary>
    public double          PacketsPerSec { get; init; }

    /// <summary>Топ-10 Source IP по объёму байт — отсортировано по убыванию.</summary>
    public TopIpEntry[]    TopSrcIPs     { get; init; } = [];

    /// <summary>Топ-10 Destination IP по объёму байт — отсортировано по убыванию.</summary>
    public TopIpEntry[]    TopDstIPs     { get; init; } = [];

    /// <summary>Все наблюдённые протоколы за секунду — отсортировано по убыванию байт.</summary>
    public ProtocolEntry[] Protocols     { get; init; } = [];
}

/// <summary>Один элемент топа IP-адресов.</summary>
public sealed class TopIpEntry
{
    /// <summary>IP-адрес в dotted-decimal ("192.168.1.1").</summary>
    public string Ip    { get; init; } = string.Empty;

    /// <summary>Суммарный объём байт за секунду.</summary>
    public long   Bytes { get; init; }

    public TopIpEntry() { }

    public TopIpEntry(string ip, long bytes) { Ip = ip; Bytes = bytes; }
}

/// <summary>Статистика одного протокола.</summary>
public sealed class ProtocolEntry
{
    /// <summary>Название протокола ("TCP", "UDP", "ICMP", ...).</summary>
    public string Name    { get; init; } = string.Empty;

    /// <summary>Суммарный объём байт за секунду.</summary>
    public long   Bytes   { get; init; }

    /// <summary>Суммарное число пакетов за секунду.</summary>
    public long   Packets { get; init; }

    public ProtocolEntry() { }

    public ProtocolEntry(string name, long bytes, long packets)
    {
        Name    = name;
        Bytes   = bytes;
        Packets = packets;
    }
}
