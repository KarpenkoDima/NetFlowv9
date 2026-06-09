namespace NetFlowAnalizer.LivePipeline.Models;

/// <summary>
/// Единичная flow-запись, распарсенная из NetFlow v9 Data FlowSet.
/// Value-тип (readonly record struct) — не порождает heap-объектов при передаче через Channel.
/// </summary>
public readonly record struct InboundFlowRecord
{
    // ── Адресация ────────────────────────────────────────────────────────────
    public uint   SrcAddr   { get; init; }   // IPv4 BE → host-order
    public uint   DstAddr   { get; init; }   // IPv4 BE → host-order
    public ushort SrcPort   { get; init; }
    public ushort DstPort   { get; init; }
    public byte   Protocol  { get; init; }   // IANA: 6=TCP, 17=UDP, 1=ICMP …

    // ── Объём ────────────────────────────────────────────────────────────────
    public ulong  Bytes     { get; init; }
    public ulong  Packets   { get; init; }

    // ── Временна́я метка ──────────────────────────────────────────────────────
    /// <summary>
    /// Метка из заголовка NetFlow (unix seconds, поле unix_secs).
    /// Если роутер не поддерживает — можно подставить DateTimeOffset.UtcNow.
    /// </summary>
    public DateTimeOffset FlowTimestamp { get; init; }

    // ── Метаданные экспортёра ─────────────────────────────────────────────────
    /// <summary>Source-ID (Observation Domain) из заголовка пакета.</summary>
    public uint   SourceId  { get; init; }

    /// <summary>
    /// Sequence-номер пакета — используется для детектирования потерь.
    /// </summary>
    public uint   SequenceNumber { get; init; }
}
