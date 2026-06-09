using NetFlowAnalizer.LivePipeline.Models;

namespace NetFlowAnalizer.LivePipeline.Aggregation;

/// <summary>
/// Потокобезопасный аккумулятор метрик за один временной бакет (секунда / минута).
/// Использует Interlocked — не требует lock на hot path.
/// </summary>
public sealed class MetricBucket
{
    private long _bytes;
    private long _packets;
    private long _flowCount;

    public void Add(in InboundFlowRecord record)
    {
        Interlocked.Add(ref _bytes,   (long)record.Bytes);
        Interlocked.Add(ref _packets, (long)record.Packets);
        Interlocked.Increment(ref _flowCount);
    }

    /// <summary>
    /// Атомарно считывает и сбрасывает счётчики — вызывается Aggregator'ом
    /// в момент публикации среза.
    /// </summary>
    public MetricSnapshot SnapshotAndReset() => new(
        Bytes:     Interlocked.Exchange(ref _bytes,     0),
        Packets:   Interlocked.Exchange(ref _packets,   0),
        FlowCount: Interlocked.Exchange(ref _flowCount, 0));
}

/// <summary>Неизменяемый снимок метрик за период.</summary>
public readonly record struct MetricSnapshot(
    long    Bytes,
    long    Packets,
    long    FlowCount,
    DateTimeOffset Timestamp = default)
{
    public double BitsPerSecond  => Bytes   * 8.0;
    public double PacketsPerSec  => Packets;
    public double FlowsPerSec    => FlowCount;
}
