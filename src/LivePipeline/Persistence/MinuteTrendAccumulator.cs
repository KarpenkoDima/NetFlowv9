namespace NetFlowAnalizer.LivePipeline.Persistence;

/// <summary>
/// Накапливает per-second MetricSnapshot'ы в течение текущей календарной минуты
/// для записи одной строки в flows_trends_1m.
///
/// Не потокобезопасен — используется только из FlushLoop в NetFlowMetricAggregator
/// (тот же поток, что вызывает TakeSnapshot раз в секунду).
/// </summary>
public sealed class MinuteTrendAccumulator
{
    private long   _totalFlows;
    private long   _totalBytes;
    private long   _totalPackets;
    private double _bpsSum;
    private double _ppsSum;
    private int    _sampleCount;
    private DateTimeOffset _minuteStart;

    public MinuteTrendAccumulator(DateTimeOffset now)
    {
        _minuteStart = FloorToMinute(now);
    }

    private static DateTimeOffset FloorToMinute(DateTimeOffset ts) =>
        new(ts.Year, ts.Month, ts.Day, ts.Hour, ts.Minute, 0, ts.Offset);

    /// <summary>
    /// Добавляет очередной секундный снимок. Если снимок относится к новой
    /// календарной минуте, возвращает завершённую строку для предыдущей минуты
    /// (и сбрасывает аккумулятор для новой), иначе — null.
    /// </summary>
    public TrendRow? AddSnapshotAndMaybeRoll(
        DateTimeOffset now, long totalFlows, long totalBytes, long totalPackets,
        double bitsPerSecond, double packetsPerSec)
    {
        var minute = FloorToMinute(now);

        TrendRow? completed = null;
        if (minute != _minuteStart && _sampleCount > 0)
        {
            completed = BuildRow();
            Reset(minute);
        }
        else if (minute != _minuteStart)
        {
            // Не было ни одного сэмпла в предыдущей минуте — просто сдвигаем окно.
            Reset(minute);
        }

        _totalFlows   += totalFlows;
        _totalBytes   += totalBytes;
        _totalPackets += totalPackets;
        _bpsSum       += bitsPerSecond;
        _ppsSum       += packetsPerSec;
        _sampleCount++;

        return completed;
    }

    private TrendRow BuildRow() => new(
        Timestamp:     _minuteStart,
        TotalFlows:    _totalFlows,
        TotalBytes:    _totalBytes,
        TotalPackets:  _totalPackets,
        BitsPerSecond: _sampleCount > 0 ? _bpsSum / _sampleCount : 0,
        PacketsPerSec: _sampleCount > 0 ? _ppsSum / _sampleCount : 0);

    private void Reset(DateTimeOffset minute)
    {
        _minuteStart  = minute;
        _totalFlows   = 0;
        _totalBytes   = 0;
        _totalPackets = 0;
        _bpsSum       = 0;
        _ppsSum       = 0;
        _sampleCount  = 0;
    }
}

/// <summary>Одна строка для таблицы flows_trends_1m.</summary>
public readonly record struct TrendRow(
    DateTimeOffset Timestamp,
    long   TotalFlows,
    long   TotalBytes,
    long   TotalPackets,
    double BitsPerSecond,
    double PacketsPerSec);
