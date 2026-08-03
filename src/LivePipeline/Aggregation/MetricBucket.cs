using System.Collections.Concurrent;
using NetFlowAnalizer.LivePipeline.Models;

namespace NetFlowAnalizer.LivePipeline.Aggregation;

/// <summary>
/// Потокобезопасный аккумулятор метрик за один временной бакет (≈1 секунда).
///
/// ── Zero-String Hot Path ─────────────────────────────────────────────────────
/// Все словари используют uint/byte в качестве ключей — строки IP-адресов
/// НЕ создаются в AccumulateLoopAsync. Конвертация в "192.168.1.1" происходит
/// исключительно при формировании финального снимка (10 IP максимум).
///
/// ── Потокобезопасность ───────────────────────────────────────────────────────
/// — Скалярные счётчики: Interlocked.Add / Increment.
/// — Словари: ConcurrentDictionary с factory-argument перегрузкой AddOrUpdate
///   (не захватывает замыкания — нет heap-аллокаций при вызове).
/// — FlushLoop выполняет Interlocked.Exchange(ref _currentBucket, new()),
///   после чего AccumulateLoop переходит на новый бакет. Крошечное окно гонки
///   (AccumulateLoop может записать ещё 1–2 записи в "старый" бакет)
///   для мониторинга трафика абсолютно приемлемо.
///
/// ── Top-10 без LINQ ──────────────────────────────────────────────────────────
/// TakeSnapshot() вызывает ExtractTop10(), который аллоцирует только
/// Span&lt;long&gt; + Span&lt;uint&gt; на стеке (stackalloc) — никаких List&lt;T&gt;,
/// никакого OrderByDescending().Take(10).
/// </summary>
public sealed class MetricBucket
{
    // ── Scalar counters (lock-free) ───────────────────────────────────────────
    private long _bytes;
    private long _packets;
    private long _flowCount;

    // ── Per-IP dictionaries (uint key = zero string allocations on hot path) ──
    // AddOrUpdate on an existing key is effectively lock-free (CAS loop inside).
    private readonly ConcurrentDictionary<uint, long> _srcIpBytes  = new();
    private readonly ConcurrentDictionary<uint, long> _dstIpBytes  = new();

    // ── Per-protocol dictionaries (byte key, max 256 entries) ────────────────
    private readonly ConcurrentDictionary<byte, long> _protoBytes   = new();
    private readonly ConcurrentDictionary<byte, long> _protoPackets = new();

    // ── Hot-path Add — called by N parser workers ─────────────────────────────

    /// <summary>
    /// Добавляет одну flow-запись в бакет.
    /// Вызывается из AccumulateLoopAsync (единственный consumer Channel 2),
    /// но ConcurrentDictionary корректно обрабатывает конкурентные обновления.
    /// </summary>
    public void Add(in InboundFlowRecord record)
    {
        // ─ Scalar counters ─────────────────────────────────────────────────────
        Interlocked.Add(ref _bytes,   (long)record.Bytes);
        Interlocked.Add(ref _packets, (long)record.Packets);
        Interlocked.Increment(ref _flowCount);

        // ─ Per-SrcIP ───────────────────────────────────────────────────────────
        // Факторные overload-ы AddOrUpdate: ни замыканий, ни heap-аллокаций.
        _srcIpBytes.AddOrUpdate(
            record.SrcAddr,
            static (_, delta) => delta,               // 2. Фабрика добавления: если ключа нет, возвращаем delta
            static (_, old, delta) => old + delta,    // 3. Фабрика обновления: если ключ есть, старое + delta
            (long)record.Bytes                        // 4. Тот самый factoryArgument (передается в обе фабрики как delta)
        );

        // ─ Per-DstIP ───────────────────────────────────────────────────────────
        _dstIpBytes.AddOrUpdate(
            record.DstAddr,
            static (_, delta) => delta,
            static (_, old, delta) => old + delta,
            (long)record.Bytes
        );

        // ─ Per-Protocol ────────────────────────────────────────────────────────
        _protoBytes.AddOrUpdate(
            record.Protocol,
            static (_, delta) => delta,
            static (_, old, delta) => old + delta,
            (long)record.Bytes
        );

        _protoPackets.AddOrUpdate(
            record.Protocol,
            static (_, delta) => delta,
            static (_, old, delta) => old + delta,
            (long)record.Packets
        );
    }

    // ── Reset для повторного использования ──────────────────────────────────────

    /// <summary>
    /// Очищает бакет после TakeSnapshot для повторного использования
    /// (double-buffering в FlushLoopAsync — без <c>new MetricBucket()</c> раз в секунду).
    /// Вызывается ПОСЛЕ TakeSnapshot, когда бакет уже не является "текущим"
    /// (AccumulateLoop пишет в другой экземпляр).
    /// </summary>
    public void Clear()
    {
        Interlocked.Exchange(ref _bytes,     0);
        Interlocked.Exchange(ref _packets,   0);
        Interlocked.Exchange(ref _flowCount, 0);

        _srcIpBytes.Clear();
        _dstIpBytes.Clear();
        _protoBytes.Clear();
        _protoPackets.Clear();
    }

    // ── Snapshot ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Вызывается FlushLoopAsync ПОСЛЕ Interlocked.Exchange — бакет уже "снят"
    /// с горячего пути, AccumulateLoop работает с новым бакетом.
    ///
    /// 1. Атомарно считывает и сбрасывает скалярные счётчики.
    /// 2. Извлекает Top-10 Src и Dst IP через FixedMinHeap на стеке (no LINQ).
    /// 3. Конвертирует uint → "a.b.c.d" строку ТОЛЬКО для итоговых 10 записей.
    /// 4. Собирает все протоколы и сортирует по байтам.
    /// </summary>
    public MetricSnapshot TakeSnapshot(DateTimeOffset now)
    {
        long bytes     = Interlocked.Exchange(ref _bytes,     0);
        long packets   = Interlocked.Exchange(ref _packets,   0);
        long flowCount = Interlocked.Exchange(ref _flowCount, 0);

        return new MetricSnapshot
        {
            Timestamp     = now,
            TotalFlows    = flowCount,
            TotalBytes    = bytes,
            TotalPackets  = packets,
            BitsPerSecond = bytes   * 8.0,
            PacketsPerSec = (double)packets,
            TopSrcIPs     = ExtractTop10(_srcIpBytes),
            TopDstIPs     = ExtractTop10(_dstIpBytes),
            Protocols     = ExtractProtocols(_protoBytes, _protoPackets),
        };
    }

    // ── FixedMinHeap (Top-10) — без LINQ, без heap-аллокаций ─────────────────

    private const int TopN = 10;

    /// <summary>
    /// Проход по словарю с min-heap фиксированного размера 10 на стеке.
    ///
    /// Сложность: O(n log 10) ≈ O(n).
    /// Память: только stackalloc (10 × long + 10 × uint = 120 байт на стеке).
    /// Строки IP создаются ТОЛЬКО для итоговых ≤10 записей.
    /// </summary>
    private static TopIpEntry[] ExtractTop10(ConcurrentDictionary<uint, long> dict)
    {
        if (dict.IsEmpty) return [];

        // Min-heap на стеке: корень = наименьшее значение (которое мы готовы выбросить)
        Span<long> heapVal = stackalloc long[TopN];
        Span<uint> heapKey = stackalloc uint[TopN];
        int size = 0;

        foreach (var kv in dict)
        {
            if (size < TopN)
            {
                heapKey[size] = kv.Key;
                heapVal[size] = kv.Value;
                size++;
                if (size == TopN)
                    BuildMinHeap(heapKey, heapVal, TopN);
            }
            else if (kv.Value > heapVal[0])
            {
                // Новый элемент больше минимума — заменяем корень и просеиваем вниз
                heapKey[0] = kv.Key;
                heapVal[0] = kv.Value;
                SiftDown(heapKey, heapVal, 0, TopN);
            }
        }

        // Сортируем первые `size` элементов по убыванию (selection sort, O(n²) при n≤10)
        for (int i = 0; i < size - 1; i++)
        {
            int maxIdx = i;
            for (int j = i + 1; j < size; j++)
                if (heapVal[j] > heapVal[maxIdx]) maxIdx = j;

            if (maxIdx != i)
            {
                (heapVal[i], heapVal[maxIdx]) = (heapVal[maxIdx], heapVal[i]);
                (heapKey[i], heapKey[maxIdx]) = (heapKey[maxIdx], heapKey[i]);
            }
        }

        // Только здесь конвертируем uint → строку (≤10 вызовов за тик)
        var result = new TopIpEntry[size];
        for (int i = 0; i < size; i++)
            result[i] = new TopIpEntry(Uint32ToIPv4(heapKey[i]), heapVal[i]);

        return result;
    }

    // ── Min-Heap helpers ──────────────────────────────────────────────────────

    private static void BuildMinHeap(Span<uint> keys, Span<long> vals, int n)
    {
        for (int i = n / 2 - 1; i >= 0; i--)
            SiftDown(keys, vals, i, n);
    }

    private static void SiftDown(Span<uint> keys, Span<long> vals, int i, int n)
    {
        while (true)
        {
            int smallest = i;
            int left     = 2 * i + 1;
            int right    = 2 * i + 2;

            if (left  < n && vals[left]  < vals[smallest]) smallest = left;
            if (right < n && vals[right] < vals[smallest]) smallest = right;

            if (smallest == i) break;

            (vals[i], vals[smallest]) = (vals[smallest], vals[i]);
            (keys[i], keys[smallest]) = (keys[smallest], keys[i]);
            i = smallest;
        }
    }

    // ── Protocol extraction ───────────────────────────────────────────────────

    private static ProtocolEntry[] ExtractProtocols(
        ConcurrentDictionary<byte, long> protoBytes,
        ConcurrentDictionary<byte, long> protoPackets)
    {
        if (protoBytes.IsEmpty) return [];

        // Протоколов в трафике обычно < 10 — List аллоцируется раз в секунду, ОК
        var list = new List<ProtocolEntry>(protoBytes.Count);
        foreach (var kv in protoBytes)
        {
            protoPackets.TryGetValue(kv.Key, out long pkts);
            list.Add(new ProtocolEntry(GetProtocolName(kv.Key), kv.Value, pkts));
        }

        list.Sort(static (a, b) => b.Bytes.CompareTo(a.Bytes));
        return [.. list];
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Конвертирует uint (network byte order, big-endian) в "a.b.c.d".
    /// НЕ вызывается в горячем цикле — только для топ-10 записей.
    /// </summary>
    private static string Uint32ToIPv4(uint beAddr) =>
        $"{(beAddr >> 24) & 0xFF}.{(beAddr >> 16) & 0xFF}.{(beAddr >> 8) & 0xFF}.{beAddr & 0xFF}";

    private static string GetProtocolName(byte proto) => proto switch
    {
        1   => "ICMP",
        2   => "IGMP",
        6   => "TCP",
        17  => "UDP",
        47  => "GRE",
        50  => "ESP",
        51  => "AH",
        58  => "IPv6-ICMP",
        89  => "OSPF",
        132 => "SCTP",
        _   => $"Proto-{proto}",
    };
}
