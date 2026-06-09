using System.Threading.Channels;
using Microsoft.Extensions.Options;
using NetFlowAnalizer.LivePipeline.Models;

namespace NetFlowAnalizer.LivePipeline.Pipeline;

/// <summary>
/// Singleton-холдер каналов конвейера.
/// Создаёт оба Channel при старте и предоставляет их зависимым сервисам.
///
/// Зачем отдельный класс, а не регистрировать Channel&lt;T&gt; напрямую?
/// — Позволяет инжектировать один объект вместо двух.
/// — Инкапсулирует конфигурацию BoundedChannelOptions в одном месте.
/// — Упрощает написание тестов (mock одного класса).
/// </summary>
public sealed class PipelineChannels
{
    // ── Channel 1 ────────────────────────────────────────────────────────────
    /// <summary>
    /// Сырые UDP-буферы: NetFlowUdpReceiver → NetFlowParserWorkerPool.
    ///
    /// SingleWriter=true   — только один Receiver пишет.
    /// SingleReader=false  — N воркеров читают конкурентно.
    /// FullMode=Wait       — Receiver ожидает (backpressure),
    ///                       не сбрасывает пакеты молча.
    /// AllowSynchronousContinuations=false — воркеры не продолжают
    ///                       синхронно на потоке Receiver (избегаем stack overflow).
    /// </summary>
    public Channel<RawPacketBuffer> RawPackets { get; }

    // ── Channel 2 ────────────────────────────────────────────────────────────
    /// <summary>
    /// Распарсенные flow-записи: NetFlowParserWorkerPool → NetFlowMetricAggregator.
    ///
    /// SingleWriter=false  — N воркеров пишут конкурентно.
    /// SingleReader=true   — только один Aggregator читает (FIFO-порядок).
    /// FullMode=Wait       — воркеры ждут, пока Aggregator успеет вычитать.
    /// </summary>
    public Channel<InboundFlowRecord> ParsedRecords { get; }

    public PipelineChannels(IOptions<PipelineOptions> options)
    {
        var opts = options.Value;

        RawPackets = Channel.CreateBounded<RawPacketBuffer>(
            new BoundedChannelOptions(opts.RawChannelCapacity)
            {
                FullMode                      = BoundedChannelFullMode.Wait,
                SingleWriter                  = true,
                SingleReader                  = false,
                AllowSynchronousContinuations = false,
            });

        ParsedRecords = Channel.CreateBounded<InboundFlowRecord>(
            new BoundedChannelOptions(opts.ParsedChannelCapacity)
            {
                FullMode                      = BoundedChannelFullMode.Wait,
                SingleWriter                  = false,
                SingleReader                  = true,
                AllowSynchronousContinuations = false,
            });
    }
}
