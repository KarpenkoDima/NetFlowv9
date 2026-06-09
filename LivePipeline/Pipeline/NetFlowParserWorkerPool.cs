using System.Buffers;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFlowAnalizer.LivePipeline.Models;

namespace NetFlowAnalizer.LivePipeline.Pipeline;

/// <summary>
/// Фоновый сервис — второе звено конвейера.
///
/// Запускает N параллельных воркеров (Task.Run на ThreadPool).
/// Каждый воркер:
///   1. Читает RawPacketBuffer из Channel 1.
///   2. Парсит заголовок NetFlow v9 и FlowSets через Span&lt;byte&gt; (TODO).
///   3. Пишет InboundFlowRecord(s) в Channel 2.
///   4. Возвращает byte[] в ArrayPool&lt;byte&gt;.Shared — ОБЯЗАТЕЛЬНО в finally.
///
/// Параллелизм:
///   — Channel&lt;RawPacketBuffer&gt; с SingleReader=false безопасен для N читателей.
///   — Каждый воркер держит свой локальный List&lt;InboundFlowRecord&gt; и пишет
///     пачкой, чтобы минимизировать число await WriteAsync.
///
/// Завершение:
///   — Когда Receiver вызывает writer.Complete(), ChannelReader.ReadAllAsync
///     отдаёт оставшиеся элементы и бросает ChannelClosedException.
///   — Воркер ловит это, выходит из цикла, и сервис дожидается всех Task.
/// </summary>
public sealed class NetFlowParserWorkerPool : BackgroundService
{
    private readonly PipelineChannels                _channels;
    private readonly PipelineOptions                 _opts;
    private readonly ILogger<NetFlowParserWorkerPool> _log;

    // TODO: инжектировать INetFlowV9Parser (твой существующий NetFlowV9Parser)
    // private readonly INetFlowParser _parser;

    public NetFlowParserWorkerPool(
        PipelineChannels                   channels,
        IOptions<PipelineOptions>          options,
        ILogger<NetFlowParserWorkerPool>   logger)
    {
        _channels = channels;
        _opts     = options.Value;
        _log      = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _log.LogInformation(
            "[ParserPool] Starting {Count} worker(s)", _opts.ParserWorkerCount);

        // Запускаем N воркеров параллельно
        var workers = Enumerable
            .Range(0, _opts.ParserWorkerCount)
            .Select(id => Task.Run(() => RunWorkerAsync(id, stoppingToken), stoppingToken))
            .ToArray();

        try
        {
            await Task.WhenAll(workers).ConfigureAwait(false);
        }
        finally
        {
            // Все воркеры завершились — закрываем Channel 2 для Aggregator
            _channels.ParsedRecords.Writer.Complete();
            _log.LogInformation("[ParserPool] All workers stopped.");
        }
    }

    // ── Один воркер ──────────────────────────────────────────────────────────

    private async Task RunWorkerAsync(int workerId, CancellationToken ct)
    {
        var reader = _channels.RawPackets.Reader;
        var writer = _channels.ParsedRecords.Writer;

        _log.LogDebug("[ParserPool] Worker {Id} started", workerId);

        // ReadAllAsync — lazy async enumerable; завершается, когда Channel закрыт
        await foreach (var buffer in reader.ReadAllAsync(ct).ConfigureAwait(false))
        {
            // КРИТИЧНО: Return буфера в пул должен быть в finally,
            // чтобы не было утечки даже при исключении в парсере.
            try
            {
                await ParseAndDispatchAsync(buffer, writer, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogWarning(ex,
                    "[ParserPool] Worker {Id}: parse error, packet dropped", workerId);
            }
            finally
            {
                // Возвращаем байтовый массив в пул — только ЗДЕСЬ, после того,
                // как ParseAndDispatchAsync уже не обращается к buffer.Array
                ArrayPool<byte>.Shared.Return(buffer.Array);
            }
        }

        _log.LogDebug("[ParserPool] Worker {Id} finished", workerId);
    }

    // ── Парсинг одного пакета ─────────────────────────────────────────────────

    private static async ValueTask ParseAndDispatchAsync(
        RawPacketBuffer           buffer,
        ChannelWriter<InboundFlowRecord> writer,
        CancellationToken         ct)
    {
        // ── TODO: Здесь будет реальный парсинг ────────────────────────────────
        //
        // Шаблон использования существующего NetFlowV9Parser:
        //
        //   ReadOnlySpan<byte> span = buffer.Span;
        //
        //   // 1. Распарсить заголовок (20 байт)
        //   var result = _parser.TryParseHeader(span, out var header);
        //   if (!result.IsSuccess) return;
        //
        //   // 2. Обойти FlowSets
        //   int offset = 20;
        //   while (offset < buffer.Length)
        //   {
        //       var fsResult = _parser.TryParseFlowSet(span[offset..], header, out var records);
        //       if (!fsResult.IsSuccess) break;
        //       foreach (var record in records)
        //           await writer.WriteAsync(record, ct).ConfigureAwait(false);
        //       offset += fsResult.Value.FlowSetLength;
        //   }
        //
        // ─────────────────────────────────────────────────────────────────────

        // Stub: эмулируем одну запись для проверки конвейера
        var stub = new InboundFlowRecord
        {
            SrcAddr        = 0xC0A80101, // 192.168.1.1
            DstAddr        = 0x08080808, // 8.8.8.8
            SrcPort        = 54321,
            DstPort        = 443,
            Protocol       = 6,          // TCP
            Bytes          = (ulong)buffer.Length,
            Packets        = 1,
            FlowTimestamp  = DateTimeOffset.FromFileTime(buffer.TimestampUtcTicks),
            SourceId       = 0,
            SequenceNumber = 0,
        };

        await writer.WriteAsync(stub, ct).ConfigureAwait(false);
    }
}
