using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFlowAnalizer.LivePipeline.Models;

namespace NetFlowAnalizer.LivePipeline.Pipeline;

/// <summary>
/// Фоновый сервис — первое звено конвейера.
///
/// Жизненный цикл:
///   StartAsync  → открывает UDP-сокет
///   ExecuteAsync → цикл ReceiveAsync → арендует буфер → пишет в Channel 1
///   StopAsync   → отменяет токен → закрывает сокет → завершает Channel 1
///
/// Zero-Allocation стратегия:
///   — ArrayPool&lt;byte&gt;.Shared.Rent() для каждого пакета.
///   — Буфер живёт ровно до конца парсинга в воркере (там Return).
///   — Socket.ReceiveAsync(Memory&lt;byte&gt;) не боксирует аргументы.
/// </summary>
public sealed class NetFlowUdpReceiver : BackgroundService
{
    private readonly PipelineChannels         _channels;
    private readonly PipelineOptions          _opts;
    private readonly ILogger<NetFlowUdpReceiver> _log;

    // Статистика (Interlocked, не требует lock)
    private long _totalReceived;
    private long _totalDropped;   // только если канал был бы DropWrite — сейчас не используем

    public long TotalReceived => Volatile.Read(ref _totalReceived);

    public NetFlowUdpReceiver(
        PipelineChannels              channels,
        IOptions<PipelineOptions>     options,
        ILogger<NetFlowUdpReceiver>   logger)
    {
        _channels = channels;
        _opts     = options.Value;
        _log      = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // ── Создаём и настраиваем сокет ──────────────────────────────────────
        using var socket = new Socket(AddressFamily.InterNetwork,
                                      SocketType.Dgram,
                                      ProtocolType.Udp);

        // Увеличиваем системный буфер приёма ядра (SO_RCVBUF).
        // Помогает при burst-трафике, пока парсеры не успевают вычитывать.
        socket.ReceiveBufferSize = 4 * 1024 * 1024; // 4 МБ

        socket.Bind(new IPEndPoint(IPAddress.Any, _opts.UdpPort));
        _log.LogInformation("[Receiver] Listening on UDP :{Port}", _opts.UdpPort);

        var writer = _channels.RawPackets.Writer;

        // ── Основной цикл приёма ─────────────────────────────────────────────
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                // 1. Арендуем буфер из пула — нулевых аллокаций на hot path
                byte[] buffer = ArrayPool<byte>.Shared.Rent(_opts.MaxUdpPacketSize);

                int bytesReceived;
                try
                {
                    // Используем Memory<byte>-перегрузку — без выделения SocketAsyncEventArgs
                    bytesReceived = await socket
                        .ReceiveAsync(buffer.AsMemory(), SocketFlags.None, stoppingToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Нормальное завершение при StopAsync
                    ArrayPool<byte>.Shared.Return(buffer);
                    break;
                }
                catch (SocketException ex)
                {
                    _log.LogWarning(ex, "[Receiver] Socket error, retrying");
                    ArrayPool<byte>.Shared.Return(buffer);
                    continue;
                }

                if (bytesReceived == 0)
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                    continue;
                }

                Interlocked.Increment(ref _totalReceived);

                var descriptor = new RawPacketBuffer(
                    array:              buffer,
                    length:             bytesReceived,
                    timestampUtcTicks:  DateTime.UtcNow.Ticks);

                // 2. Пишем дескриптор в Channel 1.
                //    WriteAsync ждёт (backpressure), если канал заполнен —
                //    пакеты накапливаются в SO_RCVBUF ядра.
                await writer
                    .WriteAsync(descriptor, stoppingToken)
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            // Сигнализируем парсерам, что входных данных больше не будет
            writer.Complete();
            _log.LogInformation(
                "[Receiver] Stopped. Packets received: {Count}", TotalReceived);
        }
    }
}
