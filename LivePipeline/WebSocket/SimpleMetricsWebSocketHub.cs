using System.Collections.Concurrent;
using System.Net.WebSockets;
using Microsoft.Extensions.Logging;

namespace NetFlowAnalizer.LivePipeline.WebSocket;

/// <summary>
/// Простая in-process реализация хаба.
/// Хранит подключённые WebSocket-клиенты в ConcurrentDictionary.
/// При ошибке отправки — автоматически снимает клиента с регистрации.
/// </summary>
public sealed class SimpleMetricsWebSocketHub : IMetricsWebSocketHub
{
    // Используем WebSocket как ключ (ссылочное равенство)
    private readonly ConcurrentDictionary<System.Net.WebSockets.WebSocket, byte> _clients = new();
    private readonly ILogger<SimpleMetricsWebSocketHub> _log;

    public SimpleMetricsWebSocketHub(ILogger<SimpleMetricsWebSocketHub> logger)
        => _log = logger;

    public void Register(System.Net.WebSockets.WebSocket socket)
    {
        _clients.TryAdd(socket, 0);
        _log.LogDebug("[WsHub] Client connected. Total: {Count}", _clients.Count);
    }

    public void Unregister(System.Net.WebSockets.WebSocket socket)
    {
        _clients.TryRemove(socket, out _);
        _log.LogDebug("[WsHub] Client disconnected. Total: {Count}", _clients.Count);
    }

    public async ValueTask BroadcastAsync(ReadOnlyMemory<byte> jsonPayload, CancellationToken ct)
    {
        if (_clients.IsEmpty) return;

        // Рассылаем параллельно всем клиентам
        var tasks = _clients.Keys
            .Select(ws => SendSafeAsync(ws, jsonPayload, ct));

        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task SendSafeAsync(
        System.Net.WebSockets.WebSocket ws,
        ReadOnlyMemory<byte>            payload,
        CancellationToken               ct)
    {
        try
        {
            if (ws.State != WebSocketState.Open) { Unregister(ws); return; }

            await ws.SendAsync(payload, WebSocketMessageType.Text,
                               endOfMessage: true, cancellationToken: ct)
                    .ConfigureAwait(false);
        }
        catch (WebSocketException)
        {
            Unregister(ws);
        }
    }
}
