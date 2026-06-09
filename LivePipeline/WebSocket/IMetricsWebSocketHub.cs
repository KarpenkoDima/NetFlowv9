using System.Net.WebSockets;

namespace NetFlowAnalizer.LivePipeline.WebSocket;

/// <summary>
/// Абстракция WebSocket-хаба для публикации метрик.
/// Реализация может быть:
///   — SimpleMetricsWebSocketHub (встроенная, см. ниже)
///   — SignalR Hub (если понадобится масштабирование)
/// </summary>
public interface IMetricsWebSocketHub
{
    /// <summary>Зарегистрировать подключившегося клиента.</summary>
    void Register(System.Net.WebSockets.WebSocket socket);

    /// <summary>Удалить отключившегося клиента.</summary>
    void Unregister(System.Net.WebSockets.WebSocket socket);

    /// <summary>
    /// Разослать JSON-срез всем подключённым клиентам.
    /// Сериализованный payload передаётся как ReadOnlyMemory&lt;byte&gt;
    /// — нет лишнего копирования строки.
    /// </summary>
    ValueTask BroadcastAsync(ReadOnlyMemory<byte> jsonPayload, CancellationToken ct);
}
