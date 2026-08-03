namespace NetFlowAnalizer.LivePipeline.Models;

/// <summary>
/// Структура-дескриптор арендованного буфера UDP-пакета.
/// Хранит ссылку на массив из ArrayPool и реальную длину принятых данных.
/// Владелец обязан вернуть Array в ArrayPool после обработки.
/// </summary>
public readonly struct RawPacketBuffer
{
    /// <summary>Арендованный массив из ArrayPool&lt;byte&gt;.Shared.</summary>
    public readonly byte[] Array;

    /// <summary>Реальное количество байт, записанных в Array (≤ Array.Length).</summary>
    public readonly int Length;

    /// <summary>Время приёма пакета (UTC) — заполняется один раз в Receiver.</summary>
    public readonly long TimestampUtcTicks;

    public RawPacketBuffer(byte[] array, int length, long timestampUtcTicks)
    {
        Array = array;
        Length = length;
        TimestampUtcTicks = timestampUtcTicks;
    }

    /// <summary>Slice данных без выделения памяти.</summary>
    public ReadOnlySpan<byte> Span => Array.AsSpan(0, Length);

    /// <summary>Slice данных без выделения памяти (Memory-вариант для async).</summary>
    public ReadOnlyMemory<byte> Memory => Array.AsMemory(0, Length);
}
