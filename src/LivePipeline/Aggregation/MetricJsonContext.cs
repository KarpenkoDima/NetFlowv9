using System.Text.Json.Serialization;

namespace NetFlowAnalizer.LivePipeline.Aggregation;

/// <summary>
/// Source Generation JSON-контекст (.NET 9).
///
/// Зачем?
///   — Полностью исключает рефлексию в сериализаторе.
///   — Код сериализации генерируется компилятором на основе атрибутов.
///   — JsonSerializer.Serialize(writer, snap, MetricJsonContext.Default.MetricSnapshot)
///     работает без рефлексии и не аллоцирует обёрток.
///
/// Настройки:
///   — CamelCase → поля JSON совпадают с именами в app.js (timestamp, totalFlows, ...)
///   — WriteIndented = false → компактный JSON для WebSocket
///   — DefaultIgnoreCondition = WhenWritingNull → не пишем null-поля
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy         = JsonKnownNamingPolicy.CamelCase,
    WriteIndented                = false,
    DefaultIgnoreCondition       = JsonIgnoreCondition.WhenWritingNull,
    GenerationMode               = JsonSourceGenerationMode.Serialization)]
[JsonSerializable(typeof(MetricSnapshot))]
[JsonSerializable(typeof(TopIpEntry))]
[JsonSerializable(typeof(ProtocolEntry))]
[JsonSerializable(typeof(TopIpEntry[]))]
[JsonSerializable(typeof(ProtocolEntry[]))]
internal sealed partial class MetricJsonContext : JsonSerializerContext;
