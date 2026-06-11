using NetFlowAnalizer.Infrastructure.Services;
using NetFlowAnalizer.Core.Services;
using NetFlowAnalizer.LivePipeline.Aggregation;
using NetFlowAnalizer.LivePipeline.Models;
using NetFlowAnalizer.LivePipeline.Parsers;
using NetFlowAnalizer.LivePipeline.Persistence;
using NetFlowAnalizer.LivePipeline.Pipeline;
using NetFlowAnalizer.LivePipeline.WebSocket;

// ═══════════════════════════════════════════════════════════════════════════
//  NetFlow Live Pipeline — точка входа
//  Архитектура:
//
//   [UDP Socket]
//       │  ArrayPool<byte>.Rent()
//       ▼
//  ┌─────────────────────────────┐
//  │   NetFlowUdpReceiver        │  BackgroundService #1
//  │   (single writer)           │
//  └─────────────┬───────────────┘
//                │  Channel<RawPacketBuffer>  ← Bounded(1024), Wait
//                │  backpressure → SO_RCVBUF ядра
//                ▼
//  ┌─────────────────────────────┐
//  │  NetFlowParserWorkerPool    │  BackgroundService #2
//  │  (N readers, Task.Run)      │  ArrayPool.Return() здесь ↩
//  └─────────────┬───────────────┘
//                │  Channel<InboundFlowRecord>  ← Bounded(16384), Wait
//                ▼
//  ┌─────────────────────────────┐
//  │  NetFlowMetricAggregator    │  BackgroundService #3
//  │  (single reader)            │
//  └─────────────┬───────────────┘
//                │  JSON (Utf8JsonWriter, zero-copy)
//                ▼
//         WebSocket /ws/metrics
// ═══════════════════════════════════════════════════════════════════════════

var builder = WebApplication.CreateBuilder(args);

// ── 1. Конфигурация конвейера из appsettings.json ─────────────────────────
//
//   appsettings.json:
//   {
//     "Pipeline": {
//       "UdpPort": 2055,
//       "RawChannelCapacity": 1024,
//       "ParsedChannelCapacity": 16384,
//       "ParserWorkerCount": 8,
//       "MetricFlushIntervalMs": 1000,
//       "WebSocketPath": "/ws/metrics"
//     }
//   }

builder.Services
    .AddOptions<PipelineOptions>()
    .Bind(builder.Configuration.GetSection(PipelineOptions.Section))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// ── 2. Парсер и кэш шаблонов ─────────────────────────────────────────────
//
// TemplateCache — потокобезопасный (lock внутри) singleton: все N воркеров
// пишут/читают шаблоны через один экземпляр.
// LiveNetFlowV9Parser — stateless (кэш инжектируется), singleton.

builder.Services.AddSingleton<ITemplateCache, TemplateCache>();
builder.Services.AddSingleton<LiveNetFlowV9Parser>();

// ── 2b. ClickHouse-персистентность ────────────────────────────────────────
//
// ClickHouseOptions — конфигурация подключения и батчинга (appsettings.json,
// секция "ClickHouse"). ClickHouseConnectionFactory создаёт по соединению на
// каждый flush (ClickHouseConnection не потокобезопасен для конкуррентного
// использования). NetFlowClickHouseWriter — четвёртый BackgroundService,
// best-effort consumer Channel 3.

builder.Services
    .AddOptions<ClickHouseOptions>()
    .Bind(builder.Configuration.GetSection(ClickHouseOptions.Section))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddSingleton<IClickHouseConnectionFactory, ClickHouseConnectionFactory>();
builder.Services.AddHostedService<NetFlowClickHouseWriter>();

// ── 4. Инфраструктура каналов ─────────────────────────────────────────────
//
// PipelineChannels — singleton, создаётся один раз при старте.
// Содержит оба Bounded Channel с настроенными BoundedChannelOptions.
// Все три BackgroundService получают его через конструктор.

builder.Services.AddSingleton<PipelineChannels>();

// ── 5. WebSocket-хаб ─────────────────────────────────────────────────────
//
// SimpleMetricsWebSocketHub хранит список подключённых клиентов.
// Aggregator инжектирует IMetricsWebSocketHub и не знает о конкретной реализации.
// Для масштабирования замени на SignalR без изменений в Aggregator.

builder.Services.AddSingleton<IMetricsWebSocketHub, SimpleMetricsWebSocketHub>();

// ── 4. BackgroundService'ы — три звена конвейера ─────────────────────────
//
// Порядок регистрации = порядок старта (IHostedService).
// Важно: все три сервиса стартуют почти одновременно — это нормально,
// т.к. они блокируются на пустых Channel до первых данных.

builder.Services.AddHostedService<NetFlowUdpReceiver>();       // Звено 1
builder.Services.AddHostedService<NetFlowParserWorkerPool>();  // Звено 2
builder.Services.AddHostedService<NetFlowMetricAggregator>();  // Звено 3

// ── 5. Опционально: метрики и health-checks ───────────────────────────────
// builder.Services.AddHealthChecks();
// builder.Services.AddOpenTelemetry()...

var app = builder.Build();

// ── 6. WebSocket middleware ───────────────────────────────────────────────
//
// Должен идти ДО UseRouting / MapControllers.
// KeepAliveInterval — пинг для детектирования разрывов.

// ── 5b. Статические файлы (live-дашборд) ──────────────────────────────────
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseWebSockets(new WebSocketOptions
{
    KeepAliveInterval = TimeSpan.FromSeconds(30),
});

// ── 7. WebSocket endpoint ─────────────────────────────────────────────────
//
// Клиент подключается к ws://<host>/ws/metrics
// и получает JSON-срез каждые MetricFlushIntervalMs мс.

var wsPath = builder.Configuration
    .GetValue<string>($"{PipelineOptions.Section}:WebSocketPath")
    ?? "/ws/metrics";

app.Map(wsPath, async context =>
{
    if (!context.WebSockets.IsWebSocketRequest)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        return;
    }

    var hub = context.RequestServices.GetRequiredService<IMetricsWebSocketHub>();
    var ws  = await context.WebSockets.AcceptWebSocketAsync();

    hub.Register(ws);

    // Держим соединение открытым, пока клиент не отключится
    try
    {
        var buf = new byte[64];
        var ct  = context.RequestAborted;
        while (ws.State == System.Net.WebSockets.WebSocketState.Open)
        {
            var result = await ws.ReceiveAsync(buf.AsMemory(), ct);
            if (result.MessageType == System.Net.WebSockets.WebSocketMessageType.Close)
                await ws.CloseAsync(
                    System.Net.WebSockets.WebSocketCloseStatus.NormalClosure,
                    "Bye", ct);
        }
    }
    finally
    {
        hub.Unregister(ws);
    }
});

// ── 8. Health endpoint (опционально) ─────────────────────────────────────
// app.MapHealthChecks("/health");

app.Run();
