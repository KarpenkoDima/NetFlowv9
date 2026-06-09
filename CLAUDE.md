Перед тобой точка входа моего проекта на .NET 9. Я хочу переписать этот инструмент на обработку живого трафика по сети через высокопроизводительный конвейер (Zero-Allocation Pipeline).

Используя структуру проекта, спроектируй сквозной конвейер на System.Threading.Channels, состоящий из трех связанных BackgroundService:
1. NetFlowUdpReceiver: Фоновый сервис. Слушает UDP-порт через низкоуровневый Socket.ReceiveAsync(Memory<byte>). Арендует буферы из ArrayPool<byte>.Shared, пишет их в Bounded Channel 1 (используй структуру-дескриптор, хранящую ссылку на массив и реальную длину пакета).
2. NetFlowParserWorkerPool: Пул воркеров (Task.Run), который параллельно вычитывает пакеты из Channel 1, парсит заголовок и FlowSets, и пишет распарсенные записи во второй Bounded Channel 2 (Channel<InboundFlowRecord>). После парсинга воркер возвращает массив байт обратно в ArrayPool.
3. NetFlowMetricAggregator: Читает записи из Channel 2, аккумулирует их в памяти (минутные/секундные бакеты) и готовит JSON-срез для отправки на дашборд по WebSocket раз в 1 секунду.

Покажи архитектурный скелет этих трех служб и то, как правильно настроить Dependency Injection (DI) в Program.cs с учетом конфигурации Bounded-каналов и стратегий Backpressure (BoundedChannelFullMode.Wait). Код самого парсера писать пока не нужно.