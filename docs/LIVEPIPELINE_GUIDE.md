# LivePipeline: руководство по разработке live-конвейера NetFlow v9

> Этот документ — продолжение [`GUIDE.md`](GUIDE.md). `GUIDE.md` рассказывает, как был
> построен offline-анализатор `NetFlowAnalizer` (PCAP → парсер → JSON-экспорт,
> Clean Architecture, 20 глав). Здесь — история и архитектура **второго приложения
> в этом репозитории**: `LivePipeline`, живого UDP-конвейера NetFlow v9 с
> ClickHouse-персистом, live-дашбордом на WebSocket и Grafana-дашбордами.
>
> Если `NetFlowAnalizer` отвечает на вопрос «как разобрать .pcap-файл с NetFlow»,
> то `LivePipeline` отвечает на вопрос «как принимать NetFlow в реальном времени,
> 24/7, без сборщика мусора на горячем пути, и показывать живую картину трафика».

---

## Часть 1. Зачем отдельное приложение

`NetFlowAnalizer` — offline-инструмент: открыл .pcap, распарсил, посчитал
агрегаты, сохранил JSON. Для живого UDP-потока с роутера такая модель не
годится:

- Пакеты приходят непрерывно, 24/7, без паузы «конец файла».
- Нагрузка может быть нестабильной (вспышки трафика) — нужен backpressure.
- Нужна метрика «прямо сейчас» (bps/pps за последнюю секунду), а не только
  итоговый отчёт.
- Нужно куда-то складывать историю — чтобы строить графики за час/день/неделю.

Поэтому `LivePipeline` — отдельный ASP.NET Core проект внутри того же решения,
переиспользующий из `NetFlowAnalizer.Core` только то, что не зависит от файлов:
модель `TemplateRecord`/`TemplateField`, `ITemplateCache` и сам принцип
структуры NetFlow v9 (RFC 3954). Всё, что касается ввода-вывода — написано с
нуля под требование **zero-allocation на горячем пути**.

Хронология (см. `git log`):

1. `01e852d` — каркас Pipeline создан коллегой (3 BackgroundService + Channels).
2. `442edfa` … `03e6204` — статические файлы и первый live-дашборд (Chart.js
   поверх WebSocket).
3. `ed6a295` / `3e42442` / `e8d6bac` … `dc94779` — спека и реализация
   ClickHouse-персиста (схема, Channel 3, batched writer, connection factory).
4. `8e64240`, `9fb7527`, `b9a9dab` — реальный парсер NetFlow v9 заведён в пул
   воркеров, исправлены имена параметров вставки, настроен dev-пользователь
   ClickHouse.
5. `9dd1af8`, `671ec18`, `461db90`, `7b64c22`, `f10ca0e`, `ee71f6c` —
   оптимизации: per-IP/per-protocol снапшоты, фикс WebSocketException,
   пул HttpClient + gzip, double-buffering бакетов, пул `object[]` строк для
   ClickHouse-вставки.
6. `f081c09` … `89db31c` — спека, план и реализация Grafana-дашбордов поверх
   ClickHouse.

---

## Часть 2. Архитектура конвейера

```
 [UDP-сокет :2055]
       │  Socket.ReceiveFromAsync(Memory<byte>)
       │  ArrayPool<byte>.Shared.Rent()
       ▼
┌─────────────────────────────┐
│  NetFlowUdpReceiver          │  BackgroundService #1 (single writer)
└─────────────┬─────────────────┘
              │ Channel<RawPacketBuffer>   Bounded(1024), FullMode=Wait
              ▼
┌─────────────────────────────┐
│  NetFlowParserWorkerPool     │  BackgroundService #2 (N воркеров, Task.Run)
│  LiveNetFlowV9Parser          │  ArrayPool.Return() здесь
└─────────────┬─────────────────┘
              │ Channel<InboundFlowRecord>  Bounded(16384), FullMode=Wait
              ▼
┌─────────────────────────────┐
│  NetFlowMetricAggregator     │  BackgroundService #3 (single reader)
│  MetricBucket (double-buffer) │
└──────┬──────────────────┬────┘
       │ JSON / 1с          │ Channel<InboundFlowRecord> Bounded, FullMode=DropWrite
       ▼                    ▼
 WebSocket /ws/metrics  ┌─────────────────────────────┐
 (live-дашборд)         │  NetFlowClickHouseWriter     │  BackgroundService #4
                         │  batched bulk insert          │
                         └──────────────┬────────────────┘
                                         ▼
                                    ClickHouse
                              (flows_raw, flows_trends_1m)
                                         │
                                         ▼
                                     Grafana
```

Все четыре сервиса регистрируются как `IHostedService` в `Program.cs` и
запускаются практически одновременно — это нормально: каждый блокируется на
`await channel.Reader.ReadAsync()` до прихода первых данных.

### 2.1. Почему именно Channels, а не очередь + блокировки

`System.Threading.Channels` даёт готовый producer/consumer с поддержкой:

- **Bounded-вместимости** — ограничивает память, если потребитель не успевает.
- **`BoundedChannelFullMode`** — явная стратегия поведения при заполнении
  (вместо «тихого» `OutOfMemoryException` от неограниченной очереди).
- **Множественных читателей/писателей** без ручных `lock`.
- **`async`/`await`**-нативного API — не нужны спин-локи или `Monitor.Wait`.

### 2.2. Три канала, три стратегии backpressure

Стратегии заданы в `LivePipeline/Pipeline/PipelineChannels.cs`:

| Канал | Тип | Capacity | SingleWriter | SingleReader | FullMode | Почему |
|---|---|---|---|---|---|---|
| Channel 1 — `RawPackets` | `RawPacketBuffer` | 1024 | true | false | `Wait` | Receiver один; если воркеры не успевают — Receiver ждёт. Потеря пакетов происходит на уровне UDP/`SO_RCVBUF`, а не молча в приложении. |
| Channel 2 — `ParsedRecords` | `InboundFlowRecord` | 16384 | false | true | `Wait` | N воркеров пишут; агрегатор должен увидеть **все** записи (иначе метрики/история разойдутся), поэтому ждём. |
| Channel 3 — `RawFlowsForPersistence` | `InboundFlowRecord` | конфигурируемая | true | true | `DropWrite` | Персист — **best-effort**. Если ClickHouse временно недоступен/тормозит, живые метрики (Channel 2 → WebSocket) НЕ должны вставать. Лишние записи отбрасываются, счётчик потерь ведёт писатель. |

Это сознательная асимметрия: для «горячих» данных (живые графики) гарантируется
доставка (`Wait`), для «холодных» (история в БД) — best-effort (`DropWrite`).
Если нужна гарантированная доставка в ClickHouse, путь — увеличить
`Channel3Capacity` и/или добавить отдельный durable-буфер (вне рамок этого
проекта).

```csharp
RawPackets = Channel.CreateBounded<RawPacketBuffer>(new BoundedChannelOptions(opts.RawChannelCapacity)
{
    FullMode = BoundedChannelFullMode.Wait,
    SingleWriter = true,
    SingleReader = false,
    AllowSynchronousContinuations = false,
});

RawFlowsForPersistence = Channel.CreateBounded<InboundFlowRecord>(new BoundedChannelOptions(opts.Channel3Capacity)
{
    FullMode = BoundedChannelFullMode.DropWrite,
    SingleWriter = true,
    SingleReader = true,
    AllowSynchronousContinuations = false,
});
```

`AllowSynchronousContinuations = false` везде — продолжения (`await` после
`ReadAsync`/`WriteAsync`) выполняются на пуле потоков, а не синхронно на потоке
писателя. Это защищает от стека вызовов «писатель → читатель → писатель → …»
и от блокировки Receiver-а кодом агрегатора.

---

## Часть 3. Звено 1 — `NetFlowUdpReceiver`

Задача: как можно быстрее забрать байты из сокета и передать дальше, не
аллоцируя на каждый пакет.

```csharp
public sealed class NetFlowUdpReceiver : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Any, _options.UdpPort));

        while (!stoppingToken.IsCancellationRequested)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(MaxUdpPacketSize);
            int received = await socket.ReceiveAsync(buffer.AsMemory(), SocketFlags.None, stoppingToken);

            var packet = new RawPacketBuffer(buffer, received, DateTime.UtcNow.Ticks);
            await _channels.RawPackets.Writer.WriteAsync(packet, stoppingToken);
        }
    }
}
```

Ключевые решения:

- **`Socket.ReceiveAsync(Memory<byte>)`** напрямую, без `UdpClient` — меньше
  слоёв абстракции, контроль над буфером.
- **`ArrayPool<byte>.Shared.Rent`** — буфер берётся из пула, а не `new byte[]`
  на каждый пакет. Возврат (`Return`) происходит позже, в звене 2, **после**
  того как парсер прочитал данные.
- **`RawPacketBuffer`** — structs-дескриптор `{ byte[] Array, int Length, long TimestampUtcTicks }`.
  Передаётся по значению через канал — никакого дополнительного `new` для
  «обёртки» пакета.
- Если `Channel 1` заполнен (`Wait`), `WriteAsync` асинхронно ждёт — это
  естественным образом замедляет `ReceiveAsync`, и ядро ОС начинает копить
  пакеты в `SO_RCVBUF` (а не приложение в управляемой куче).

---

## Часть 4. Звено 2 — `NetFlowParserWorkerPool`

Задача: распараллелить разбор пакетов (CPU-bound), вернуть буферы в пул,
наполнить Channel 2.

```csharp
public sealed class NetFlowParserWorkerPool : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var workers = Enumerable.Range(0, _options.ParserWorkerCount)
            .Select(_ => Task.Run(() => WorkerLoopAsync(stoppingToken), stoppingToken));

        await Task.WhenAll(workers);
    }

    private async Task WorkerLoopAsync(CancellationToken ct)
    {
        var outputBuf = new InboundFlowRecord[LiveNetFlowV9Parser.MaxRecordsPerPacket];

        await foreach (var packet in _channels.RawPackets.Reader.ReadAllAsync(ct))
        {
            try
            {
                int count = _parser.TryParseRecords(
                    packet.Span, packet.TimestampUtcTicks, outputBuf);

                for (int i = 0; i < count; i++)
                    await _channels.ParsedRecords.Writer.WriteAsync(outputBuf[i], ct);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(packet.Array);
            }
        }
    }
}
```

Почему `Task.Run`, а не `Parallel.ForEachAsync`/PLINQ:

- Channel `ReadAllAsync` — это async-стрим; каждый воркер просто крутит свой
  `await foreach` независимо. `SingleReader=false` на Channel 1 явно разрешает
  N конкурентных читателей — Channel сам решает балансировку.
- `Task.Run` + `Task.WhenAll` даёт простое управление жизненным циклом: при
  отмене `ct` все воркеры синхронно завершаются, `ExecuteAsync` дожидается их.

Парсер — `LiveNetFlowV9Parser` (`LivePipeline/Parsers/LiveNetFlowV9Parser.cs`,
318 строк) — **stateless** (singleton), а состояние шаблонов NetFlow живёт в
`ITemplateCache` (тоже singleton, thread-safe через `lock` внутри). Это
позволяет N воркерам безопасно делить один и тот же парсер и кэш.

Главный приём zero-allocation в парсере — **запись результатов прямо в
`Span<InboundFlowRecord>`**, переданный воркером:

```csharp
public int TryParseRecords(ReadOnlySpan<byte> data, long receivedAtTicks, Span<InboundFlowRecord> outputBuf)
```

- Заголовок (20 байт) читается через `BinaryPrimitives.ReadXxxBigEndian` — без
  промежуточных структур.
- Каждая запись из Data FlowSet — это `struct InboundFlowRecord`, который
  пишется напрямую в `outputBuf[written++]` — value-type copy, без кучи.
- Единственное допустимое выделение — `TemplateRecord`/`TemplateField[]` при
  получении **нового** Template FlowSet (ID=0). Это происходит редко (при
  старте экспортёра/переподключении) и кэшируется навсегда в
  `ITemplateCache`.

Таблица поддерживаемых полей NetFlow v9 (RFC 3954 §8), используемых парсером:

| Type | Поле | Размер |
|---|---|---|
| 1 | IN_BYTES | 4 или 8 байт |
| 2 | IN_PKTS | 4 или 8 байт |
| 4 | PROTOCOL | 1 байт |
| 7 | L4_SRC_PORT | 2 байта |
| 8 | IPV4_SRC_ADDR | 4 байта |
| 11 | L4_DST_PORT | 2 байта |
| 12 | IPV4_DST_ADDR | 4 байта |

Остальные типы полей пропускаются (`fieldOffset` сдвигается на `fLength`, без
чтения) — конвейер не падает на «незнакомых» полях, просто игнорирует их.

---

## Часть 5. Звено 3 — `NetFlowMetricAggregator`

Задача: копить статистику по входящим записям, раз в секунду отдавать JSON
через WebSocket, и попутно — отправлять каждую запись в Channel 3 для
персиста.

### 5.1. Double-buffering вместо аллокаций каждую секунду (`f10ca0e`)

Изначальная (наивная) реализация создавала бы новый `MetricBucket` каждую
секунду — мусор на GC при стабильно высокой частоте flow-записей.
Вместо этого `MetricBucket` **переиспользуется**:

```csharp
private MetricBucket _active = new();
private MetricBucket _flushing = new();

private void Accumulate(in InboundFlowRecord record)
{
    _active.Add(in record);
}

private async Task FlushLoopAsync(CancellationToken ct)
{
    while (await _timer.WaitForNextTickAsync(ct))
    {
        // Меняем местами буферы — O(1), без аллокаций.
        (_active, _flushing) = (_flushing, _active);

        var json = BuildSnapshotJson(_flushing);
        await _hub.BroadcastAsync(json, ct);

        _flushing.Reset();   // очищаем накопители для следующего цикла
    }
}
```

Пока идёт сериализация и broadcast `_flushing`-бакета, `_active` уже принимает
новые записи — нет блокировки на время отправки JSON.

### 5.2. Zero-copy JSON через `Utf8JsonWriter`

`MetricJsonContext`/`MetricSnapshot` сериализуются напрямую в
`IBufferWriter<byte>` через `Utf8JsonWriter` — без промежуточного
`string`/`byte[]` для каждого снапшота. Итоговый `ReadOnlyMemory<byte>`
передаётся в `IMetricsWebSocketHub.BroadcastAsync`, который шлёт его всем
подключённым WebSocket-клиентам через `SendAsync`.

### 5.3. Fan-out в Channel 3 (персист, `5ebddfb`)

Каждая запись, попавшая в `Accumulate`, дополнительно (best-effort) пишется в
`RawFlowsForPersistence`:

```csharp
if (!_channels.RawFlowsForPersistence.Writer.TryWrite(record))
{
    Interlocked.Increment(ref _droppedForPersistence);
}
```

`TryWrite` (не `await WriteAsync`!) — синхронная неблокирующая попытка. Если
канал полон (`DropWrite`), `TryWrite` возвращает `false`, запись теряется, но
**аггрегатор не блокируется** — живые метрики продолжают идти в WebSocket без
задержки.

### 5.4. Минутные тренды (`5ebddfb`, `MinuteTrendAccumulator`)

Параллельно с секундными бакетами аггрегатор ведёт **минутный накопитель**
(`MinuteTrendAccumulator`): при смене минуты он формирует строку для таблицы
`flows_trends_1m` (TotalFlows, TotalBytes, TotalPackets, BitsPerSecond,
PacketsPerSec) и тоже отправляет её через Channel 3 (как отдельный тип записи
/ через тот же конвейер персиста — в зависимости от реализации писателя).
Это та таблица, на которой строится Grafana-панель «Bps/Pps».

---

## Часть 6. Звено 4 — `NetFlowClickHouseWriter`

Добавлено отдельной спекой/планом (`3e42442`, `7ad85d4`) и серией коммитов
`3cb5a01` … `ee71f6c`.

### 6.1. Зачем отдельный сервис, а не писать прямо из аггрегатора

- Сетевой I/O в ClickHouse — это latency, которая не должна влиять на
  WebSocket-цикл (1 раз/сек).
  Разделение по Channel 3 даёт естественную изоляцию: медленный ClickHouse →
  растёт только Channel 3, остальной конвейер не замечает.
- `NetFlowClickHouseWriter` сам решает, **когда** флашить (по таймеру и/или по
  накоплению N строк) — батчинг снижает число round-trip-ов к БД.

### 6.2. Connection factory + пул HttpClient (`461db90`, `7b64c22`)

`ClickHouse.Driver` создаёт `ClickHouseConnection` на базе `HttpClient`.
Изначально на каждый flush создавался новый `HttpClient` → новый
`SocketsHttpHandler` → новый пул сокетов → TCP-хендшейки каждую секунду.
Исправлено через `IHttpClientFactory`:

```csharp
builder.Services
    .AddHttpClient(ClickHouseConnectionFactory.HttpClientName)
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AutomaticDecompression = DecompressionMethods.All,
    });

builder.Services.AddSingleton<IClickHouseConnectionFactory, ClickHouseConnectionFactory>();
```

`AutomaticDecompression = DecompressionMethods.All` — обязателен: ClickHouse
по умолчанию отвечает gzip-сжатым телом, а `SocketsHttpHandler` без этой
настройки отдаёт сырые сжатые байты драйверу, который падает с
`InvalidOperationException` при чтении заголовков ответа (`7b64c22`).

`IClickHouseConnectionFactory.CreateConnection()` создаёт новый
`ClickHouseConnection` **на каждый flush** (драйвер не thread-safe для
конкуррентного использования одного соединения), но переиспользует
`HttpClient`/`SocketsHttpHandler` через фабрику — TCP-соединения у пула живут
между вызовами (keep-alive).

### 6.3. Пул `object[]`-строк (`ee71f6c`)

`ClickHouseBulkCopy` принимает `IEnumerable<object[]>` — по одному `object[]`
на строку. При батче в тысячи flow-записей это тысячи аллокаций `object[]` +
boxing каждого `uint`/`ulong`/`byte` поля на каждый flush. Решение —
переиспользуемый пул `object[]`-массивов фиксированного размера (по числу
колонок), которые заполняются заново на каждый batch и возвращаются после
вставки. Boxing самих значений (`uint` → `object`) остаётся неизбежным из-за
сигнатуры `ClickHouseBulkCopy`, но аллокации контейнеров — нет.

### 6.4. Схема ClickHouse (`clickhouse-init/001-schema.sql`, `e8d6bac`)

```sql
CREATE TABLE flows_raw (
    Timestamp   DateTime CODEC(DoubleDelta, ZSTD(1)),
    SrcIp       UInt32,
    DstIp       UInt32,
    SrcPort     UInt16,
    DstPort     UInt16,
    Protocol    UInt8,
    Bytes       UInt64,
    Packets     UInt64,
    SourceId    UInt32,
    SequenceNumber UInt32
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(Timestamp)
ORDER BY (Timestamp, SrcIp, DstIp)
TTL Timestamp + INTERVAL 14 DAY;

CREATE TABLE flows_trends_1m (
    Timestamp     DateTime,
    TotalFlows    UInt64,
    TotalBytes    UInt64,
    TotalPackets  UInt64,
    BitsPerSecond Float64,
    PacketsPerSec Float64
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(Timestamp)
ORDER BY Timestamp;
```

- `DoubleDelta` + `ZSTD(1)` на `Timestamp` в `flows_raw` — временные метки
  растущей последовательности сжимаются почти до нуля; критично, учитывая,
  что `flows_raw` пишет каждую отдельную flow-запись (десятки тысяч строк/сек
  при высокой нагрузке).
- `PARTITION BY toYYYYMMDD` + `TTL 14 DAY` — старые партиции целиком удаляются
  ClickHouse фоном, без построчного `DELETE`.
- `flows_trends_1m` — низкая кардинальность (1 строка/минуту), партиционирована
  по месяцу, без спец-кодеков — на этой таблице строится панель Bps/Pps.

> **Важно про время**: `DateTime` в ClickHouse хранит «наивные» Unix-секунды —
> никакой информации о часовом поясе в самой колонке нет. Если сервер ClickHouse
> и приложение пишут UTC (`DateTimeOffset.UtcNow`/`flowTimestamp` из парсера —
> UTC), а Grafana должна показывать локальное время, datasource нужно явно
> сказать, что хранимые значения — UTC (`jsonData.timezone: UTC` в
> `grafana/provisioning/datasources/clickhouse.yml`), иначе график окажется
> смещён на разницу с локальным поясом.

---

## Часть 7. Live-дашборд (WebSocket + Chart.js)

Самый первый UI конвейера (`ed6a295`, `71e9e78`, `03e6204`, `442edfa`):

- `app.UseDefaultFiles()` + `app.UseStaticFiles()` — отдаёт `wwwroot/index.html`
  и `wwwroot/app.js` как статику (никакого SPA-фреймворка).
- `app.UseWebSockets(...)` + `app.Map("/ws/metrics", ...)` — единственный
  кастомный endpoint, принимает WebSocket-подключения и регистрирует их в
  `SimpleMetricsWebSocketHub`.
- `SimpleMetricsWebSocketHub` хранит список живых `WebSocket`-соединений;
  `NetFlowMetricAggregator` раз в секунду вызывает `BroadcastAsync(jsonBytes)`
  — хаб итерируется по списку и шлёт байты каждому клиенту.
- На клиенте — `app.js` открывает `new WebSocket('ws://.../ws/metrics')`,
  на каждое сообщение обновляет графики Chart.js (bps/pps во времени,
  топ источников/портов — в зависимости от состава `MetricSnapshot`).
- `671ec18` — фикс: при разрыве соединения клиентом (закрытие вкладки,
  обновление страницы) `ws.SendAsync`/`ReceiveAsync` бросали необработанный
  `WebSocketException`, валивший фоновую задачу. Исправлено добавлением
  `catch (WebSocketException)`/`catch (OperationCanceledException)` вокруг
  цикла обработки соединения в `Program.cs` — обрыв клиента теперь штатное
  завершение, а не падение.

Эта пара (хаб + endpoint) намеренно отделена интерфейсом
`IMetricsWebSocketHub` — `Program.cs` явно комментирует, что для масштабирования
на несколько инстансов сервиса реализацию можно заменить на SignalR с Redis
backplane, не трогая `NetFlowMetricAggregator`.

---

## Часть 8. DI и конфигурация (`Program.cs`)

Порядок регистрации в `Program.cs` отражает порядок зависимостей:

```csharp
// 1. Опции с валидацией при старте — приложение не поднимется
//    с некорректным конфигом (например, UdpPort = 0).
builder.Services.AddOptions<PipelineOptions>()
    .Bind(builder.Configuration.GetSection(PipelineOptions.Section))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddOptions<ClickHouseOptions>()
    .Bind(builder.Configuration.GetSection(ClickHouseOptions.Section))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// 2. Парсер + кэш шаблонов — singleton, переживают весь жизненный цикл хоста.
builder.Services.AddSingleton<ITemplateCache, TemplateCache>();
builder.Services.AddSingleton<LiveNetFlowV9Parser>();

// 3. HttpClient-фабрика + ClickHouse connection factory.
builder.Services.AddHttpClient(ClickHouseConnectionFactory.HttpClientName)
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AutomaticDecompression = DecompressionMethods.All,
    });
builder.Services.AddSingleton<IClickHouseConnectionFactory, ClickHouseConnectionFactory>();

// 4. Каналы — singleton, единый источник Channel 1/2/3 для всех сервисов.
builder.Services.AddSingleton<PipelineChannels>();

// 5. WebSocket-хаб — интерфейс, чтобы агрегатор не знал о транспорте.
builder.Services.AddSingleton<IMetricsWebSocketHub, SimpleMetricsWebSocketHub>();

// 6. Четыре BackgroundService — порядок регистрации = порядок старта.
builder.Services.AddHostedService<NetFlowUdpReceiver>();
builder.Services.AddHostedService<NetFlowParserWorkerPool>();
builder.Services.AddHostedService<NetFlowMetricAggregator>();
builder.Services.AddHostedService<NetFlowClickHouseWriter>();
```

`appsettings.json`:

```json
{
  "Pipeline": {
    "UdpPort": 2055,
    "RawChannelCapacity": 1024,
    "ParsedChannelCapacity": 16384,
    "Channel3Capacity": 8192,
    "ParserWorkerCount": 8,
    "MetricFlushIntervalMs": 1000,
    "WebSocketPath": "/ws/metrics"
  },
  "ClickHouse": {
    "ConnectionString": "Host=localhost;Port=8123;Database=netflow;User=default;Password=",
    "BatchSize": 1000,
    "FlushIntervalMs": 1000
  }
}
```

---

## Часть 9. Стек Grafana (наблюдаемость поверх ClickHouse)

Реализован спекой/планом `f081c09`/`33ba76a` и коммитами `efd5b67` →
`89db31c`.

### 9.1. docker-compose

`efd5b67` добавляет сервис `grafana` в `docker-compose.yml` рядом с
`netflow-clickhouse`:

```yaml
grafana:
  image: grafana/grafana:11.5.0
  container_name: netflow-grafana
  ports:
    - "3000:3000"
  environment:
    GF_AUTH_ANONYMOUS_ENABLED: "true"
    GF_AUTH_ANONYMOUS_ORG_ROLE: "Admin"
    GF_INSTALL_PLUGINS: "grafana-clickhouse-datasource"
  volumes:
    - ./grafana/provisioning:/etc/grafana/provisioning
    - grafana-data:/var/lib/grafana
  depends_on:
    - clickhouse
```

Анонимный admin-доступ — осознанное упрощение для локальной разработки (не для
прода).

### 9.2. Provisioning datasource (`d8915e0`)

`grafana/provisioning/datasources/clickhouse.yml` — декларативная регистрация
ClickHouse как datasource при старте контейнера (без ручной настройки через
UI):

```yaml
apiVersion: 1
datasources:
  - name: ClickHouse
    type: grafana-clickhouse-datasource
    access: proxy
    isDefault: true
    jsonData:
      host: clickhouse
      port: 8123
      protocol: http
      defaultDatabase: netflow
      timezone: UTC
```

### 9.3. Provisioning дашбордов (`b0d080b`)

`grafana/provisioning/dashboards/dashboards.yml` указывает Grafana подхватывать
JSON-файлы дашбордов из примонтированной директории — любой `.json`-файл там
автоматически появляется в UI после рестарта контейнера, без импорта руками.

### 9.4. Дашборд «NetFlow Traffic» (`89db31c`)

Три панели, все запросы — к `flows_trends_1m`/`flows_raw`:

1. **Bps/Pps (timeseries)** — `BitsPerSecond` и `PacketsPerSec` из
   `flows_trends_1m` за выбранный диапазон. Это прямой результат минутных
   тренд-строк, которые шлёт `MinuteTrendAccumulator`.
2. **Summary (stat tiles)** — агрегаты (`sum`/`avg`) по тому же
   `flows_trends_1m` за диапазон — суммарный трафик, средние bps/pps.
3. **Top 10 Destination Ports (table)** — `SELECT DstPort, sum(Bytes), sum(Packets)
   FROM flows_raw WHERE Timestamp >= $__fromTime AND Timestamp <= $__toTime
   GROUP BY DstPort ORDER BY sum(Bytes) DESC LIMIT 10` — прямой запрос к
   построчным данным `flows_raw`.

---

## Часть 10. Нагрузочное тестирование

Полный конвейер (UDP → Channels → ClickHouse → Grafana) был проверен
синтетическим генератором NetFlow v9, который:

1. Шлёт **Template FlowSet** (TemplateId=256, 7 полей: `IPV4_SRC_ADDR`,
   `IPV4_DST_ADDR`, `L4_SRC_PORT`, `L4_DST_PORT`, `PROTOCOL`, `IN_BYTES`,
   `IN_PKTS`, RecordLength=21 байт) на `udp://127.0.0.1:2055` —
   повторяя её каждые 500 пакетов (некоторые реальные экспортёры тоже
   периодически пере-шлют шаблон).
2. Шлёт **Data FlowSet**-пакеты по 20 записей каждый: случайные `SrcIp`
   (`10.0.0.x`), фиксированный `DstIp` (`10.0.1.x`), случайный `SrcPort`,
   `DstPort=443`, `Protocol=6` (TCP), случайные `Bytes` (64–1500) и `Packets`
   (1–10).
3. Работает 90 секунд, отправляя пакеты в цикле с микро-паузой каждые 1000
   пакетов (throttle, чтобы не насыщать localhost loopback мгновенно).

За 90 секунд генератор отправил ~5.7 млн пакетов, что после парсинга дало
~200 000 строк в `flows_raw` — этого достаточно, чтобы все три панели Grafana
отрисовали реальные кривые, а не пустые графики.

Структура пакета в коде генератора (для справки, при необходимости повторить
тест):

```
Header (20 байт, Big-Endian):
  Version=9, Count, SysUptime, UnixSecs, SequenceNumber, SourceId=1

Template FlowSet (ID=0):
  FlowSetId=0, Length, TemplateId=256, FieldCount=7
  [Type=8,Len=4]  IPV4_SRC_ADDR
  [Type=12,Len=4] IPV4_DST_ADDR
  [Type=7,Len=2]  L4_SRC_PORT
  [Type=11,Len=2] L4_DST_PORT
  [Type=4,Len=1]  PROTOCOL
  [Type=1,Len=4]  IN_BYTES
  [Type=2,Len=4]  IN_PKTS

Data FlowSet (ID=256):
  FlowSetId=256, Length
  20 × [SrcIp(4) DstIp(4) SrcPort(2) DstPort(2)=443 Proto(1)=6 Bytes(4) Pkts(4)]  // 21 байт/запись
```

---

## Часть 11. Запуск всего стека

```powershell
# 1. ClickHouse + Grafana
docker compose up -d clickhouse grafana

# 2. Live-конвейер (UDP-приёмник, WebSocket, ClickHouse-писатель)
dotnet run --project LivePipeline/LivePipeline.csproj

# 3. (опционально) синтетическая нагрузка для проверки
dotnet run --project <путь к synload>
```

После старта:

- Live-дашборд (WebSocket): `http://localhost:5000/` (или порт из
  `launchSettings.json`).
- Grafana: `http://localhost:3000/` (анонимный admin) → дашборд
  «NetFlow Traffic».
- ClickHouse HTTP-интерфейс: `http://localhost:8123/`.

---

## Часть 12. Карта проекта

```
LivePipeline/
├── Program.cs                         — DI, конфигурация Channels, WebSocket middleware
├── Aggregation/
│   ├── MetricBucket.cs                — секундный накопитель (double-buffered)
│   ├── MetricSnapshot.cs              — снимок для JSON
│   └── MetricJsonContext.cs           — Utf8JsonWriter сериализация
├── Models/
│   ├── PipelineOptions.cs             — конфиг Channel-ов и воркеров
│   ├── ClickHouseOptions.cs           — конфиг подключения/батчинга
│   ├── RawPacketBuffer.cs             — дескриптор {byte[], Length, Ticks}
│   └── InboundFlowRecord.cs           — value-type распарсенной записи
├── Parsers/
│   └── LiveNetFlowV9Parser.cs         — zero-allocation парсер RFC 3954
├── Pipeline/
│   ├── PipelineChannels.cs            — Channel 1/2/3 + BoundedChannelOptions
│   ├── NetFlowUdpReceiver.cs           — звено 1
│   ├── NetFlowParserWorkerPool.cs      — звено 2
│   └── NetFlowMetricAggregator.cs      — звено 3
├── Persistence/
│   ├── IClickHouseConnectionFactory.cs / ClickHouseConnectionFactory.cs
│   ├── MinuteTrendAccumulator.cs       — минутные тренды → flows_trends_1m
│   └── NetFlowClickHouseWriter.cs      — звено 4, батч-вставка с retry/drop
├── WebSocket/
│   ├── IMetricsWebSocketHub.cs
│   └── SimpleMetricsWebSocketHub.cs
└── wwwroot/                            — live-дашборд (HTML + Chart.js)

clickhouse-init/001-schema.sql          — flows_raw, flows_trends_1m
grafana/provisioning/
├── datasources/clickhouse.yml          — ClickHouse datasource (timezone: UTC)
└── dashboards/                          — file-provider + NetFlow Traffic.json
docker-compose.yml                      — clickhouse + grafana сервисы

docs/superpowers/specs/                 — спеки: live-dashboard, clickhouse-persistence, grafana-dashboards
docs/superpowers/plans/                 — планы реализации к этим спекам
```

---

## Итог

`LivePipeline` демонстрирует сквозной паттерн «приём → парсинг → агрегация →
вывод/персист» на `System.Threading.Channels`, где:

- каждое звено — отдельный `BackgroundService` с собственным жизненным циклом;
- горячий путь (приём UDP → парсинг → секундные метрики) не аллоцирует на
  управляемой куче за счёт `ArrayPool`, `Span<T>`, value-type записей и
  double-buffering;
- персист в ClickHouse изолирован отдельным каналом с `DropWrite`
  backpressure — медленная БД не может замедлить живые метрики;
- наблюдаемость поверх накопленной истории строится на готовом стеке
  (ClickHouse + Grafana с provisioning), без написания собственного UI для
  исторических графиков.

Дальнейшие шаги, не реализованные в этом репозитории, но логично
продолжающие архитектуру: горизонтальное масштабирование WebSocket-хаба через
SignalR/Redis backplane, durable-буфер для Channel 3 (чтобы персист был не
best-effort), метрики самого приложения (GC, latency каналов) через
OpenTelemetry → тот же Grafana.
