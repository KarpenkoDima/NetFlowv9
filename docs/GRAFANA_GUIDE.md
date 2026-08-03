# Grafana для NetFlow — практическое руководство

## Как всё устроено

В стеке два источника визуализации:

| URL | Что показывает | Хранение |
|---|---|---|
| `localhost:5000` | Живые метрики последней секунды — bps, pps, flow count. Данные исчезают при рестарте. | В памяти (MetricBucket) |
| `localhost:3000` | Исторические данные за любой период. Можно смотреть что было вчера или час назад. | ClickHouse (flows_raw, flows_trends_1m) |

Для аналитики — всегда Grafana на `localhost:3000`. Дашборд открывается без пароля (anonymous admin).

---

## Готовый дашборд «NetFlow Traffic»

При запуске `docker compose up` Grafana автоматически загружает три панели из `infra/grafana/dashboards/`:

| Панель | Таблица | Что видно |
|---|---|---|
| Bps / Pps | `flows_trends_1m` | Биты в секунду и пакеты в секунду — тайм-серия |
| Summary | `flows_trends_1m` | Суммарные потоки, байты, пакеты за выбранный период |
| Top 10 Dst Ports | `flows_raw` | Порты назначения по объёму трафика |

> **Данных нет?** Убедись, что RouterOS отправляет NetFlow: IP → Traffic Flow → Targets должен содержать адрес хоста с Docker и порт `2055`.

---

## Создать новую панель — шаг за шагом

1. **Открой дашборд** — `localhost:3000` → NetFlow Traffic
2. **Add → Visualization** — кнопка в верхнем меню дашборда
3. **Выбери тип панели** (правая колонка) — Time series, Stat, Table, Bar chart
4. **Напиши SQL-запрос** внизу редактора — datasource ClickHouse уже выбран
5. **Run query → Apply** — увидишь данные; затем **Save dashboard**

> Кнопка **Discard** в редакторе отменяет все изменения без сохранения.

---

## Типы панелей

| Тип | Когда использовать |
|---|---|
| **Time series** | График во времени. Нужен столбец `time` и числовые столбцы. |
| **Stat** | Одно большое число. Запрос возвращает одну строку, одно поле. |
| **Bar chart** | Сравнение категорий: Top N IP, порты по трафику. |
| **Table** | Произвольная таблица. Последние потоки, список соединений. |
| **Pie chart** | Доля каждой категории. Хорошо для протоколов (TCP / UDP / ICMP). |
| **Gauge** | Стрелочный индикатор от min до max. Загрузка канала в %. |

---

## Таблицы в ClickHouse

| Таблица | Что хранит | Когда использовать |
|---|---|---|
| `netflow.flows_trends_1m` | Агрегаты по минутам: BitsPerSecond, PacketsPerSec, FlowCount, TotalBytes | Тренды, графики во времени, сводки |
| `netflow.flows_raw` | Каждый поток: SrcIp, DstIp, SrcPort, DstPort, Protocol, Bytes, Packets | Топ N, разбивка по портам / протоколам / адресам |

---

## Запросы к ClickHouse

### Трафик во времени (Time series)

```sql
SELECT
    toStartOfMinute(Timestamp)  AS time,
    sum(BitsPerSecond)          AS bps,
    sum(PacketsPerSec)          AS pps
FROM netflow.flows_trends_1m
WHERE Timestamp BETWEEN $__fromTime AND $__toTime
GROUP BY time
ORDER BY time ASC
```

### Top 10 источников по трафику (Bar chart)

```sql
SELECT
    IPv4NumToString(SrcIp)  AS src_ip,
    sum(Bytes)              AS total_bytes
FROM netflow.flows_raw
WHERE Timestamp BETWEEN $__fromTime AND $__toTime
GROUP BY src_ip
ORDER BY total_bytes DESC
LIMIT 10
```

### Top 10 портов назначения (Bar chart)

```sql
SELECT
    DstPort                 AS port,
    sum(Bytes)              AS total_bytes
FROM netflow.flows_raw
WHERE Timestamp BETWEEN $__fromTime AND $__toTime
GROUP BY port
ORDER BY total_bytes DESC
LIMIT 10
```

### Протоколы TCP / UDP / other (Pie chart)

```sql
SELECT
    CASE
        WHEN Protocol = 6  THEN 'TCP'
        WHEN Protocol = 17 THEN 'UDP'
        WHEN Protocol = 1  THEN 'ICMP'
        ELSE toString(Protocol)
    END                     AS proto,
    sum(Bytes)              AS bytes
FROM netflow.flows_raw
WHERE Timestamp BETWEEN $__fromTime AND $__toTime
GROUP BY proto
ORDER BY bytes DESC
```

### Всего байт за период (Stat)

```sql
SELECT
    sum(Bytes) AS total_bytes
FROM netflow.flows_raw
WHERE Timestamp BETWEEN $__fromTime AND $__toTime
```

> В настройках панели → Standard options → Unit → выбери `Data > bytes (IEC)` — отобразит в GiB/MiB.

### Последние 50 потоков (Table)

```sql
SELECT
    Timestamp,
    IPv4NumToString(SrcIp)  AS src,
    IPv4NumToString(DstIp)  AS dst,
    DstPort                 AS port,
    CASE Protocol
        WHEN 6  THEN 'TCP'
        WHEN 17 THEN 'UDP'
        ELSE toString(Protocol)
    END                     AS proto,
    Bytes
FROM netflow.flows_raw
WHERE Timestamp BETWEEN $__fromTime AND $__toTime
ORDER BY Timestamp DESC
LIMIT 50
```

---

## Макросы временного диапазона

| Макрос | Что подставляется |
|---|---|
| `$__fromTime` | Начало выбранного диапазона (DateTime) |
| `$__toTime` | Конец выбранного диапазона (DateTime) |
| `$__timeFilter(col)` | Сокращение для `col BETWEEN $__fromTime AND $__toTime` |
| `$__interval_s` | Шаг в секундах, подобранный под ширину графика |

**Правило:** Всегда добавляй `WHERE Timestamp BETWEEN $__fromTime AND $__toTime` — иначе Grafana сканирует всю таблицу целиком при каждом обновлении.

---

## Переменные — фильтры на дашборде

Создают выпадающие списки в верхней части дашборда. Все панели фильтруются автоматически.

**Настройка:** ⚙ → Variables → Add variable → тип Query, datasource ClickHouse.

Запрос для переменной `$dst_port`:

```sql
SELECT DISTINCT DstPort
FROM netflow.flows_raw
WHERE Timestamp >= now() - INTERVAL 1 HOUR
ORDER BY DstPort ASC
```

Использование в панели: `WHERE DstPort = $dst_port`

---

## Практические советы

- **Единицы:** Standard options → Unit → `Data → bytes (IEC)` для байт, `Data rate → bits/sec (IEC)` для битрейта
- **Автообновление:** правый верхний угол дашборда — поставь 5s или 10s
- **Имена в легенде:** задаются прямо в SQL через `AS` — `sum(Bytes) AS total_bytes`
- **Цвета линий:** Time series → Overrides → Add field override → Standard options → Color
- **IP в числах:** SrcIp и DstIp — тип `UInt32`; используй `IPv4NumToString()` для читаемого вида
- **Протоколы:** `6` = TCP, `17` = UDP, `1` = ICMP

**Сохранить панель в репозиторий:** ⚙ → JSON Model → скопируй JSON → положи в `infra/grafana/dashboards/`.

---

## Быстрый старт

Открой существующую панель «Top 10 Dst Ports» → заголовок → **Edit**. Посмотри на запрос, замени `DstPort` на `SrcIp` или `DstIp`, нажми **Run query** — это самый быстрый способ понять, как всё работает.
