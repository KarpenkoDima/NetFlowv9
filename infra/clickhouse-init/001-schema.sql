CREATE DATABASE IF NOT EXISTS netflow;

CREATE TABLE IF NOT EXISTS netflow.flows_raw
(
    Timestamp DateTime CODEC(DoubleDelta, ZSTD(1)),
    SrcIp     UInt32   CODEC(ZSTD(1)),
    DstIp     UInt32   CODEC(ZSTD(1)),
    SrcPort   UInt16   CODEC(ZSTD(1)),
    DstPort   UInt16   CODEC(ZSTD(1)),
    Protocol  UInt8    CODEC(ZSTD(1)),
    Bytes     UInt64   CODEC(ZSTD(1)),
    Packets   UInt64   CODEC(ZSTD(1))
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(Timestamp)
ORDER BY (Timestamp, SrcIp, DstIp)
TTL Timestamp + INTERVAL 14 DAY;

CREATE TABLE IF NOT EXISTS netflow.flows_trends_1m
(
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
