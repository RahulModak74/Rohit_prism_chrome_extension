-- Browser-shield ingest table. Run once on the shield ClickHouse.
CREATE TABLE IF NOT EXISTS shield_events
(
    timestamp       DateTime64(3) DEFAULT now64(3),
    org_id          LowCardinality(String),
    user_id         String,
    ip_address      String,
    page            String,                 -- registrable domain, or full URL if org opted in
    referrer        String,                 -- only populated when org opted into full URLs
    device_fp       String,                 -- canvas+webgl device hash (top frame), survives storage wipe
    frame_is_top    UInt8,
    event_type      LowCardinality(String),
    origin          String,
    is_third_party  UInt8,
    is_initial      UInt8,
    novel           UInt8,                   -- third-party origin not in org allowlist
    element_type    LowCardinality(String),
    attr_name       LowCardinality(String),
    method          LowCardinality(String),
    severity        LowCardinality(String),  -- high | info
    detail          String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (org_id, user_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;
