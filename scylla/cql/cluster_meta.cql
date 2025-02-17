use cluster_meta;

-- Cluster Meta
-- Used for fast fetching of cluster info

CREATE TABLE IF NOT EXISTS Meta
(
    cluster_version              INT,
    public                       BOOLEAN,
    official_release             BOOLEAN,
    cluster_pass_phrase          BLOB,
    cluster_mask                 TEXT,

    cluster_domain               TEXT,
    cluster_name                 TEXT,
    cluster_type                 TEXT,
    cluster_location             TEXT,
    cluster_banner               BLOB,
    cluster_avatar               BLOB,
    cluster_description          BLOB,
    cluster_privacy_policy       BLOB,
    cluster_terms_and_conditions BLOB,

    max_concurrent_users         INT,
    cluster_bandwidth            INT,
    cluster_status               TINYINT,
    cluster_load                 TINYINT,

    media_codec_av1              BOOLEAN,
    media_codec_h264             BOOLEAN,
    media_serves_lz4             BOOLEAN,
    media_serves_brotli          BOOLEAN,

    community_rating             INT,
    online_user_amount           INT,
    offline_user_amount          INT,

    created_at                   DATE,
    last_update                  DATE
);

