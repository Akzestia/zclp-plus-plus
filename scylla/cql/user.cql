use user_data;

CREATE TABLE IF NOT EXISTS Users
(
    Id          UUID,
    public_name TEXT,
    email       BLOB,
    avatar      BLOB,

    joined_at   TIMESTAMP,

    PRIMARY KEY ((public_name), Id)
);

CREATE TABLE IF NOT EXISTS LastVisitedCluster
(
    Id           UUID,
    cluster      TEXT,
    user         TEXT,
    cluster_mask TEXT,

    PRIMARY KEY ((user))
);
