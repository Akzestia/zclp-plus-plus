use user_data;

-- LZ4 AV1
CREATE TABLE IF NOT EXISTS PublicContent
(
    name TEXT,
    data BLOB,

    meta TEXT,

    PRIMARY KEY ((name))
);

CREATE TABLE IF NOT EXISTS PrivateContent
(
    name TEXT,
    data BLOB,

    meta TEXT,

    PRIMARY KEY ((name))
);