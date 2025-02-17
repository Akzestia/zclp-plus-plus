use user_data;

-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

CREATE TABLE IF NOT EXISTS MediaNode
(
    Id           UUID,
    public_name  TEXT,
    max_capacity INT,

    visibility   TINYINT,

    PRIMARY KEY ( (public_name) )
);

-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

CREATE TABLE IF NOT EXISTS TextNode
(
    Id          UUID,
    public_name TEXT,

    visibility  TINYINT,

    PRIMARY KEY ( (public_name) )
);

-- XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

-- Roles owned by different nodes
CREATE TABLE IF NOT EXISTS NodeRoles
(
    node UUID,
    role INT,

    PRIMARY KEY ( (node) )
);

-- Serves node's banner | background
CREATE TABLE IF NOT EXISTS NodeBanners
(
    node   UUID,
    banner BLOB,

    PRIMARY KEY ( (node) )
);

-- Serves node's fonts
CREATE TABLE IF NOT EXISTS NodeFonts
(
    node           UUID,
    main_font      BLOB,
    secondary_font BLOB,

    PRIMARY KEY ( (node) )
);

-- Serves node's config
-- node specific plugins, features etc.
CREATE TABLE IF NOT EXISTS NodeConfigs
(
    node   UUID,
    config BLOB,

    PRIMARY KEY ( (node) )
);

-- Node's Roles rights
CREATE TABLE IF NOT EXISTS NodeRolesAccess
(
    node       UUID,
    role       INT,
    has_access BOOLEAN
);

