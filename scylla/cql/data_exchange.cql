use user_data;

CREATE TABLE IF NOT EXISTS Messages
(
    Id        UUID,
    sender    UUID,
    recipient UUID,
    data      BLOB
);

CREATE TABLE IF NOT EXISTS E2E_Messages
(
    Id                 UUID,
    message            UUID,

    encryption_version INT,
    encryption_type    INT
)