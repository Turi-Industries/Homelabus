-- The recipients Stalwart's queue still had to deliver to, at its last reading.
-- Replaced whole at every reading: a message delivered or bounced since is gone.
CREATE TABLE mail_queue (
    message_id TEXT    NOT NULL,
    recipient  TEXT    NOT NULL,
    since      INTEGER NOT NULL,
    attempts   INTEGER NOT NULL,
    next_retry INTEGER NOT NULL,
    expires_at INTEGER,
    error      TEXT,
    read_at    INTEGER NOT NULL,
    PRIMARY KEY (message_id, recipient)
) STRICT;
