-- Notifications quiet hours held back, delivered once they end. One per subject: a
-- backup failing on every pass of the night is one notice in the morning, the
-- latest. `revision` moves with every replacement, so a delivery releases only the
-- version it sent and never a newer one written meanwhile.
CREATE TABLE held_notifications (
    subject  TEXT    PRIMARY KEY,
    level    TEXT    NOT NULL,
    title    TEXT    NOT NULL,
    body     TEXT    NOT NULL,
    held_at  INTEGER NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0
) STRICT;
