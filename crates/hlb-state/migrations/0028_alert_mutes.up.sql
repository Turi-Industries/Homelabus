-- Alert mutes: the one place a mute lives.
--
-- The evaluation loop carried the previous pass's mutes forward in memory, so a restart
-- lifted every one of them, and the silenced alert notified again. `until` is seconds
-- since the epoch; a row past it is a mute that has ended, ignored when read.
CREATE TABLE alert_mutes (
    rule       TEXT PRIMARY KEY,
    until      INTEGER NOT NULL,
    muted_by   TEXT NOT NULL,
    reason     TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
