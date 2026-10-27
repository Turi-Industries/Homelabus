-- Disaster-recovery drills.
--
-- 🔴 A procedure never exercised does not work the day you need it. This table
-- exists so you can SEE it — "94 days ago" — instead of relying on your memory of
-- the last time.
CREATE TABLE dr_drills (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL,
    -- 'ok' or 'failed'. A failed drill is recorded like the others: it is the most
    -- useful information in the table.
    status      TEXT NOT NULL,
    -- Number of tables read, when the drill could count them.
    tables      INTEGER,
    duration_s  INTEGER,
    detail      TEXT,
    finished_at TEXT NOT NULL DEFAULT (datetime('now'))
);
