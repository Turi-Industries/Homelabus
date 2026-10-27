-- Multiple backup destinations and their routing.
--
-- 🔴 The `destination` column on `backup_runs` is what stops a fresh
-- destination from masking a stale one. Without it, `MAX(finished_at)` aggregates
-- every destination: a NAS backed up every 4 h would make an off-site dead for
-- three weeks look like a 2 h old backup.

CREATE TABLE backup_destinations (
    name               TEXT PRIMARY KEY,
    -- Local path, or restic `s3:...` URL.
    location           TEXT NOT NULL,
    -- Accepted classes, comma separated: "critical,bulky". Empty = the destination
    -- receives nothing, and `describe()` says so.
    classes            TEXT NOT NULL DEFAULT '',
    -- Name of the secret holding "access_key:secret_key". Never the value itself.
    credentials_secret TEXT,
    created_at         TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Routing per app and per class. Absent = fall back to the classes the destination
-- accepts globally.
CREATE TABLE backup_routes (
    app         TEXT NOT NULL,
    class       TEXT NOT NULL,
    destination TEXT NOT NULL REFERENCES backup_destinations(name) ON DELETE CASCADE,
    PRIMARY KEY (app, class, destination)
) STRICT;

-- NULL for runs predating this migration: we do not know where they went, and
-- pretending otherwise would be worse than admitting it.
ALTER TABLE backup_runs ADD COLUMN destination TEXT;

CREATE INDEX idx_backup_runs_dest ON backup_runs(app, destination, status, finished_at DESC);
