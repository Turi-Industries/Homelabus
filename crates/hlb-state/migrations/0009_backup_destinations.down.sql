-- Rollback: destinations and routing disappear.
--
-- ⚠️ SQLite cannot drop a column before 3.35, so `backup_runs` is rebuilt without
-- `destination`. The backup history is PRESERVED — losing it would suggest apps
-- were never backed up, and would raise critical alerts on perfectly protected
-- data.

DROP INDEX IF EXISTS idx_backup_runs_dest;
DROP TABLE IF EXISTS backup_routes;
DROP TABLE IF EXISTS backup_destinations;

CREATE TABLE backup_runs_old (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    app         TEXT NOT NULL,
    kind        TEXT NOT NULL,
    snapshot_id TEXT,
    status      TEXT NOT NULL,
    error       TEXT,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT
) STRICT;

INSERT INTO backup_runs_old (id, app, kind, snapshot_id, status, error, started_at, finished_at)
SELECT id, app, kind, snapshot_id, status, error, started_at, finished_at FROM backup_runs;

DROP TABLE backup_runs;
ALTER TABLE backup_runs_old RENAME TO backup_runs;

CREATE INDEX idx_backup_runs_app ON backup_runs(app, status, started_at DESC);
