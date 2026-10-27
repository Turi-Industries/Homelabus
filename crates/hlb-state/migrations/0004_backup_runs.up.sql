-- History of backups and of their verifications.
--
-- Two purposes:
--   1. decide what is due (interval since the last SUCCESS);
--   2. answer "are my backups working?" with facts.
CREATE TABLE backup_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    app         TEXT NOT NULL,
    -- 'volume' | 'database'
    kind        TEXT NOT NULL,
    snapshot_id TEXT,
    -- 'ok' | 'failed'
    status      TEXT NOT NULL,
    error       TEXT,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT
) STRICT;

CREATE INDEX idx_backup_runs_app ON backup_runs(app, status, started_at DESC);

-- An untested backup is not a backup. A copy whose restore was never verified
-- stays a hypothesis.
CREATE TABLE restore_verifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    app         TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    -- 'ok' | 'failed'
    status      TEXT NOT NULL,
    detail      TEXT,
    verified_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_verifications_app ON restore_verifications(app, verified_at DESC);
