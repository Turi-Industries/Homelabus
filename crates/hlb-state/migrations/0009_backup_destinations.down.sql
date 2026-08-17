-- Retour arrière : les destinations et le routage disparaissent.
--
-- ⚠️ SQLite ne sait pas retirer une colonne avant la 3.35 ; on reconstruit donc
-- `backup_runs` sans `destination`. L'historique des sauvegardes est PRÉSERVÉ — le
-- perdre ferait croire à des apps jamais sauvegardées, et déclencherait des alertes
-- critiques sur des données parfaitement protégées.

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
