-- Historique des sauvegardes et de leurs vérifications (§8.1, §8.3).
--
-- Sert à deux choses :
--   1. décider ce qui est dû (intervalle depuis la dernière RÉUSSITE) ;
--   2. répondre à « mes sauvegardes marchent-elles ? » avec des faits.
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

-- §8.3 — « un backup non testé n'est pas un backup ». Une sauvegarde dont la
-- restauration n'a jamais été vérifiée reste une hypothèse.
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
