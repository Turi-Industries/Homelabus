-- Journal d'audit (§9).
--
-- Append-only : aucune commande n'expose de suppression ni de modification. Un
-- journal qu'on peut réécrire ne prouve rien — et c'est précisément ce qu'un
-- attaquant chercherait à faire après coup.
CREATE TABLE audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       TEXT NOT NULL DEFAULT (datetime('now')),
    -- Qui : identité PocketID, ou 'cli' pour une action locale.
    actor    TEXT NOT NULL,
    role     TEXT NOT NULL,
    -- Quoi : install, update, purge, restore…
    action   TEXT NOT NULL,
    -- Sur quoi.
    target   TEXT NOT NULL,
    -- 'ok' | 'refused' | 'failed'
    outcome  TEXT NOT NULL,
    detail   TEXT
) STRICT;

CREATE INDEX idx_audit_at ON audit_log(at DESC, id DESC);
CREATE INDEX idx_audit_target ON audit_log(target, at DESC);
