-- Audit log.
--
-- Append-only: no command exposes deletion or modification. A journal you can
-- rewrite proves nothing — and rewriting it is exactly what an attacker would try
-- after the fact.
CREATE TABLE audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       TEXT NOT NULL DEFAULT (datetime('now')),
    -- Who: PocketID identity, or 'cli' for a local action.
    actor    TEXT NOT NULL,
    role     TEXT NOT NULL,
    -- What: install, update, purge, restore...
    action   TEXT NOT NULL,
    -- On what.
    target   TEXT NOT NULL,
    -- 'ok' | 'refused' | 'failed'
    outcome  TEXT NOT NULL,
    detail   TEXT
) STRICT;

CREATE INDEX idx_audit_at ON audit_log(at DESC, id DESC);
CREATE INDEX idx_audit_target ON audit_log(target, at DESC);
