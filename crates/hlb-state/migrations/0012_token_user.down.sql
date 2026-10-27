-- Rollback: tokens lose their binding to a user.
--
-- ⚠️ Consequence: personal tokens become service tokens. The alias API will then
-- refuse to serve them — the right behaviour, preferable to letting a token with no
-- identity act in someone's name.
CREATE TABLE api_tokens_old (
    name        TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    last_used   TEXT
);

INSERT INTO api_tokens_old (name, fingerprint, role, created_at, last_used)
SELECT name, fingerprint, role, created_at, last_used FROM api_tokens;

DROP TABLE api_tokens;
ALTER TABLE api_tokens_old RENAME TO api_tokens;
