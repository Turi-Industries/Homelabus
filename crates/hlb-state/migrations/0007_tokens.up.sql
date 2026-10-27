-- API access tokens.
--
-- 🔴 A FINGERPRINT is stored, never the value. A leak of this table reveals
-- that a token exists, not what it is: regenerate it, do not panic.
CREATE TABLE api_tokens (
    name        TEXT PRIMARY KEY,
    -- Hexadecimal SHA-256 fingerprint.
    fingerprint TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    -- Last observed use: spots a forgotten token, better revoked than ignored.
    last_used   TEXT
);
