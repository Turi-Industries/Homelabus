-- Secrets, encrypted at rest with the age master key.
--
-- The plaintext never exists on disk nor in the Git repository. Without the master
-- key this table is unusable — deliberately so.
CREATE TABLE secrets (
    name       TEXT PRIMARY KEY,
    ciphertext BLOB NOT NULL,
    purpose    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    rotated_at TEXT
) STRICT;
