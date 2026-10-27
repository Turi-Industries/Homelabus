-- Human accounts, mailboxes and aliases.
--
-- 🔴 Why Homelabus keeps this registry when PocketID and Stalwart exist:
-- neither knows what a TEMPORARY alias is. Stalwart stores a list of aliases with
-- no dates, PocketID ignores mailboxes. The expiry date therefore lives nowhere
-- else — and without it, "temporary" is just a word.

CREATE TABLE users (
    name       TEXT PRIMARY KEY,
    profile     TEXT NOT NULL DEFAULT 'standard',
    -- PocketID identifier. NULL until the identity is created: this is what makes
    -- the "half created" state visible rather than guessed.
    pocket_id  TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE TABLE user_mailboxes (
    user       TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    local      TEXT NOT NULL,
    domain     TEXT NOT NULL,
    -- The mailbox that acts as the account's identity. Exactly one per user.
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user, local)
) STRICT;

CREATE TABLE user_aliases (
    user       TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    mailbox    TEXT NOT NULL,
    local      TEXT NOT NULL,
    -- NULL = permanent. Otherwise, Unix expiry timestamp.
    expires_at INTEGER,
    -- 🔴 Does it STILL exist on Stalwart? This flag is what distinguishes
    -- "expired and removed" from "expired and STILL ACTIVE". Without it, a purge
    -- that never runs would leave addresses open that you believe are closed.
    active     INTEGER NOT NULL DEFAULT 1,
    -- The generation hint: which site this address was given to. This is what makes
    -- a leak attributable — the real benefit of the whole scheme.
    hint       TEXT,
    note       TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user, local)
) STRICT;

CREATE INDEX idx_user_aliases_expiry ON user_aliases(active, expires_at);
