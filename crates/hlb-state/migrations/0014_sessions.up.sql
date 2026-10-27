-- Browser sessions and people's roles.
--
-- ## Why a session and not just a token
--
-- An API token suits a machine: the CLI, Bitwarden, a scrape. It does not suit
-- twenty people — they would have to keep and paste a 52-character value, with no
-- way to sign out and no way to know who is signed in.
--
-- The session is issued after an OIDC round trip to PocketID, which stays the only
-- source of truth for identities.

CREATE TABLE sessions (
    -- 🔴 The SHA-256 fingerprint of the cookie value, NEVER the value.
    --
    -- Same discipline as `api_tokens.fingerprint`: a leaked database reveals that
    -- sessions exist, not enough to impersonate them. Without this, a snapshot of
    -- `hlb.db` — which goes into the backups, therefore off-site — would be a key
    -- ring.
    fingerprint TEXT PRIMARY KEY,

    -- The Homelabus account. Deleting the account kills its sessions: otherwise a
    -- revoked person would stay signed in until the cookie expires.
    user        TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,

    -- The PocketID `sub`, kept to cross-check a renamed identity.
    subject     TEXT,

    -- 🔴 Unix timestamps (INTEGER), not `datetime('now')`.
    --
    -- `datetime('now')` has ONE SECOND resolution, which already bit the backup
    -- failure counter. For an expiry you want to compare, not to display.
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,

    -- So that "my active sessions" is readable: "Firefox on Linux", not an opaque
    -- identifier you could not revoke knowingly.
    user_agent  TEXT
) STRICT;

CREATE INDEX idx_sessions_user ON sessions(user, expires_at DESC);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

-- A person's role in Homelabus.
--
-- ## 🔴 The role is NOT copied into the session
--
-- Freezing the role at sign-in time is tempting: one join less per request. But then
-- removing someone's administrator rights would have no effect while their session
-- lives — up to twelve hours. And you remove rights precisely when you are in a
-- hurry to remove them.
--
-- The role is therefore re-read here on every request, and a revocation takes effect
-- on the next one.
--
-- A missing row means `user` (the default of `hlb_types::Role`): a PocketID identity
-- unknown to Homelabus comes in at the lowest level, never higher.
CREATE TABLE user_roles (
    user       TEXT PRIMARY KEY REFERENCES users(name) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    -- Who granted this role: the first question you ask after an incident.
    granted_by TEXT,
    granted_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
