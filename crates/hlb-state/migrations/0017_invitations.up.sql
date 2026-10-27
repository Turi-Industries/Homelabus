-- Invitations to create an account.
--
-- ## Why a table rather than an API token
--
-- An API token grants access to the API. An invitation grants the right to create
-- ONE account, once, and nothing else. Confusing them would hand an operational key
-- to someone who does not even have an account yet.
--
-- ## 🔴 The fingerprint, never the value
--
-- Same discipline as `api_tokens` and `sessions`: the database goes into the
-- backups, therefore off-site. Storing usable tokens there would make every copy a
-- key ring. The value is shown ONCE, at creation, and can never be shown again.
CREATE TABLE invitations (
    fingerprint TEXT PRIMARY KEY,

    -- Who invited: the first question you ask in front of an unexpected account.
    created_by    TEXT NOT NULL,

    -- The quota profile and the role the created account will receive.
    --
    -- ⚠️ Fixed at INVITATION time, not chosen by the invitee: otherwise anyone could
    -- give themselves the `admin` role by signing up.
    profile      TEXT NOT NULL DEFAULT 'standard',
    role        TEXT NOT NULL DEFAULT 'user',

    -- The imposed mail domain, if there is one.
    domain     TEXT,

    -- Unix timestamps: we compare, we do not display. `datetime('now')` has
    -- one-second resolution, which has already bitten elsewhere in this project.
    created_at     INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,

    -- 🔴 Marked BEFORE any creation: a consumed invitation must not be usable
    -- again, even if the creation then fails. The opposite would let several accounts
    -- be created from a link you believe is single-use.
    used_at  TEXT,
    -- The account actually created, once it has been used.
    account      TEXT,

    note        TEXT
) STRICT;

CREATE INDEX idx_invitations_expiry ON invitations(used_at, expires_at);
