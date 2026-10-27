-- Roles become data: a name, one of the four permission levels, mail limits, a quota
-- per app. They replace two axes chosen as a pair — `user_roles.role` (the level) and
-- `users.profile` (the mail limits).
--
-- ## Each pair present becomes one role, counted now
--
-- The level and the profile of every account, and of every invitation still open,
-- name a role: `standard` for a person at the `user` level with the standard profile,
-- `admin-unlimited` for an administrator with no limit. Nobody's level or limits move.
-- A database with none gets the three a household starts with.
--
-- ⚠️ A role's id is its PocketID group's name (`hlb-<id>`) and every app's
-- restriction: it never changes once written. Its `name` is for people.
--
-- ⚠️ `audit_log` keeps the words it was written with (`role` there is the level held
-- at the time): rewriting a row breaks its hash chain.

CREATE TABLE roles (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL UNIQUE,
    level                 TEXT NOT NULL
                          CHECK (level IN ('user', 'viewer', 'operator', 'admin')),
    max_mailboxes         INTEGER NOT NULL,
    max_permanent_aliases INTEGER NOT NULL,
    max_temporary_aliases INTEGER NOT NULL,
    max_duration_s        INTEGER NOT NULL,
    -- NULL: the mail server's own.
    mail_quota_bytes      INTEGER,
    created_by            TEXT,
    created_at            TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- A role's storage quota in an app. No row: no quota.
CREATE TABLE role_quotas (
    role  TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    app   TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    PRIMARY KEY (role, app)
) STRICT;

-- A person's own quota in an app, over their role's — and who set it, which their
-- account page says: "200 GiB, set by lena on …" is the answer to "why mine and not
-- the others'".
CREATE TABLE person_quotas (
    user   TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    app    TEXT NOT NULL,
    -- NULL: none at all, even where the role has one.
    bytes  INTEGER,
    set_by TEXT NOT NULL,
    set_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user, app)
) STRICT;

-- What a person's quota last became inside an app: set, not yet possible (they have
-- no account there — they never signed in to it), or refused. The sync skips one set
-- the same day, and the account page says which.
CREATE TABLE quota_applied (
    user   TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    app    TEXT NOT NULL,
    -- NULL: none at all.
    bytes  INTEGER,
    state  TEXT NOT NULL CHECK (state IN ('applied', 'absent', 'failed')),
    detail TEXT,
    at     INTEGER NOT NULL,
    PRIMARY KEY (user, app)
) STRICT;

-- The roles an app lets in. None: nobody gets in.
--
-- 🔴 No foreign key on `role`: a role named here that does not exist CLOSES the app
-- (`hlb_users::access`), which a cascade would have turned into the others still
-- getting in. Deleting a role is refused while an app lets it in.
CREATE TABLE app_roles (
    app        TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    granted_by TEXT,
    granted_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (app, role)
) STRICT;

-- The pairs, read with the same leniency `Role::parse` and `Profile::by_name` had: the
-- French spellings, any case, an unknown profile read as `standard`.
CREATE TEMP TABLE pairs AS
SELECT DISTINCT
    CASE lower(trim(coalesce(level, 'user')))
        WHEN 'viewer' THEN 'viewer' WHEN 'lecteur' THEN 'viewer'
        WHEN 'operator' THEN 'operator' WHEN 'operateur' THEN 'operator'
        WHEN 'admin' THEN 'admin' WHEN 'administrateur' THEN 'admin'
        ELSE 'user'
    END AS level,
    CASE lower(trim(profile))
        WHEN 'guest' THEN 'guest' WHEN 'unlimited' THEN 'unlimited'
        ELSE 'standard'
    END AS profile
FROM (
    SELECT r.role AS level, u.profile AS profile
    FROM users u LEFT JOIN user_roles r ON r.user = u.name
    UNION ALL
    SELECT role, profile FROM invitations
    WHERE uses < max_uses AND expires_at > CAST(strftime('%s', 'now') AS INTEGER)
);

INSERT INTO roles (id, name, level, max_mailboxes, max_permanent_aliases,
                   max_temporary_aliases, max_duration_s, mail_quota_bytes, created_by)
SELECT
    CASE level WHEN 'user' THEN profile ELSE level || '-' || profile END,
    CASE level WHEN 'user' THEN profile ELSE level || '-' || profile END,
    level,
    CASE profile WHEN 'guest' THEN 1 WHEN 'unlimited' THEN 4294967295 ELSE 3 END,
    CASE profile WHEN 'guest' THEN 0 WHEN 'unlimited' THEN 4294967295 ELSE 10 END,
    CASE profile WHEN 'guest' THEN 5 WHEN 'unlimited' THEN 4294967295 ELSE 50 END,
    CASE profile WHEN 'guest' THEN 2592000 WHEN 'unlimited' THEN 9223372036854775807
                 ELSE 31536000 END,
    CASE profile WHEN 'guest' THEN 1073741824 WHEN 'unlimited' THEN NULL
                 ELSE 5368709120 END,
    'migration'
FROM pairs;

-- A new installation: an administrator with no limit, a household member, a guest.
INSERT INTO roles (id, name, level, max_mailboxes, max_permanent_aliases,
                   max_temporary_aliases, max_duration_s, mail_quota_bytes, created_by)
SELECT * FROM (
    SELECT 'admin', 'admin', 'admin', 4294967295, 4294967295, 4294967295,
           9223372036854775807, NULL, 'migration'
    UNION ALL
    SELECT 'standard', 'standard', 'user', 3, 10, 50, 31536000, 5368709120, 'migration'
    UNION ALL
    SELECT 'guest', 'guest', 'user', 1, 0, 5, 2592000, 1073741824, 'migration'
)
WHERE NOT EXISTS (SELECT 1 FROM roles);

DROP TABLE pairs;

-- No foreign key: SQLite cannot drop a column carrying one, which the way back needs.
-- A role id naming no role reads as no role at all — the lowest level, nothing to
-- create, no app — and deleting a role someone holds is refused.
ALTER TABLE users ADD COLUMN role TEXT;
ALTER TABLE users ADD COLUMN role_granted_by TEXT;
ALTER TABLE users ADD COLUMN role_granted_at TEXT;

UPDATE users SET
    role = (
        SELECT CASE l WHEN 'user' THEN p ELSE l || '-' || p END FROM (
            SELECT
                CASE lower(trim(coalesce(
                    (SELECT r.role FROM user_roles r WHERE r.user = users.name), 'user')))
                    WHEN 'viewer' THEN 'viewer' WHEN 'lecteur' THEN 'viewer'
                    WHEN 'operator' THEN 'operator' WHEN 'operateur' THEN 'operator'
                    WHEN 'admin' THEN 'admin' WHEN 'administrateur' THEN 'admin'
                    ELSE 'user'
                END AS l,
                CASE lower(trim(users.profile))
                    WHEN 'guest' THEN 'guest' WHEN 'unlimited' THEN 'unlimited'
                    ELSE 'standard'
                END AS p
        )
    ),
    role_granted_by = (SELECT r.granted_by FROM user_roles r WHERE r.user = users.name),
    role_granted_at = (SELECT r.granted_at FROM user_roles r WHERE r.user = users.name);

-- An invitation names the role its account will hold. A closed one keeps a role id
-- computed the same way, which may name no role: it is history, and lets nobody in.
UPDATE invitations SET role = (
    SELECT CASE l WHEN 'user' THEN p ELSE l || '-' || p END FROM (
        SELECT
            CASE lower(trim(invitations.role))
                WHEN 'viewer' THEN 'viewer' WHEN 'lecteur' THEN 'viewer'
                WHEN 'operator' THEN 'operator' WHEN 'operateur' THEN 'operator'
                WHEN 'admin' THEN 'admin' WHEN 'administrateur' THEN 'admin'
                ELSE 'user'
            END AS l,
            CASE lower(trim(invitations.profile))
                WHEN 'guest' THEN 'guest' WHEN 'unlimited' THEN 'unlimited'
                ELSE 'standard'
            END AS p
    )
);

-- Every app installed before roles kept letting in whoever PocketID knew: it lets in
-- every role, so nobody is locked out by the upgrade. Its floor still applies — Termix
-- is restricted to the administrator roles from the first sync. Only the apps signing
-- in through PocketID, read from the frozen manifest's YAML; the portal's own client
-- is checked per route, never as an app.
INSERT INTO app_roles (app, role, granted_by)
SELECT a.name, r.id, 'migration' FROM apps a CROSS JOIN roles r
WHERE a.name <> 'oauth2-proxy'
  AND (a.manifest LIKE '%mode: native%' OR a.manifest LIKE '%mode: proxy-%');

DROP TABLE user_roles;
ALTER TABLE users DROP COLUMN profile;
ALTER TABLE invitations DROP COLUMN profile;
