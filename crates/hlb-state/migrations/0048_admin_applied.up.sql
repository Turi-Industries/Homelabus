-- What an app told its administrators by command (`access.admins.apply`, Fluxer's
-- ACL) last became, per person: granted or taken back, done, waiting for an account
-- the person has not made yet (they never signed in), or refused. The sync skips one
-- set the same day, as a quota.
CREATE TABLE admin_applied (
    user   TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    app    TEXT NOT NULL,
    admin  INTEGER NOT NULL CHECK (admin IN (0, 1)),
    state  TEXT NOT NULL CHECK (state IN ('applied', 'absent', 'failed')),
    detail TEXT,
    at     INTEGER NOT NULL,
    PRIMARY KEY (user, app)
) STRICT;
