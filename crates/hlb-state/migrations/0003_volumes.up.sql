-- The volumes created for each app, with their real location.
--
-- This is what lets the backup know WHAT to back up: without this table an app
-- cannot be tied to the data it owns.
CREATE TABLE app_volumes (
    app        TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    mountpoint TEXT NOT NULL,
    -- Some volumes need no backup (caches, reconstructible data). The manifest
    -- declares it, we record it here.
    backup     INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (app, name)
) STRICT;
