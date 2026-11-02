-- The catalog's third-party sources, each a directory read beside the official
-- catalog, its apps found as `<source>/<app>`.
CREATE TABLE catalog_sources (
    name TEXT PRIMARY KEY,
    directory TEXT NOT NULL,
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- The source an app was installed from, frozen with it: its upgrades and updates
-- follow that source's manifest, never another's of the same name.
-- NULL: the official catalog — and every app recorded before this column.
ALTER TABLE apps ADD COLUMN source TEXT;
