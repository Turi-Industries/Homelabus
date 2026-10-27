-- Installation-wide values a manifest's tokens read: `timezone` for `{{ timezone }}`.
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
