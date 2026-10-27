-- The manifest declared `storage[].sqlite: true` from the start and nothing
-- recorded it: SQLite databases were therefore backed up HOT, which is forbidden.
-- A SQLite file copied during a write restores as a corrupt database, with nothing
-- signalling it to the backup.
ALTER TABLE app_volumes ADD COLUMN sqlite INTEGER NOT NULL DEFAULT 0;
