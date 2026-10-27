-- 🔴 The column is really removed, not left in place.
--
-- The first version of this `down` did nothing, on the grounds that a spare column
-- is harmless to the previous version. That was wrong: after a rollback, replaying
-- the `up` fails on "duplicate column name", and the rollback -> retry cycle — the
-- most realistic scenario — becomes impossible.
--
-- `DROP COLUMN` needs SQLite 3.35 (2021), amply covered by the library bundled
-- with sqlx.
ALTER TABLE app_volumes DROP COLUMN sqlite;
