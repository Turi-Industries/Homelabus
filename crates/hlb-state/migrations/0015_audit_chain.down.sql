-- SQLite cannot drop a column before 3.35, and doing it by recreating the table
-- would lose the log. The columns are left in place: they are NULLable, so an older
-- binary ignores them without error.
--
-- Nothing to do.
SELECT 1;
