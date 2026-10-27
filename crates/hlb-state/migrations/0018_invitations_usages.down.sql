-- SQLite cannot drop a column before 3.35, and doing it by recreation would lose the
-- pending invitations. The columns have a DEFAULT: an older binary ignores them
-- without error.
SELECT 1;
