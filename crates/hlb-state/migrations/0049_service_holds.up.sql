-- Services stopped on purpose — a restore, a store stopped for its backup's copy — that
-- reconciliation must leave stopped until `until` (seconds since the epoch). A hold
-- lapses rather than lasting for ever: the process that took it may die holding it.
CREATE TABLE service_holds (
    service TEXT PRIMARY KEY,
    why     TEXT NOT NULL,
    until   INTEGER NOT NULL
) STRICT;
