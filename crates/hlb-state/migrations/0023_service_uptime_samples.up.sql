-- Uptime history: one sample per service per reconcile tick.
--
-- `ServiceState` was computed live on every request, from a single `status` column
-- the reconcile loop overwrites every tick — no history existed anywhere.
-- At the default 60 s reconcile interval, 90 days is ~130k rows per service, trivial
-- for SQLite.
CREATE TABLE service_uptime_samples (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT NOT NULL,
    -- 'operationnel' | 'degrade' | 'unavailable' | 'maintenance'
    state   TEXT NOT NULL,
    at      TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_service_uptime_samples_service ON service_uptime_samples(service, at DESC);
