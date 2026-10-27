-- Every outcome of an image update, success included: an update that went through
-- silently cannot be told from an updater that does nothing. The controller notifies
-- each row once, and sets `notified_at`.
CREATE TABLE update_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    app         TEXT NOT NULL,
    ran_at      INTEGER NOT NULL,
    from_image  TEXT NOT NULL,
    to_image    TEXT NOT NULL,
    -- applied | rolled-back | paused | inconclusive
    outcome     TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    notified_at INTEGER
);
CREATE INDEX update_runs_unnotified ON update_runs (notified_at) WHERE notified_at IS NULL;
