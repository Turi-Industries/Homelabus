-- Desired state and execution progress.
--
-- The controller is never the single source of truth: this database is
-- reconstructible from the Git repository and from Swarm itself. It is an
-- accelerator and a journal, not an irreplaceable store.

CREATE TABLE apps (
    name        TEXT PRIMARY KEY,
    -- The manifest frozen AT DEPLOY TIME: a catalog update never modifies a
    -- running app.
    manifest    TEXT NOT NULL,
    domain      TEXT,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- One row per plan action. This is what makes execution idempotent and
-- resumable: a finished action is never replayed.
CREATE TABLE plan_actions (
    app         TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    description TEXT NOT NULL,
    status      TEXT NOT NULL,
    error       TEXT,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (app, seq)
) STRICT;

CREATE INDEX idx_plan_actions_status ON plan_actions(app, status);

-- The queue of manual steps. Persistent, not a popup.
CREATE TABLE pending_guides (
    id          TEXT NOT NULL,
    app         TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    blocking    INTEGER NOT NULL,
    verified_at TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (app, id)
) STRICT;
