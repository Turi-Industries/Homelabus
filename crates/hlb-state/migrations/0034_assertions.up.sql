-- The last reading of each assertion a manifest declares: what a running app must keep
-- true, read by its effect. One row per assertion, replaced at every reading — the
-- inbox wants the state now, not a history. Forgotten with the app.
CREATE TABLE assertion_results (
    app        TEXT    NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    id         TEXT    NOT NULL,
    holds      TEXT    NOT NULL,
    verdict    TEXT    NOT NULL CHECK (verdict IN ('holds', 'broken', 'unknown')),
    observed   TEXT    NOT NULL,
    checked_at INTEGER NOT NULL,
    PRIMARY KEY (app, id)
);
