-- The last run of each scheduled job a manifest declares (`spec.jobs`): when, whether
-- it succeeded, and the end of what it printed. One row per job, replaced at each run.
CREATE TABLE job_runs (
    app        TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    job        TEXT NOT NULL,
    ran_at     INTEGER NOT NULL,
    succeeded  INTEGER NOT NULL,
    output     TEXT NOT NULL,
    PRIMARY KEY (app, job)
);
