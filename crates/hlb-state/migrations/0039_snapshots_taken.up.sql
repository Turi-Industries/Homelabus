-- Every restic snapshot Homelabus took, by its id. A restore takes only these, unless
-- a person names another by its full id: a snapshot added to a repository by anyone
-- else — an intruder holding the repository's password, writing one dated in 2099 so
-- that it is "the latest" forever — is set aside, and said. A restic id is the hash of
-- the snapshot, so a rewritten one is another id.
CREATE TABLE snapshots_taken (
    snapshot_id TEXT PRIMARY KEY,
    app         TEXT NOT NULL,
    destination TEXT NOT NULL,
    taken_at    TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- What the backup history already holds: the last snapshot of each run.
INSERT OR IGNORE INTO snapshots_taken (snapshot_id, app, destination, taken_at)
SELECT snapshot_id, app, COALESCE(destination, 'default'), COALESCE(finished_at, started_at)
FROM backup_runs
WHERE status = 'ok' AND snapshot_id IS NOT NULL;
