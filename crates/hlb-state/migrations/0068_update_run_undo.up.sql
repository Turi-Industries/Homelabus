-- What undoing an update puts back, kept with its run: every snapshot its prior copy took
-- (volumes, buckets, dumps — JSON array of restic ids) and each companion's image before
-- (JSON object, companion name → `repo:tag@digest`). Found later by time or by tag, the
-- copy is not recoverable: a pass's volume snapshots carry `kind:pre-update` too, and a
-- prior dump is tagged as the pass's are. NULL on a run recorded before: no undo.
ALTER TABLE update_runs ADD COLUMN copies TEXT;
ALTER TABLE update_runs ADD COLUMN companions_from TEXT;
