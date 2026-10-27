-- A step handled by `hlb ack --force`, against its own check. The nightly re-check
-- reopened it every night the check still failed: the person had already said it was
-- done. Cleared once the check itself confirms it, or the step is reopened.
ALTER TABLE pending_guides ADD COLUMN forced INTEGER NOT NULL DEFAULT 0;
