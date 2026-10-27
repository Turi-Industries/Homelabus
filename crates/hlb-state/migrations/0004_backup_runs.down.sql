-- 🔴 Destroys the backup HISTORY, not the backups. Concretely: every app goes
-- back to "never backed up", so every one becomes due immediately — and the next
-- round fires a snapshot for each. Noisy but harmless.
DROP TABLE IF EXISTS restore_verifications;
DROP TABLE IF EXISTS backup_runs;
