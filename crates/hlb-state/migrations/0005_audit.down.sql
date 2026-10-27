-- 🔴 The audit log is APPEND-ONLY by design: nothing in the code can delete a
-- row. This `down` is the only path that erases it, and it exists only for a
-- version rollback.
--
-- A rollback therefore loses the trace of who did what. A real cost, accepted: the
-- alternative — a migration with no inverse — would forbid any update.
DROP TABLE IF EXISTS audit_log;
