-- 🔴 Rolling back the initial migration destroys ALL state.
--
-- It exists only so the chain of `down` scripts is complete — without it the
-- reversibility check would refuse every update. A version rollback will never run
-- it: you do not go back past the first migration.
DROP TABLE IF EXISTS plan_actions;
DROP TABLE IF EXISTS pending_guides;
DROP TABLE IF EXISTS apps;
