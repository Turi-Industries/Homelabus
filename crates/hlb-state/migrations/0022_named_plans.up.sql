-- Plans saved as drafts.
--
-- Prepare an operation cold, re-read it, and run it during a quiet hour. Without
-- this, every action is decided and executed within the same minute — which is
-- exactly how you aim at the wrong target.
--
-- 🔴 The plan is stored as it was PREVIEWED, not recomputed at execution
-- time: two computations at two different moments can diverge (an app installed
-- meanwhile, a changed domain), and you would then execute something other than what
-- you read and approved.
--
-- ⚠️ No secret value enters here. The plan already passes through the display, the
-- state and the Git mirror; that is why secret tokens are resolved in the executor
-- and never in the plan.
CREATE TABLE named_plans (
    name        TEXT PRIMARY KEY,
    -- The action and its body, as the route expects them.
    method    TEXT NOT NULL,
    path     TEXT NOT NULL,
    body      TEXT NOT NULL,
    -- The summary read at save time: THIS is the text that was approved.
    summary     TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    note       TEXT
) STRICT;
