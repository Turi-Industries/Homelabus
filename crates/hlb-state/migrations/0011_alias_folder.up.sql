-- The sorting folder of an alias.
--
-- 🔴 NULL is not the empty string. NULL means "nothing was decided" — a
-- default derived from the hint will be offered. An empty string means "the user
-- does NOT want sorting" and must be honoured: re-imposing a folder on every
-- regeneration would ignore an explicit choice.
ALTER TABLE user_aliases ADD COLUMN folder TEXT;
