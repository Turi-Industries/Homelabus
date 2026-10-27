-- The cards a person pinned below the home's inbox: a JSON array of `HomeWidget` names.
--
-- NULL = never arranged, and the default applies — not the same as `[]`, a person who
-- unpinned everything on purpose and would see the default come back otherwise.
ALTER TABLE user_prefs ADD COLUMN home TEXT;
