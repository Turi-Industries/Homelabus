-- Rollback: accounts disappear from the Homelabus registry.
--
-- ⚠️ PocketID accounts and Stalwart mailboxes are NOT touched: they exist
-- independently, and deleting them on a migration rollback would destroy data
-- nobody asked to destroy.
--
-- 🔴 Consequence to know about: the expiry dates of temporary aliases are
-- lost. They live nowhere else — Stalwart has no notion of them. The aliases will
-- therefore stay active indefinitely, with nothing signalling it.
DROP INDEX IF EXISTS idx_user_aliases_expiry;
DROP TABLE IF EXISTS user_aliases;
DROP TABLE IF EXISTS user_mailboxes;
DROP TABLE IF EXISTS users;
