-- The last three guide step ids left in French, renamed in place.
--
-- 🔴 Without this migration the rename is a SILENT REGRESSION, not a cosmetic change.
-- `pending_guides` is keyed on (app, id) and nothing ever deletes a row: `add_guide`
-- upserts, and `pending_guides()` returns everything with `verified_at IS NULL`. So a
-- renamed id does not move — it leaves the verified row behind under the old name and
-- inserts a fresh, UNVERIFIED one under the new one.
--
-- For `n8n` that closes a door someone already opened. Both of its steps are
-- `severity: blocking`, `unverified_blocking()` would count the new rows, and the
-- manifest exposes n8n `after-guide` — so an installation whose owner had done the work
-- months ago would find its public route shut again, with the guide asking for the same
-- two things a second time. `bulwark`'s step is `required` rather than blocking: it
-- would only reappear in the todo list forever.
--
-- Scoped by app on purpose. The id is renamed for THESE catalog entries; a private
-- catalog that happens to reuse one of these strings keeps its own.
UPDATE pending_guides SET id = 'safety-net'
 WHERE app = 'bulwark' AND id = 'filet-de-securite';

UPDATE pending_guides SET id = 'encryption-key'
 WHERE app = 'n8n' AND id = 'cle-de-chiffrement';

UPDATE pending_guides SET id = 'owner-account'
 WHERE app = 'n8n' AND id = 'compte-proprietaire';

-- And the one secret label that was still written in French. Cosmetic, unlike the
-- above: `purpose` is descriptive text shown on the secrets screen, never looked up.
-- Rows already written keep the old label without this, which is the whole reason to
-- bother — a vault half in each language is worse than either.
UPDATE secrets SET purpose = 'IMAP/SMTP password'
 WHERE purpose = 'mot de passe IMAP/SMTP';
