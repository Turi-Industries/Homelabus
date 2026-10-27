-- Nothing is lost either way: the rename is a pure key change, and `verified_at`,
-- `created_at`, `title` and `blocking` travel with the row in both directions.
--
-- ⚠️ Going down without also reverting the catalog leaves the database on the old ids
-- and the guide files on the new ones — which is the regression described in the `up`,
-- just pointing the other way.
UPDATE pending_guides SET id = 'filet-de-securite'
 WHERE app = 'bulwark' AND id = 'safety-net';

UPDATE pending_guides SET id = 'cle-de-chiffrement'
 WHERE app = 'n8n' AND id = 'encryption-key';

UPDATE pending_guides SET id = 'compte-proprietaire'
 WHERE app = 'n8n' AND id = 'owner-account';

UPDATE secrets SET purpose = 'mot de passe IMAP/SMTP'
 WHERE purpose = 'IMAP/SMTP password';
