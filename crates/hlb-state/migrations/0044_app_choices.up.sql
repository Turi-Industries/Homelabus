-- What was decided for an app after its manifest, kept beside it.
--
-- `mail_domain`: the mail domain its install took. Read again from the exposure at
-- every upgrade, an exposure moved since gave the app mailboxes at another domain.
-- `replicas`: the count `hlb stop` / `hlb scale` set, NULL for the manifest's. Kept in
-- Swarm alone, reconciliation read it as drift and scaled a stopped app back up.
ALTER TABLE apps ADD COLUMN mail_domain TEXT;
ALTER TABLE apps ADD COLUMN replicas INTEGER;
