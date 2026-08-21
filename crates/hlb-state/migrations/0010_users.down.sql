-- Retour arrière : les comptes disparaissent du registre Homelabus.
--
-- ⚠️ Les comptes PocketID et les boîtes Stalwart ne sont PAS touchés : ils existent
-- indépendamment, et les supprimer sur un retour de migration détruirait des données
-- que personne n'a demandé de détruire.
--
-- 🔴 Conséquence à connaître : les dates d'expiration des aliases temporaires sont
-- perdues. Elles ne vivent nulle part ailleurs — Stalwart n'en a pas la notion. Les
-- aliases resteront donc actifs indéfiniment, sans que rien ne le signale.
DROP INDEX IF EXISTS idx_user_aliases_expiry;
DROP TABLE IF EXISTS user_aliases;
DROP TABLE IF EXISTS user_mailboxes;
DROP TABLE IF EXISTS users;
