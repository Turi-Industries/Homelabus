-- Le dossier de tri d'un alias (§5bis.3).
--
-- 🔴 NULL ≠ chaîne vide. NULL veut dire « rien n'a été décidé » — on proposera un
-- défaut dérivé de l'indice. Une chaîne vide veut dire « l'utilisateur ne veut PAS de
-- tri » et doit être respectée : lui réimposer un dossier à chaque régénération
-- reviendrait à ignorer un choix explicite.
ALTER TABLE user_aliases ADD COLUMN folder TEXT;
