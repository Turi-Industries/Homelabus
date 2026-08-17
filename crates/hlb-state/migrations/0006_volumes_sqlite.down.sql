-- 🔴 La colonne est réellement retirée, pas laissée en place.
--
-- La première version de ce `down` ne faisait rien, au motif qu'une colonne en trop
-- est inoffensive pour la version précédente. C'était faux : après un retour arrière,
-- réappliquer le `up` échoue sur « duplicate column name », et le cycle
-- rollback → nouvelle tentative — le scénario le plus réaliste — devient impossible.
--
-- `DROP COLUMN` demande SQLite 3.35 (2021), largement couvert par la bibliothèque
-- embarquée avec sqlx.
ALTER TABLE app_volumes DROP COLUMN sqlite;
