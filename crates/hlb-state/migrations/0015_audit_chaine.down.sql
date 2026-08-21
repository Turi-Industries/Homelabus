-- SQLite ne sait pas retirer une colonne avant la 3.35, et le faire par recréation de
-- table perdrait le journal. On laisse les colonnes : elles sont NULLables, donc un
-- binaire antérieur les ignore sans erreur (§7bis, réversibilité).
--
-- Rien à faire.
SELECT 1;
