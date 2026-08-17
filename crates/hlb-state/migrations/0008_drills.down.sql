-- Détruit l'historique des exercices. Conséquence : la préparation repasse en
-- « JAMAIS exercée », ce qui est le bon sens de l'échec — mieux vaut réexercer
-- inutilement que se croire prêt à tort.
DROP TABLE IF EXISTS dr_drills;
