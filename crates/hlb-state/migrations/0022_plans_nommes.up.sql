-- Les plans enregistrés en brouillon (§10.4).
--
-- Préparer une opération à froid, la relire, et l'exécuter à l'heure creuse. Sans ça,
-- toute action se décide et s'exécute dans la même minute — ce qui est exactement la
-- façon dont on se trompe de cible.
--
-- 🔴 Le plan est stocké tel qu'il a été PRÉVISUALISÉ, pas re-calculé au moment de
-- l'exécution : deux calculs à deux instants différents peuvent diverger (une app
-- installée entre-temps, un domaine changé), et l'on exécuterait alors autre chose que
-- ce qu'on a relu et approuvé.
--
-- ⚠️ Aucune valeur de secret n'entre ici. Le plan traverse déjà l'affichage, l'état et
-- le miroir Git ; c'est la raison pour laquelle les jetons de secret sont résolus dans
-- l'exécuteur et jamais dans le plan.
CREATE TABLE plans_nommes (
    nom        TEXT PRIMARY KEY,
    -- L'action et son corps, tels que la route les attend.
    methode    TEXT NOT NULL,
    chemin     TEXT NOT NULL,
    corps      TEXT NOT NULL,
    -- Le résumé lu au moment de l'enregistrement : c'est CE texte qu'on a approuvé.
    resume     TEXT NOT NULL,
    cree_par   TEXT NOT NULL,
    cree_le    TEXT NOT NULL DEFAULT (datetime('now')),
    note       TEXT
) STRICT;
