-- Exercices de reprise après sinistre (§8.3).
--
-- 🔴 Une procédure jamais exercée ne marche pas le jour où on en a besoin. Cette
-- table existe pour qu'on puisse le CONSTATER — « ça fait 94 jours » — au lieu de
-- s'en remettre au souvenir de la dernière fois.
CREATE TABLE dr_drills (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL,
    -- 'ok' ou 'failed'. Un exercice raté est enregistré comme les autres : c'est
    -- l'information la plus utile de la table.
    status      TEXT NOT NULL,
    -- Nombre de tables lues, quand l'exercice a pu compter.
    tables      INTEGER,
    duration_s  INTEGER,
    detail      TEXT,
    finished_at TEXT NOT NULL DEFAULT (datetime('now'))
);
