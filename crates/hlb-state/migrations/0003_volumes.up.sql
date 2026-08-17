-- Les volumes créés pour chaque app, avec leur emplacement réel.
--
-- C'est ce qui permet à la sauvegarde de savoir QUOI sauvegarder (§8) : sans cette
-- table, on ne peut pas relier une app aux données qu'elle possède.
CREATE TABLE app_volumes (
    app        TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    mountpoint TEXT NOT NULL,
    -- Certains volumes n'ont pas à être sauvegardés (caches, données
    -- reconstructibles). Le manifest le déclare, on le mémorise ici.
    backup     INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (app, name)
) STRICT;
