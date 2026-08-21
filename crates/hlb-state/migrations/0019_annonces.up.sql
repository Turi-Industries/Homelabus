-- Les annonces et les incidents (lot 7.2).
--
-- ## Pourquoi une table plutôt qu'un fichier
--
-- Une annonce a une audience, une échéance et un fil de mises à jour. Un fichier
-- Markdown ne porte rien de tout ça, et il faudrait le sauvegarder à part — donc
-- l'oublier lors d'une restauration.
CREATE TABLE annonces (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    titre      TEXT NOT NULL,
    corps      TEXT NOT NULL,

    -- 'info' | 'maintenance' | 'avertissement' | 'incident'
    niveau     TEXT NOT NULL DEFAULT 'info',

    -- Épinglée en tête du portail.
    epinglee   INTEGER NOT NULL DEFAULT 0,

    -- Le rôle minimal pour la voir. NULL = tout le monde.
    --
    -- ⚠️ Une annonce d'exploitation (« redémarrage des bases à 3 h ») n'intéresse pas
    -- l'utilisateur du portail, et l'inonder de messages qui ne le concernent pas lui
    -- fait cesser de les lire — au moment précis où l'un d'eux comptera.
    audience   TEXT,

    auteur     TEXT NOT NULL,
    publiee_le TEXT NOT NULL DEFAULT (datetime('now')),

    -- 🔴 Une annonce expirée disparaît du portail mais RESTE en base : c'est
    -- l'historique des incidents, et c'est ce qu'on relit après coup.
    expire_le  INTEGER
) STRICT;

CREATE INDEX idx_annonces_ordre ON annonces(epinglee DESC, id DESC);

-- Le fil d'un incident.
--
-- 🔴 Un incident se SUIT, il ne se réécrit pas. Modifier le corps d'origine effacerait
-- la chronologie — or c'est précisément elle qu'on relit après coup : à quelle heure
-- on a su, à quelle heure on a compris, à quelle heure c'était réglé.
CREATE TABLE annonce_maj (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    annonce INTEGER NOT NULL REFERENCES annonces(id) ON DELETE CASCADE,
    corps   TEXT NOT NULL,
    auteur  TEXT NOT NULL,
    at      TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_annonce_maj ON annonce_maj(annonce, id);
