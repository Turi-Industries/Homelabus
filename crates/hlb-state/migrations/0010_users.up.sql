-- Comptes humains, boîtes mail et aliases (§5bis.3).
--
-- 🔴 Pourquoi HomelabUS tient ce registre alors que PocketID et Stalwart existent :
-- aucun des deux ne connaît la notion d'alias TEMPORAIRE. Stalwart stocke une liste
-- d'aliases sans date, PocketID ignore les boîtes. La date d'expiration ne vit donc
-- nulle part ailleurs — et sans elle, « temporaire » n'est qu'un mot.

CREATE TABLE users (
    name       TEXT PRIMARY KEY,
    profil     TEXT NOT NULL DEFAULT 'standard',
    -- Identifiant PocketID. NULL tant que l'identité n'est pas créée : c'est ce qui
    -- rend l'état « à moitié créé » visible plutôt que deviné.
    pocket_id  TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE TABLE user_mailboxes (
    user       TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    local      TEXT NOT NULL,
    domain     TEXT NOT NULL,
    -- La boîte qui sert d'identité au compte. Une seule par utilisateur.
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user, local)
) STRICT;

CREATE TABLE user_aliases (
    user       TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    mailbox    TEXT NOT NULL,
    local      TEXT NOT NULL,
    -- NULL = permanent. Sinon, horodatage Unix d'expiration.
    expires_at INTEGER,
    -- 🔴 Existe-t-il ENCORE chez Stalwart ? C'est ce drapeau qui permet de distinguer
    -- « expiré et supprimé » de « expiré et TOUJOURS ACTIF ». Sans lui, une purge qui
    -- ne tourne pas laisserait des adresses ouvertes que l'on croit fermées.
    active     INTEGER NOT NULL DEFAULT 1,
    -- L'indice de génération : à quel site cette adresse a été donnée. C'est ce qui
    -- permet d'attribuer une fuite — le vrai bénéfice du dispositif.
    hint       TEXT,
    note       TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user, local)
) STRICT;

CREATE INDEX idx_user_aliases_expiry ON user_aliases(active, expires_at);
