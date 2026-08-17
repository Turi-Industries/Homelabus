-- Les secrets, chiffrés au repos avec la clé maîtresse age (§9quater).
--
-- La valeur en clair n'existe jamais sur disque ni dans le dépôt Git. Sans la clé
-- maîtresse, cette table est inexploitable — c'est voulu.
CREATE TABLE secrets (
    name       TEXT PRIMARY KEY,
    ciphertext BLOB NOT NULL,
    purpose    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    rotated_at TEXT
) STRICT;
