-- Retour arrière : les dossiers de tri choisis sont perdus.
--
-- ⚠️ Les règles Sieve déjà posées chez Stalwart ne sont PAS retirées : elles
-- continueront de trier. C'est le bon choix — supprimer le tri de quelqu'un sur un
-- retour de migration mélangerait des mois de courrier rangé.
--
-- SQLite < 3.35 ne sait pas retirer une colonne ; on reconstruit la table.
CREATE TABLE user_aliases_old (
    user       TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    mailbox    TEXT NOT NULL,
    local      TEXT NOT NULL,
    expires_at INTEGER,
    active     INTEGER NOT NULL DEFAULT 1,
    hint       TEXT,
    note       TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user, local)
) STRICT;

INSERT INTO user_aliases_old (user, mailbox, local, expires_at, active, hint, note, created_at)
SELECT user, mailbox, local, expires_at, active, hint, note, created_at FROM user_aliases;

DROP INDEX IF EXISTS idx_user_aliases_expiry;
DROP TABLE user_aliases;
ALTER TABLE user_aliases_old RENAME TO user_aliases;
CREATE INDEX idx_user_aliases_expiry ON user_aliases(active, expires_at);
