-- Retour arrière : les jetons visent à nouveau la boîte par défaut.
--
-- ⚠️ Conséquence : un jeton qui déposait dans « photo » déposera désormais dans la
-- boîte par défaut. Les aliases déjà créés ne bougent pas — ils gardent leur boîte.
CREATE TABLE api_tokens_old (
    name        TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    last_used   TEXT,
    user        TEXT
);

INSERT INTO api_tokens_old (name, fingerprint, role, created_at, last_used, user)
SELECT name, fingerprint, role, created_at, last_used, user FROM api_tokens;

DROP TABLE api_tokens;
ALTER TABLE api_tokens_old RENAME TO api_tokens;
