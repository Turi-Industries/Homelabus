-- Retour arrière : les jetons perdent leur rattachement à un utilisateur.
--
-- ⚠️ Conséquence : les jetons personnels deviennent des jetons de service. L'API
-- d'aliases refusera alors de les servir — c'est le bon comportement, préférable à
-- laisser un jeton sans identité agir au nom de quelqu'un.
CREATE TABLE api_tokens_old (
    name        TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    last_used   TEXT
);

INSERT INTO api_tokens_old (name, fingerprint, role, created_at, last_used)
SELECT name, fingerprint, role, created_at, last_used FROM api_tokens;

DROP TABLE api_tokens;
ALTER TABLE api_tokens_old RENAME TO api_tokens;
