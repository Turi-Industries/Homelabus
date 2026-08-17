-- Jetons d'accès à l'API (§9ter).
--
-- 🔴 On stocke une EMPREINTE, jamais la valeur. Une fuite de cette table révèle
-- qu'un jeton existe, pas sa valeur : il faut le régénérer, pas s'en inquiéter.
CREATE TABLE api_tokens (
    name        TEXT PRIMARY KEY,
    -- Empreinte SHA-256 hexadécimale.
    fingerprint TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    -- Dernier usage constaté : sert à repérer un jeton oublié, qu'il vaut mieux
    -- révoquer qu'ignorer.
    last_used   TEXT
);
