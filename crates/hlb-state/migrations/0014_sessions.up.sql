-- Sessions de navigateur et rôles des personnes (§9ter, amendé).
--
-- ## Pourquoi une session et pas seulement un jeton
--
-- Un jeton d'API convient à une machine : le CLI, Bitwarden, un scrape. Il ne convient
-- pas à vingt personnes — il faudrait leur faire conserver et coller une valeur de
-- 52 caractères, sans possibilité de se déconnecter ni de savoir qui est connecté.
--
-- La session est posée après un aller-retour OIDC vers PocketID, qui reste la seule
-- source de vérité des identités.

CREATE TABLE sessions (
    -- 🔴 L'empreinte SHA-256 de la valeur du cookie, JAMAIS la valeur.
    --
    -- Même discipline que `api_tokens.fingerprint` : une base qui fuite révèle que des
    -- sessions existent, pas de quoi s'y substituer. Sans ça, un instantané de `hlb.db`
    -- — qui part dans les sauvegardes, donc hors site — serait un trousseau de clés.
    fingerprint TEXT PRIMARY KEY,

    -- Le compte Homelabus. La suppression du compte tue ses sessions : sinon une
    -- personne révoquée resterait connectée jusqu'à l'expiration du cookie.
    user        TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,

    -- Le `sub` PocketID, conservé pour recouper une identité renommée.
    subject     TEXT,

    -- 🔴 Horodatages en Unix (INTEGER), pas en `datetime('now')`.
    --
    -- `datetime('now')` a une résolution d'une SECONDE, ce qui a déjà mordu sur le
    -- compteur d'échecs de sauvegarde. Pour une expiration on veut comparer, pas
    -- afficher.
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,

    -- Pour que « mes sessions actives » soit lisible : « Firefox sur Linux », pas un
    -- identifiant opaque qu'on ne saurait pas révoquer en connaissance de cause.
    user_agent  TEXT
) STRICT;

CREATE INDEX idx_sessions_user ON sessions(user, expires_at DESC);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

-- Le rôle d'une personne dans Homelabus.
--
-- ## 🔴 Le rôle n'est PAS copié dans la session
--
-- Il serait tentant de figer le rôle au moment de la connexion : une jointure de moins
-- à chaque requête. Mais alors, retirer les droits d'administrateur à quelqu'un
-- n'aurait aucun effet tant que sa session vit — soit jusqu'à douze heures. Or on
-- retire des droits précisément quand on est pressé de les retirer.
--
-- Le rôle est donc relu ici à chaque requête, et une révocation prend effet à la
-- requête suivante.
--
-- L'absence de ligne vaut `utilisateur` (le défaut de `hlb_types::Role`) : une
-- identité PocketID inconnue de Homelabus entre au plus bas, jamais plus.
CREATE TABLE user_roles (
    user       TEXT PRIMARY KEY REFERENCES users(name) ON DELETE CASCADE,
    role       TEXT NOT NULL,
    -- Qui a accordé ce rôle : la question qu'on se pose en premier après un incident.
    granted_by TEXT,
    granted_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
