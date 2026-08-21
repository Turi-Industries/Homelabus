-- Les invitations à créer un compte (lot 6.2).
--
-- ## Pourquoi une table plutôt qu'un jeton d'API
--
-- Un jeton d'API donne accès à l'API. Une invitation donne le droit de créer UN compte,
-- une seule fois, et rien d'autre. Les confondre reviendrait à distribuer une clé
-- d'exploitation à quelqu'un qui n'a pas encore de compte.
--
-- ## 🔴 L'empreinte, jamais la valeur
--
-- Même discipline que `api_tokens` et `sessions` : la base part dans les sauvegardes,
-- donc hors site. Y stocker des jetons utilisables ferait de chaque copie un trousseau
-- de clés. La valeur est affichée UNE fois, à la création, et n'est jamais réaffichable.
CREATE TABLE invitations (
    fingerprint TEXT PRIMARY KEY,

    -- Qui a invité : la première question qu'on se pose devant un compte inattendu.
    cree_par    TEXT NOT NULL,

    -- Le profil de quotas et le rôle que recevra le compte créé.
    --
    -- ⚠️ Fixés à l'INVITATION, pas choisis par l'invité : sinon n'importe qui pourrait
    -- se donner le rôle `admin` en s'inscrivant.
    profil      TEXT NOT NULL DEFAULT 'standard',
    role        TEXT NOT NULL DEFAULT 'utilisateur',

    -- Le domaine mail imposé, s'il y en a un.
    domaine     TEXT,

    -- Horodatages Unix : on compare, on n'affiche pas. `datetime('now')` a une
    -- résolution d'une seconde, ce qui a déjà mordu ailleurs dans ce projet.
    cree_le     INTEGER NOT NULL,
    expire_le   INTEGER NOT NULL,

    -- 🔴 Marqué AVANT toute création : une invitation consommée ne doit pas pouvoir
    -- resservir, même si la création échoue ensuite. Le contraire permettrait de créer
    -- plusieurs comptes avec un lien qu'on croit à usage unique.
    utilise_le  TEXT,
    -- Le compte effectivement créé, quand elle a servi.
    compte      TEXT,

    note        TEXT
) STRICT;

CREATE INDEX idx_invitations_expiry ON invitations(utilise_le, expire_le);
