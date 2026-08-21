-- Ce qui a réellement été publié à la dernière application de la configuration
-- d'entrée (§9.10).
--
-- 🔴 Sans cette table, comparer « déclaré » et « réel » est impossible : les deux
-- viendraient de la même fonction, et la comparaison ne pourrait jamais échouer. Or le
-- cas dangereux est précisément celui où le Caddyfile posé ne correspond plus aux
-- manifests — une app installée sans réappliquer l'entrée, ou une app retirée dont la
-- route reste ouverte.
CREATE TABLE ingress_publie (
    host        TEXT PRIMARY KEY,
    app         TEXT NOT NULL,
    -- 0 = joignable seulement depuis le VPN, 1 = ouvert sur l'internet.
    public      INTEGER NOT NULL,
    applique_le TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
