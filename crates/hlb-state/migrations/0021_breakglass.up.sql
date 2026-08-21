-- Les garde-fous d'accès de secours du §5.7bis, et QUAND on les a vérifiés.
--
-- 🔴 Homelabus ne peut vérifier lui-même aucun de ces quatre points : il ne sait pas
-- combien de passkeys sont enregistrées, ni si les codes à usage unique sont imprimés
-- et rangés quelque part. Il ne peut donc pas les cocher — mais il peut demander qu'on
-- les atteste, garder la date, et redevenir rouge quand l'attestation vieillit.
--
-- Un break-glass jamais éprouvé n'est pas un break-glass : c'est exactement le
-- raisonnement des exercices de restauration du §8.3.
CREATE TABLE breakglass (
    -- Identifiant stable du garde-fou : 'codes-imprimes', 'deux-passkeys', …
    id          TEXT PRIMARY KEY,
    atteste_le  TEXT NOT NULL DEFAULT (datetime('now')),
    atteste_par TEXT NOT NULL,
    note        TEXT
) STRICT;
