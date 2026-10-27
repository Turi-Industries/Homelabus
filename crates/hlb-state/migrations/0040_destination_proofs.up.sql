-- The last proof that a destination cannot be erased with its credential — or that it
-- can. Kept apart from `backup_destinations`: re-declaring a destination must not carry
-- a proof made against what it was before.
CREATE TABLE destination_proofs (
    destination TEXT PRIMARY KEY,
    location    TEXT NOT NULL,
    -- 'kept' | 'erasable' | 'unproven'
    verdict     TEXT NOT NULL,
    detail      TEXT NOT NULL,
    proven_at   INTEGER NOT NULL
) STRICT;
