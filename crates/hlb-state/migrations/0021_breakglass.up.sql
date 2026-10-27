-- The emergency-access safeguards, and WHEN they were verified.
--
-- 🔴 Homelabus can verify none of these four points itself: it does not know
-- how many passkeys are registered, nor whether the one-time codes are printed and
-- stored somewhere. So it cannot tick them off — but it can ask for an attestation,
-- keep the date, and go red again when the attestation ages.
--
-- A break-glass never exercised is not a break-glass: exactly the reasoning behind
-- the restore drills.
CREATE TABLE breakglass (
    -- Stable identifier of the safeguard: 'codes-imprimes', 'deux-passkeys', ...
    id          TEXT PRIMARY KEY,
    attested_at  TEXT NOT NULL DEFAULT (datetime('now')),
    attested_by TEXT NOT NULL,
    note        TEXT
) STRICT;
