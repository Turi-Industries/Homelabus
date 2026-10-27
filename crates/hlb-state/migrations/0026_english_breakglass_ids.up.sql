-- The break-glass safeguards whose ids were French, renamed in place.
--
-- An attestation is keyed on the id the code knows: renamed in the code alone, every
-- safeguard attested before the upgrade would read as never attested, and the recovery
-- screen would go red the day after for checks that had been done.
--
-- ⚠️ `audit_log` is deliberately NOT rewritten, though it holds French words too
-- (`gerer-accounts`, `anonyme`, the targets of these attestations). Each entry's hash
-- covers its actor, action and target: rewriting them breaks the chain, and
-- `hlb audit --verify` reports tampering on every installation — while rehashing it to
-- hide that is exactly what tampering looks like. The log keeps the words it recorded;
-- nothing matches on them, they are read by people.
UPDATE breakglass SET id = 'printed-codes' WHERE id = 'codes-imprimes';
UPDATE breakglass SET id = 'two-passkeys' WHERE id = 'deux-passkeys';
UPDATE breakglass SET id = 'pocketid-restored' WHERE id = 'pocketid-restaure';
