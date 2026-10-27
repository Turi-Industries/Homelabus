-- Back to the ids the previous binary knows: without this, it would read every
-- safeguard attested by the newer one as never attested.
UPDATE breakglass SET id = 'codes-imprimes' WHERE id = 'printed-codes';
UPDATE breakglass SET id = 'deux-passkeys' WHERE id = 'two-passkeys';
UPDATE breakglass SET id = 'pocketid-restaure' WHERE id = 'pocketid-restored';
