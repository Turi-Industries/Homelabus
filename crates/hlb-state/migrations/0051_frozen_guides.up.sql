-- The guide frozen beside the manifest. Read from today's catalog, an installed app's
-- acknowledgements, nightly re-checks and post-restore steps followed a guide its
-- manifest was never deployed with — and none at all once the app left the catalog.
-- NULL: recorded before this column, read from the catalog until the next upgrade.
ALTER TABLE apps ADD COLUMN guide TEXT;
