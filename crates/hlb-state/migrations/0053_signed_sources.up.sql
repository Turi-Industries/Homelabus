-- A source fetched from a URL: its key, and the highest index counter read from it —
-- a mirror serving a lower one is replaying an old index. NULL url: a directory.
ALTER TABLE catalog_sources ADD COLUMN url TEXT;
ALTER TABLE catalog_sources ADD COLUMN key TEXT;
ALTER TABLE catalog_sources ADD COLUMN counter INTEGER;

-- The counter of the signed index an app was installed from, frozen with it.
ALTER TABLE apps ADD COLUMN source_index INTEGER;
