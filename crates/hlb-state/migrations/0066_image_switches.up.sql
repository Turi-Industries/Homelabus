-- An image an update has pushed to a service and is still watching. The frozen manifest
-- moves only once the new image is proved running, so until then reconciliation reads
-- the new image as drift and puts the old one back: Caddy 0.4.8, five seconds into its
-- switch on the lab (2026-11-08). A row here tells it the service is someone's for now.
--
-- `until` bounds it: an update that died mid-switch must not keep reconciliation away for
-- ever, and what it pushed was never proved, so going back to the frozen image is right.
CREATE TABLE image_switches (
    service TEXT PRIMARY KEY,
    image TEXT NOT NULL,
    until INTEGER NOT NULL
);
