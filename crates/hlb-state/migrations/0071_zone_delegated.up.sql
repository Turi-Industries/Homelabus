-- The registrar delegates to the house's zone (`hlb zone switch`): Caddy's challenges
-- and Stalwart's DKIM keys are written into it over RFC 2136 from then on, each in a
-- zone of its own below it. 0: the provider's zone is still the one the internet asks.
ALTER TABLE zone ADD COLUMN delegated INTEGER NOT NULL DEFAULT 0 CHECK (delegated IN (0, 1));
