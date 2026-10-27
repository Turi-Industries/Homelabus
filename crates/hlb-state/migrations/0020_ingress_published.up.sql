-- What was actually published the last time the ingress configuration was applied.
--
-- 🔴 Without this table, comparing "declared" and "real" is impossible: both
-- would come from the same function, and the comparison could never fail. Yet the
-- dangerous case is precisely the one where the installed Caddyfile no longer matches
-- the manifests — an app installed without reapplying the ingress, or a removed app
-- whose route stays open.
CREATE TABLE ingress_published (
    host        TEXT PRIMARY KEY,
    app         TEXT NOT NULL,
    -- 0 = reachable from the VPN only, 1 = open to the internet.
    public      INTEGER NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
