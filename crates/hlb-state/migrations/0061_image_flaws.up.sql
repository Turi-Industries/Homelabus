-- The flaws a fix exists for in each image running, as the privileged side's daily scan
-- read them (Grype, against the package list Syft made once per digest).
--
-- A failed reading keeps the last good one and says it failed: an unread image is not a
-- clean one. `first_seen` survives every reading, so "new since" is a fact, not a guess.
CREATE TABLE image_scans (
    digest TEXT PRIMARY KEY,
    image TEXT NOT NULL,
    read_at INTEGER,
    failed_at INTEGER,
    error TEXT
);

CREATE TABLE image_flaws (
    digest TEXT NOT NULL REFERENCES image_scans (digest) ON DELETE CASCADE,
    id TEXT NOT NULL,
    package TEXT NOT NULL,
    severity TEXT NOT NULL,
    version TEXT NOT NULL,
    fixed_in TEXT NOT NULL,
    exploited INTEGER NOT NULL,
    epss REAL,
    first_seen INTEGER NOT NULL,
    PRIMARY KEY (digest, id, package)
);

-- One alert per flaw per app: said once, then in the weekly digest until it is gone.
CREATE TABLE flaw_alerts (
    app TEXT NOT NULL,
    id TEXT NOT NULL,
    alerted_at INTEGER NOT NULL,
    PRIMARY KEY (app, id)
);

-- When the weekly digest was last sent: one row at most.
CREATE TABLE flaw_digest (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    sent_at INTEGER NOT NULL
);
