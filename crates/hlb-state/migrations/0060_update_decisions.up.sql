-- Who applies each update waiting, as the privileged side's hourly pass last decided: read
-- by the inbox, which never asks a registry itself. `why`, `notes` and `refused` are JSON of
-- hlb-api's wire types, written by that pass alone.
--
-- An approval and a refusal hold for one digest: a newer candidate clears both, so a click
-- never applies an image nobody looked at, and a refusal never outlives what it refused.
CREATE TABLE update_decisions (
    app TEXT PRIMARY KEY,
    digest TEXT NOT NULL,
    from_tag TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('rebuild', 'version', 'catalog', 'companions')),
    to_tag TEXT,
    who TEXT NOT NULL CHECK (who IN ('automatic', 'one-click', 'manual')),
    why TEXT,
    notes TEXT,
    decided_at INTEGER NOT NULL,
    refused TEXT,
    refused_at INTEGER,
    approved_by TEXT,
    approved_at INTEGER
);
