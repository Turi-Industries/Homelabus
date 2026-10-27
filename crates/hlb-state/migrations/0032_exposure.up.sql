-- How the installation is reached from outside: its domain, where its certificates come
-- from, and the name the interface is published at.
--
-- One row, as for `appearance`: two would give routes that change with read order.
-- Absent, nothing is published — an installation nobody configured stays private,
-- rather than being given a domain it does not own.
--
-- ⚠️ No credential here: the DNS provider's are vault secrets (`dns-<provider>-*`).
CREATE TABLE exposure (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    domain          TEXT NOT NULL,
    certificates    TEXT NOT NULL CHECK (certificates IN ('acme', 'internal')),
    acme_email      TEXT,
    -- NULL with `acme`: one certificate per name, over HTTP-01.
    dns_provider    TEXT,
    staging         INTEGER NOT NULL DEFAULT 0,
    controller_host TEXT,
    modified_at     TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
