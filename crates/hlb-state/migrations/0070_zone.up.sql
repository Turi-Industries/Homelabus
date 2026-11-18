-- The house's own zone, signed by its Knot (`hlb zone set`). One row: one registered
-- name whose name servers the house serves. Absent, the house serves no zone and its
-- names are the DNS provider's.
--
-- `addresses` are the front door's public addresses, space-separated: every published
-- name resolves there. `extra` holds the owner's own lines, relative to the apex.
CREATE TABLE zone (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    apex        TEXT NOT NULL,
    addresses   TEXT NOT NULL,
    extra       TEXT NOT NULL DEFAULT '',
    modified_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
