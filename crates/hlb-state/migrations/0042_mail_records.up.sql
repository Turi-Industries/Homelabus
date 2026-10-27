-- The last reading of each DNS record a mail domain needs, from a public resolver.
-- Replaced whole at every reading: a domain Stalwart no longer hosts, or a DKIM
-- selector it retired, is not left reporting a record nobody needs.
CREATE TABLE mail_records (
    domain     TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    purpose    TEXT    NOT NULL CHECK (purpose IN ('dkim', 'spf', 'mx', 'dmarc')),
    expected   TEXT    NOT NULL,
    state      TEXT    NOT NULL CHECK (state IN ('published', 'missing', 'differs', 'unreadable')),
    observed   TEXT    NOT NULL,
    checked_at INTEGER NOT NULL,
    PRIMARY KEY (domain, name, purpose)
) STRICT;
