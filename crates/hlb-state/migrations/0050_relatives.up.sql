-- The relatives each sealed kit is mailed to, at an address of their own outside the
-- house: what they hold must outlive the house's mail.
CREATE TABLE relatives (
    address TEXT PRIMARY KEY,
    added   INTEGER NOT NULL
) STRICT;
