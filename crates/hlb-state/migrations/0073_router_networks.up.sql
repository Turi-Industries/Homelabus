-- The house's networks beyond the trusted one (`hlb router network`), by kind: the VLAN
-- tag each is carried on. Its address is the router's, read back, never declared here.
CREATE TABLE router_networks (
    kind TEXT PRIMARY KEY NOT NULL,
    vlan INTEGER NOT NULL UNIQUE
);
