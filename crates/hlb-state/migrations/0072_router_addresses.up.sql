-- Each node's address on the house's network, declared (`hlb router address`): where the
-- router forwards a port its services publish. Swarm's is the mesh's, which the router
-- does not reach.
CREATE TABLE router_addresses (
    node    TEXT PRIMARY KEY NOT NULL,
    address TEXT NOT NULL
);
