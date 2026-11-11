-- The server each app database was provisioned on. The manifest names an engine and the
-- house places it: a vital app's PostgreSQL lives on `postgres-vital` once the house has
-- a site. No row means the engine's shared server, where every database provisioned
-- before this lives.
CREATE TABLE database_servers (
    app TEXT NOT NULL,
    database TEXT NOT NULL,
    server TEXT NOT NULL,
    PRIMARY KEY (app, database)
);
