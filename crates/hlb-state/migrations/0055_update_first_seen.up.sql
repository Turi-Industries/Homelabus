-- When each image an update would move to was first proposed here: the registries date a
-- build, GHCR and Quay often not at all, and neither says when this house could have known.
-- `last_seen_at` is the last pass that still proposed it: one replaced by a newer build
-- is no longer waiting for anything.
CREATE TABLE update_first_seen (
    app           TEXT NOT NULL,
    digest        TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    PRIMARY KEY (app, digest)
) STRICT;
