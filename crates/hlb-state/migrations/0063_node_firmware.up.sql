-- What fwupd says each machine's firmware could move to, as the privileged side's daily
-- pass read it. Homelabus never applies one: a firmware update is a person's, at the
-- machine — it may change what the next boot measures.
--
-- A failed reading keeps the last good one and says it failed, as `image_scans` does:
-- firmware unread is not firmware current. `updates` is JSON, the last good reading's.
CREATE TABLE node_firmware (
    hostname TEXT PRIMARY KEY,
    read_at INTEGER,
    failed_at INTEGER,
    error TEXT,
    updates TEXT NOT NULL DEFAULT '[]'
);
