-- Each machine's disks as SMART says them, and its ZFS pools as `zpool status` does, read
-- by the privileged side's daily pass. Nothing is repaired or scheduled from here.
--
-- A failed reading keeps the last good one and says it failed, as `node_firmware` does:
-- a disk unread is not a disk healthy. `disks` and `pools` are JSON, the last good
-- reading's — each disk carrying when one of its error counters last grew, which only a
-- comparison with the reading before can tell.
CREATE TABLE node_disks (
    hostname TEXT PRIMARY KEY,
    read_at INTEGER,
    failed_at INTEGER,
    error TEXT,
    disks TEXT NOT NULL DEFAULT '[]',
    pools TEXT NOT NULL DEFAULT '[]'
);
