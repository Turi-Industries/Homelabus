-- The one node the privileged side is rebooting, or gave up rebooting. One row at most:
-- a reboot is one node at a time, and the row outlives the daemon, which may run on
-- the node it reboots.
--
-- `phase`: draining (its services are leaving), rebooting (the command was sent),
-- stopped (gave up: no automatic reboot until `hlb node upgrade` succeeds on it).
-- `drained`: whether the daemon drained it, so only then does it put it back.
CREATE TABLE node_reboots (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    node_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    phase TEXT NOT NULL,
    drained INTEGER NOT NULL,
    started_at INTEGER NOT NULL,
    phase_at INTEGER NOT NULL,
    detail TEXT
);
