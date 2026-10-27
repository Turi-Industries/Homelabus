-- A day of measurements, one a minute, for the home's curves: what each machine's
-- processor, memory, swap, load, disks and network did, and how many applications ran.
-- `subject` is a node's agent address, or '' for the installation as a whole; `metric`
-- is `cpu`, `memory`, `swap`, `load`, `disk:<mount>`, `net_rx`, `net_tx` (byte counters,
-- turned into rates when read) or `apps_running`. Pruned past a day by the recorder.
CREATE TABLE history (
    metric  TEXT NOT NULL,
    subject TEXT NOT NULL,
    at      INTEGER NOT NULL,
    value   REAL NOT NULL,
    PRIMARY KEY (metric, subject, at)
) STRICT, WITHOUT ROWID;
