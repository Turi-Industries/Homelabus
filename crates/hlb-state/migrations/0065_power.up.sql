-- The UPS as the privileged side last read it through NUT, and the stop it ordered.
--
-- One row each, kept here rather than in the daemon's memory: the daemon stops with the
-- machine it runs on, and comes back after the power with nothing else to tell it that
-- every app was left scaled to zero, nor in which waves to start them again.
CREATE TABLE ups_reading (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    read_at INTEGER,
    failed_at INTEGER,
    error TEXT,
    -- NUT's `ups.status`: `OL`, `OB`, `OB LB`, `FSD OB LB`…
    status TEXT,
    runtime_s INTEGER,
    charge INTEGER,
    -- When the UPS went on battery, or came back on line: what each delay is counted from.
    on_battery_since INTEGER,
    online_since INTEGER
);

CREATE TABLE power_stop (
    one INTEGER PRIMARY KEY CHECK (one = 1),
    -- `stopping`, `stopped`, `starting`.
    phase TEXT NOT NULL,
    reason TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    phase_at INTEGER NOT NULL,
    -- JSON: the waves, each a list of [service, replicas], in the order they stop.
    waves TEXT NOT NULL
);
