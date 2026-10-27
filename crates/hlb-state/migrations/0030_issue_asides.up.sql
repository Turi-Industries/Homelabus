-- Inbox lines a person set aside, until a moment. `cause` is the `hlb_api::issues::Cause`
-- as JSON — its identity; `attention` and `subjects` are what the line was when it was
-- set aside: worse than that, and it is back in view.
CREATE TABLE issue_asides (
    user       TEXT NOT NULL,
    cause      TEXT NOT NULL,
    until      INTEGER NOT NULL,
    attention  TEXT NOT NULL,
    subjects   INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user, cause)
) STRICT;
