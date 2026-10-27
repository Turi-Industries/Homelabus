-- Announcements and incidents.
--
-- ## Why a table rather than a file
--
-- An announcement has an audience, a deadline and a thread of updates. A Markdown
-- file carries none of that, and it would have to be backed up separately —
-- therefore forgotten at restore time.
CREATE TABLE announcements (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL,
    body      TEXT NOT NULL,

    -- 'info' | 'maintenance' | 'warning' | 'incident'
    level     TEXT NOT NULL DEFAULT 'info',

    -- Pinned at the top of the portal.
    pinned   INTEGER NOT NULL DEFAULT 0,

    -- The minimum role needed to see it. NULL = everyone.
    --
    -- ⚠️ An operational announcement ("databases restart at 3 a.m.") does not
    -- interest a portal user, and flooding them with messages that do not concern
    -- them makes them stop reading — precisely when one of them will matter.
    audience   TEXT,

    author     TEXT NOT NULL,
    published_at TEXT NOT NULL DEFAULT (datetime('now')),

    -- 🔴 An expired announcement leaves the portal but STAYS in the database:
    -- it is the incident history, and it is what you re-read afterwards.
    expires_at  INTEGER
) STRICT;

CREATE INDEX idx_annonces_ordre ON announcements(pinned DESC, id DESC);

-- The thread of an incident.
--
-- 🔴 An incident is FOLLOWED, not rewritten. Editing the original body would
-- erase the chronology — and the chronology is exactly what you re-read afterwards:
-- when you knew, when you understood, when it was fixed.
CREATE TABLE announcement_updates (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    announcement INTEGER NOT NULL REFERENCES announcements(id) ON DELETE CASCADE,
    body   TEXT NOT NULL,
    author  TEXT NOT NULL,
    at      TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

CREATE INDEX idx_annonce_maj ON announcement_updates(announcement, id);
