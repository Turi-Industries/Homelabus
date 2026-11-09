-- What the site's status page announced, mirrored into the house's announcements: one
-- row per incident of the page, keyed by the timestamp its announcer gave the entry —
-- the page appends to an incident's one entry, never adds another.
--
-- `seen` is the page's message as last mirrored: what follows it is new, a follow-up of
-- the house's announcement, which is never rewritten. `announcement` is NULL once a
-- person removed the house's copy: the next pass must not bring it back.
CREATE TABLE site_announcements (
    timestamp TEXT PRIMARY KEY,
    announcement INTEGER REFERENCES announcements(id) ON DELETE SET NULL,
    seen TEXT NOT NULL,
    archived INTEGER NOT NULL DEFAULT 0
) STRICT;
