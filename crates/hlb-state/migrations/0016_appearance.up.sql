-- The installation's visual identity.
--
-- ## Why in the database rather than compiled into the interface
--
-- The name of the house could be a wasm constant. But changing it would then require
-- recompiling and redeploying the interface, which puts "what we are called" on the
-- same footing as an architecture decision. Here an administrator edits it from the
-- settings screen and the binary stays the same.
--
-- ## A single row, guaranteed by the schema
--
-- `id INTEGER PRIMARY KEY CHECK (id = 1)`: two rows become impossible. Without that
-- constraint, a second row inserted by mistake would give a brand that changes with
-- read order — a defect you would never reproduce.
CREATE TABLE appearance (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    name          TEXT NOT NULL,
    product      TEXT NOT NULL,
    -- Accent colour in hexadecimal ("7B8CFF"). NULL = the theme's own.
    accent       TEXT,
    -- The logo, as PNG. NULL = painted monogram.
    --
    -- ⚠️ Stored here rather than on disk: the database goes into the backups, a file
    -- dropped beside it would not, and a restore would return an installation with
    -- no logo and nothing signalling why.
    logo         BLOB,
    footer         TEXT,
    default_theme TEXT,
    modified_at   TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- The default brand, so the interface has something to show on first start rather
-- than an empty header.
INSERT INTO appearance (id, name, product) VALUES (1, 'Turi Industries', 'Homelabus');

-- A person's display preferences.
--
-- Separate from `user_roles`: a theme is not a right, and mixing them would route a
-- colour change through role access control.
CREATE TABLE user_prefs (
    user       TEXT PRIMARY KEY REFERENCES users(name) ON DELETE CASCADE,
    theme      TEXT,
    modified_at TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
