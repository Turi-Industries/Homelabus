-- An invitation can be used several times, and its lifetime is chosen.
--
-- ## Why several uses
--
-- Inviting a team of five meant sending five links one by one. A single link shared
-- in a team channel does the same work in one go.
--
-- ## 🔴 What it costs, and what must be said
--
-- A link with N uses that leaks lets N people in, not one. The trade-off is real:
-- the higher the number, the more expensive the leak. That is why the default stays
-- **1** — the safe case — and why the interface shows the remaining count, so a
-- widely open link does not go unnoticed.
--
-- The number is FIXED at creation: raising it afterwards would reopen a link you
-- believe is exhausted.
ALTER TABLE invitations ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 1;
ALTER TABLE invitations ADD COLUMN uses INTEGER NOT NULL DEFAULT 0;

-- ⚠️ Existing invitations: those already used count for one use, the others for
-- zero. Without this, an invitation consumed before this migration would become
-- usable again — exactly what "single use" promised to prevent.
UPDATE invitations SET uses = 1 WHERE used_at IS NOT NULL;
