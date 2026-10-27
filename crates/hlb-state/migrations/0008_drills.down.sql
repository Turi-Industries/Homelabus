-- Destroys the drill history. Consequence: preparedness goes back to "NEVER
-- exercised", which is the right way to fail — better to drill needlessly than to
-- believe yourself ready by mistake.
DROP TABLE IF EXISTS dr_drills;
