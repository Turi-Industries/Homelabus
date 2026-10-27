-- The volume inventory, not the volumes themselves: the Docker data survives. The
-- backup, however, no longer knows WHAT to save until the apps are reinstalled.
DROP TABLE IF EXISTS app_volumes;
