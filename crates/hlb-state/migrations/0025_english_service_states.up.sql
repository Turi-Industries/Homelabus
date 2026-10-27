-- The two service states still stored in French, renamed in place.
--
-- `ServiceState` went to English on the wire on 2026-10-05, and this table is the one
-- place its values are kept. They are written and read by a hand-written mapping in
-- `hlb-state`, not by serde, so nothing would have failed without this migration: the
-- mapping would simply have kept writing French forever, or — had it been switched to
-- the new words alone — every day recorded before the upgrade would have read as "no
-- sample", the gap the status page draws as missing history.
UPDATE service_uptime_samples SET state = 'operational' WHERE state = 'operationnel';
UPDATE service_uptime_samples SET state = 'degraded' WHERE state = 'degrade';
