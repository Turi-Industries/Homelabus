-- What a held service is to be given back. Read from Swarm by whoever starts it, a pass
-- after one that died read 0 and "started" the service at 0, so it stayed down with no hold
-- left to say why. NULL: held before this column, and started by nobody but reconciliation.
ALTER TABLE service_holds ADD COLUMN replicas INTEGER;
