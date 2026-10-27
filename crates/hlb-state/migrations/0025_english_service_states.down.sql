-- Back to the words the previous binary reads: without this, every sample recorded by
-- the newer one would be skipped as unreadable, and its days shown as missing.
UPDATE service_uptime_samples SET state = 'operationnel' WHERE state = 'operational';
UPDATE service_uptime_samples SET state = 'degrade' WHERE state = 'degraded';
