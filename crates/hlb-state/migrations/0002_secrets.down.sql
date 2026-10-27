-- ⚠️ Destroys the ENCRYPTED secrets, not the master key. Secrets Homelabus
-- generates (database passwords) stay reconstructible, but the ones deposited by
-- hand do NOT: DNS token, CrowdSec bouncer key.
DROP TABLE IF EXISTS secrets;
