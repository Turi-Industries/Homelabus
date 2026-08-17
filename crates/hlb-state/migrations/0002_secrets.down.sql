-- ⚠️ Détruit les secrets CHIFFRÉS, pas la clé maîtresse. Les secrets restent
-- reconstructibles pour ceux que HomelabUS génère (mots de passe de base), mais
-- PAS pour ceux déposés à la main : jeton DNS, clé de videur CrowdSec.
DROP TABLE IF EXISTS secrets;
