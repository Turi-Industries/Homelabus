-- 🔴 Détruit l'HISTORIQUE des sauvegardes, pas les sauvegardes. Conséquence
-- concrète : toutes les apps repassent en « jamais sauvegardée », donc toutes
-- deviennent dues immédiatement — et le prochain tour lancera un instantané pour
-- chacune. C'est bruyant mais sans danger.
DROP TABLE IF EXISTS restore_verifications;
DROP TABLE IF EXISTS backup_runs;
