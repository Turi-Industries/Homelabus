-- SQLite ne retire pas une colonne avant la 3.35, et le faire par recréation perdrait
-- les invitations en cours. Les colonnes ont un DEFAULT : un binaire antérieur les
-- ignore sans erreur (§7bis, réversibilité).
SELECT 1;
