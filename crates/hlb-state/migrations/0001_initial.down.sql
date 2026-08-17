-- 🔴 Retour arrière de la migration initiale : détruit TOUT l'état.
--
-- Il n'existe que pour que la chaîne de `down` soit complète — sans lui, la
-- vérification de réversibilité du §7bis refuserait toute mise à jour. Il ne sera
-- jamais exécuté par un rollback de version : on ne revient pas avant la première.
DROP TABLE IF EXISTS plan_actions;
DROP TABLE IF EXISTS pending_guides;
DROP TABLE IF EXISTS apps;
