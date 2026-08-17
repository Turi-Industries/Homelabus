-- 🔴 Le journal d'audit est APPEND-ONLY par conception (§9) : rien dans le code ne
-- permet d'en supprimer une ligne. Ce `down` est le seul chemin qui l'efface, et il
-- n'existe que pour un retour arrière de version.
--
-- Un rollback perd donc la trace de qui a fait quoi. C'est un vrai coût, assumé :
-- l'alternative — une migration sans inverse — interdirait toute mise à jour.
DROP TABLE IF EXISTS audit_log;
