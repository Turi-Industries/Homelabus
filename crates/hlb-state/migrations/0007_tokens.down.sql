-- 🔴 Détruit tous les jetons d'accès. Après un retour arrière, l'API n'accepte plus
-- personne tant que de nouveaux jetons n'ont pas été créés — ce qui est le bon sens
-- de l'échec : mieux vaut fermé que grand ouvert.
DROP TABLE IF EXISTS api_tokens;
