-- Une invitation peut servir plusieurs fois, et sa durée se choisit.
--
-- ## Pourquoi plusieurs usages
--
-- Inviter une équipe de cinq personnes demandait cinq liens à transmettre un par un.
-- Un lien unique partagé dans un canal d'équipe fait le même travail en une fois.
--
-- ## 🔴 Ce que ça coûte, et qui doit être dit
--
-- Un lien à N usages qui fuite fait entrer N personnes, pas une. Le compromis est
-- réel : plus le nombre est élevé, plus la fuite est coûteuse. C'est pourquoi le
-- défaut reste **1** — le cas sûr — et que l'interface affiche le nombre restant, pour
-- qu'un lien largement ouvert ne passe pas inaperçu.
--
-- Le nombre est FIXÉ à la création : l'augmenter après coup permettrait de rouvrir un
-- lien qu'on croit épuisé.
ALTER TABLE invitations ADD COLUMN usages_max INTEGER NOT NULL DEFAULT 1;
ALTER TABLE invitations ADD COLUMN usages INTEGER NOT NULL DEFAULT 0;

-- ⚠️ Les invitations existantes : celles déjà utilisées comptent pour un usage, les
-- autres pour zéro. Sans ça, une invitation consommée avant cette migration
-- redeviendrait utilisable — exactement ce que « usage unique » promettait d'empêcher.
UPDATE invitations SET usages = 1 WHERE utilise_le IS NOT NULL;
