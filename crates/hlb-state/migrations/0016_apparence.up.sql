-- L'identité visuelle de l'installation (lot 2.2).
--
-- ## Pourquoi en base plutôt que compilée dans l'interface
--
-- Le nom de la maison pourrait être une constante du wasm. Mais alors le changer
-- exigerait de recompiler et redéployer l'interface, ce qui met « comment on s'appelle »
-- au même niveau qu'une décision d'architecture. Ici, un administrateur l'édite depuis
-- l'écran des réglages et le binaire reste le même.
--
-- ## Une seule ligne, garantie par le schéma
--
-- `id INTEGER PRIMARY KEY CHECK (id = 1)` : deux lignes deviennent impossibles. Sans
-- cette contrainte, une seconde ligne insérée par erreur donnerait une marque qui change
-- selon l'ordre de lecture — un défaut qu'on ne reproduirait jamais.
CREATE TABLE apparence (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    nom          TEXT NOT NULL,
    produit      TEXT NOT NULL,
    -- Couleur d'accent en hexadécimal (« 7B8CFF »). NULL = celle du thème.
    accent       TEXT,
    -- Le logo, en PNG. NULL = monogramme peint.
    --
    -- ⚠️ Stocké ici plutôt que sur le disque : la base part dans les sauvegardes, un
    -- fichier posé à côté n'en ferait pas partie, et une restauration rendrait une
    -- installation sans logo sans que rien ne le signale.
    logo         BLOB,
    pied         TEXT,
    theme_defaut TEXT,
    modifie_le   TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- La marque par défaut, pour que l'interface ait quelque chose à afficher au premier
-- démarrage plutôt qu'un en-tête vide.
INSERT INTO apparence (id, nom, produit) VALUES (1, 'Turi Industries', 'HomelabUS');

-- Les préférences d'affichage d'une personne.
--
-- Séparées de `user_roles` : un thème n'est pas un droit, et les mélanger ferait
-- passer un changement de couleur par le contrôle d'accès aux rôles.
CREATE TABLE user_prefs (
    user       TEXT PRIMARY KEY REFERENCES users(name) ON DELETE CASCADE,
    theme      TEXT,
    modifie_le TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;
