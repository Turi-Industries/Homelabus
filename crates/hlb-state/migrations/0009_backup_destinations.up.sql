-- Destinations de sauvegarde multiples et leur routage (§8.1).
--
-- 🔴 La colonne `destination` sur `backup_runs` est ce qui empêche une destination
-- fraîche d'en masquer une périmée. Sans elle, `MAX(finished_at)` agrège toutes les
-- destinations : un NAS sauvegardé toutes les 4 h ferait passer un hors-site mort
-- depuis trois semaines pour une sauvegarde de 2 h.

CREATE TABLE backup_destinations (
    name               TEXT PRIMARY KEY,
    -- Chemin local, ou URL restic `s3:…`.
    location           TEXT NOT NULL,
    -- Classes acceptées, séparées par des virgules : « critique,volumineux ».
    -- Vide = la destination ne reçoit rien, et `describe()` le dit.
    classes            TEXT NOT NULL DEFAULT '',
    -- Nom du secret portant « clé_accès:clé_secrète ». Jamais la valeur elle-même.
    credentials_secret TEXT,
    created_at         TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Le routage par app et par classe. Absent = on retombe sur les classes que la
-- destination accepte globalement.
CREATE TABLE backup_routes (
    app         TEXT NOT NULL,
    class       TEXT NOT NULL,
    destination TEXT NOT NULL REFERENCES backup_destinations(name) ON DELETE CASCADE,
    PRIMARY KEY (app, class, destination)
) STRICT;

-- NULL pour les exécutions antérieures à cette migration : on ne sait pas où elles
-- sont allées, et prétendre le contraire serait pire que de l'ignorer.
ALTER TABLE backup_runs ADD COLUMN destination TEXT;

CREATE INDEX idx_backup_runs_dest ON backup_runs(app, destination, status, finished_at DESC);
