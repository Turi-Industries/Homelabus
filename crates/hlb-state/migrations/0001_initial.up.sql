-- État désiré et progression d'exécution.
--
-- Le controller n'est jamais la source de vérité unique (§9quater) : cette base est
-- reconstructible depuis le dépôt Git et le Swarm lui-même. Elle sert d'accélérateur
-- et de journal, pas de dépôt irremplaçable.

CREATE TABLE apps (
    name        TEXT PRIMARY KEY,
    -- Le manifest figé AU DÉPLOIEMENT (§4.8) : une évolution du catalogue ne
    -- modifie jamais une app en fonctionnement.
    manifest    TEXT NOT NULL,
    domain      TEXT,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
) STRICT;

-- Une ligne par action du plan. C'est ce qui rend l'exécution idempotente et
-- reprenable (§2ter.5) : on ne rejoue jamais une action déjà terminée.
CREATE TABLE plan_actions (
    app         TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    description TEXT NOT NULL,
    status      TEXT NOT NULL,
    error       TEXT,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (app, seq)
) STRICT;

CREATE INDEX idx_plan_actions_status ON plan_actions(app, status);

-- La file d'actions manuelles du §4.6. Persistante, pas une popup.
CREATE TABLE pending_guides (
    id          TEXT NOT NULL,
    app         TEXT NOT NULL REFERENCES apps(name) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    blocking    INTEGER NOT NULL,
    verified_at TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (app, id)
) STRICT;
