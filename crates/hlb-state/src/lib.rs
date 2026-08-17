//! Le store d'état du controller.
//!
//! Deux responsabilités :
//!   1. mémoriser le **manifest figé au déploiement** (§4.8) — le catalogue peut
//!      évoluer sans jamais modifier une app en fonctionnement ;
//!   2. journaliser la progression des plans, ce qui donne gratuitement
//!      **l'idempotence et la reprise après échec** (§2ter.5).
//!
//! Cette base n'est pas irremplaçable : elle est reconstructible depuis le dépôt Git
//! et le Swarm lui-même (§9quater).

use std::path::Path;
use std::str::FromStr;

use hlb_types::Manifest;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("base d'état : {0}")]
    Db(#[from] sqlx::Error),

    #[error("migration : {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    #[error("manifest stocké illisible pour « {app} » : {source}")]
    StoredManifest {
        app: String,
        #[source]
        source: serde_yaml_ng::Error,
    },

    #[error("app « {0} » inconnue")]
    UnknownApp(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Statut d'une action dans un plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionStatus {
    Pending,
    Done,
    Failed,
    /// Action reconnue mais pas encore implémentée par l'exécuteur.
    /// Explicitement distincte de `Done` : on ne prétend jamais avoir fait.
    Unimplemented,
}

impl ActionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Unimplemented => "unimplemented",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "done" => Self::Done,
            "failed" => Self::Failed,
            "unimplemented" => Self::Unimplemented,
            _ => Self::Pending,
        }
    }

    /// Une action terminée ne doit jamais être rejouée.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done)
    }
}

#[derive(Debug, Clone)]
pub struct ActionRecord {
    pub seq: i64,
    pub kind: String,
    pub description: String,
    pub status: ActionStatus,
    pub error: Option<String>,
}

pub struct State {
    pool: SqlitePool,
}

impl State {
    /// Ouvre (et crée si besoin) la base à `path`, puis applique les migrations.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let opts = SqliteConnectOptions::new()
            .filename(path.as_ref())
            .create_if_missing(true)
            // WAL : lectures concurrentes pendant qu'une réconciliation écrit.
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .foreign_keys(true);

        Self::from_options(opts).await
    }

    /// Base en mémoire, pour les tests.
    pub async fn in_memory() -> Result<Self> {
        let opts = SqliteConnectOptions::from_str(":memory:")
            .map_err(Error::Db)?
            .foreign_keys(true);
        Self::from_options(opts).await
    }

    async fn from_options(opts: SqliteConnectOptions) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            // SQLite en mémoire : plusieurs connexions verraient des bases distinctes.
            .max_connections(1)
            .connect_with(opts)
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Enregistre l'intention d'installer une app, en figeant son manifest.
    pub async fn upsert_app(
        &self,
        name: &str,
        manifest: &Manifest,
        domain: Option<&str>,
    ) -> Result<()> {
        let yaml = serde_yaml_ng::to_string(manifest).map_err(|source| Error::StoredManifest {
            app: name.to_string(),
            source,
        })?;

        sqlx::query(
            "INSERT INTO apps (name, manifest, domain, status)
             VALUES (?1, ?2, ?3, 'installing')
             ON CONFLICT(name) DO UPDATE SET
                 manifest = excluded.manifest,
                 domain = excluded.domain,
                 updated_at = datetime('now')",
        )
        .bind(name)
        .bind(&yaml)
        .bind(domain)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Le manifest **tel qu'il a été déployé**, pas celui du catalogue courant.
    pub async fn app_manifest(&self, name: &str) -> Result<Manifest> {
        let row = sqlx::query("SELECT manifest FROM apps WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| Error::UnknownApp(name.to_string()))?;

        let yaml: String = row.try_get("manifest")?;
        serde_yaml_ng::from_str(&yaml).map_err(|source| Error::StoredManifest {
            app: name.to_string(),
            source,
        })
    }

    /// Le domaine choisi à l'installation, nécessaire pour résoudre les gabarits.
    pub async fn app_domain(&self, name: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT domain FROM apps WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(r.try_get("domain")?),
            None => Ok(None),
        }
    }

    /// Mémorise un volume et son emplacement réel.
    pub async fn add_volume(
        &self,
        app: &str,
        name: &str,
        mountpoint: &str,
        backup: bool,
        sqlite: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO app_volumes (app, name, mountpoint, backup, sqlite)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(app, name) DO UPDATE SET
                 mountpoint = excluded.mountpoint,
                 backup = excluded.backup,
                 sqlite = excluded.sqlite",
        )
        .bind(app)
        .bind(name)
        .bind(mountpoint)
        .bind(backup as i64)
        .bind(sqlite as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Les volumes qui contiennent une base SQLite (§3.4).
    ///
    /// 🔴 Ceux-là ne peuvent PAS être sauvegardés par simple copie de fichiers : il
    /// leur faut un instantané cohérent au préalable. Renvoie `(app, nom, montage)`.
    pub async fn sqlite_volumes(&self) -> Result<Vec<(String, String, String)>> {
        let rows = sqlx::query(
            "SELECT app, name, mountpoint FROM app_volumes
             WHERE sqlite = 1 AND backup = 1 ORDER BY app, name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("app")?,
                    r.try_get("name")?,
                    r.try_get("mountpoint")?,
                ))
            })
            .collect()
    }

    /// Les volumes d'une app à sauvegarder : (nom, point de montage).
    ///
    /// Ne renvoie que ceux marqués `backup` — un cache n'a pas à occuper de la place
    /// dans le dépôt.
    pub async fn volumes_to_backup(&self, app: &str) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query(
            "SELECT name, mountpoint FROM app_volumes
             WHERE app = ?1 AND backup = 1 ORDER BY name",
        )
        .bind(app)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("name")?, r.try_get("mountpoint")?)))
            .collect()
    }

    /// Consigne une action dans le journal d'audit (§9).
    ///
    /// 🔴 Append-only : ce crate n'expose aucun moyen de supprimer ni de modifier
    /// une entrée. Un journal réécrivable ne prouve rien.
    pub async fn audit(
        &self,
        actor: &str,
        role: hlb_types::Role,
        action: &str,
        target: &str,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_log (actor, role, action, target, outcome, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(actor)
        .bind(role.as_str())
        .bind(action)
        .bind(target)
        .bind(outcome)
        .bind(detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Les dernières entrées du journal : (quand, acteur, action, cible, issue).
    pub async fn audit_trail(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, String, String, String, String)>> {
        let rows = sqlx::query(
            "SELECT at, actor, action, target, outcome FROM audit_log
             ORDER BY at DESC, id DESC LIMIT ?1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("at")?,
                    r.try_get("actor")?,
                    r.try_get("action")?,
                    r.try_get("target")?,
                    r.try_get("outcome")?,
                ))
            })
            .collect()
    }

    /// Enregistre une sauvegarde et son issue.
    pub async fn record_backup(
        &self,
        app: &str,
        kind: &str,
        snapshot_id: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO backup_runs (app, kind, snapshot_id, status, error, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))",
        )
        .bind(app)
        .bind(kind)
        .bind(snapshot_id)
        .bind(if error.is_some() { "failed" } else { "ok" })
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Âge de la dernière sauvegarde **réussie**, en secondes.
    ///
    /// 🔴 On ignore délibérément les échecs : un échec ne doit pas repousser
    /// l'échéance, sinon une sauvegarde cassée se ferait de plus en plus rare (§8.1).
    pub async fn seconds_since_last_success(&self, app: &str) -> Result<Option<i64>> {
        let row = sqlx::query(
            "SELECT CAST(strftime('%s','now') AS INTEGER)
                    - CAST(strftime('%s', MAX(finished_at)) AS INTEGER) AS age
             FROM backup_runs WHERE app = ?1 AND status = 'ok'",
        )
        .bind(app)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.try_get::<Option<i64>, _>("age").ok().flatten()))
    }

    /// Défait les migrations jusqu'à la version `cible` incluse (§7bis).
    ///
    /// 🔴 **Opération destructrice.** Chaque `down` supprime les tables que sa
    /// migration avait créées : revenir avant `0005` efface le journal d'audit,
    /// avant `0004` l'historique des sauvegardes. Le `down` de chaque migration
    /// documente ce qui est perdu.
    ///
    /// ⚠️ `cible` est le numéro de la dernière migration **conservée**. Passer `4`
    /// défait `0005` et `0006`, et garde `0001` à `0004`.
    ///
    /// N'existe que pour le retour arrière d'une version : un binaire N ne sait pas
    /// lire un schéma N+1, et sans ce chemin il n'y aurait aucune sortie.
    pub async fn undo_migrations(&self, cible: i64) -> Result<()> {
        tracing::warn!(cible, "🔴 retour arrière du schéma — opération destructrice");
        sqlx::migrate!("./migrations").undo(&self.pool, cible).await?;
        Ok(())
    }

    /// La dernière migration appliquée.
    pub async fn schema_version(&self) -> Result<Option<i64>> {
        let row = sqlx::query("SELECT MAX(version) AS v FROM _sqlx_migrations")
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| r.try_get::<Option<i64>, _>("v").ok().flatten()))
    }

    /// Les bases de données de chaque app, telles que son manifest FIGÉ les déclare.
    ///
    /// 🔴 On lit le manifest figé (§4.8), pas le catalogue courant : une app installée
    /// il y a six mois doit être sauvegardée selon ce qu'elle demandait ALORS. Un
    /// catalogue qui aurait changé de nom de base ferait sauvegarder une base vide en
    /// laissant l'ancienne dériver sans filet.
    ///
    /// Renvoie `(app, moteur, base, rôle, secret du mot de passe)`.
    pub async fn app_databases(&self) -> Result<Vec<(String, String, String, String)>> {
        let mut out = Vec::new();

        for (app, statut) in self.installed_apps().await? {
            // Une app en échec n'a probablement pas de base provisionnée ; tenter de
            // la sauvegarder produirait un échec par app à chaque tour.
            if statut == "failed" {
                continue;
            }
            let Ok(m) = self.app_manifest(&app).await else {
                continue;
            };

            for c in &m.spec.requires {
                if let hlb_types::Capability::Database { engine, name } = c {
                    // Même convention que le résolveur : sans nom explicite, la base
                    // porte le nom de l'app. Les deux DOIVENT rester alignés, sinon on
                    // sauvegarderait une base qui n'existe pas.
                    let db = name.clone().unwrap_or_else(|| app.clone());
                    out.push((
                        app.clone(),
                        engine.service_name().to_string(),
                        db,
                        format!("{app}-db-password"),
                    ));
                }
            }
        }
        Ok(out)
    }

    /// Les sauvegardes de base PostgreSQL réussies, les plus anciennes d'abord (§8.1).
    ///
    /// Ce sont les points de départ possibles d'un rejeu WAL. Les échecs sont exclus :
    /// une base de départ incomplète ne restaure rien, et la faire figurer dans la
    /// fenêtre restaurable annoncerait une garantie qu'on n'a pas.
    pub async fn base_backups(&self, app: &str) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT snapshot_id, CAST(strftime('%s', finished_at) AS INTEGER) AS at
             FROM backup_runs
             WHERE app = ?1 AND kind = 'pg-basebackup'
               AND status = 'ok' AND snapshot_id IS NOT NULL
             ORDER BY finished_at ASC, id ASC",
        )
        .bind(app)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|r| {
                Some((
                    r.try_get::<String, _>("snapshot_id").ok()?,
                    r.try_get::<i64, _>("at").ok()?,
                ))
            })
            .collect())
    }

    /// L'instantané le plus récent d'une app, pour le vérifier.
    pub async fn latest_snapshot(&self, app: &str) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT snapshot_id FROM backup_runs
             WHERE app = ?1 AND status = 'ok' AND snapshot_id IS NOT NULL
             -- `datetime('now')` a une résolution à la seconde : deux sauvegardes
             -- rapprochées auraient le même horodatage. L'id auto-incrémenté
             -- départage de façon fiable, car il suit l'ordre d'insertion.
             ORDER BY finished_at DESC, id DESC LIMIT 1",
        )
        .bind(app)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.try_get::<Option<String>, _>("snapshot_id").ok().flatten()))
    }

    pub async fn record_verification(
        &self,
        app: &str,
        snapshot_id: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO restore_verifications (app, snapshot_id, status, detail)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(app)
        .bind(snapshot_id)
        .bind(if detail.is_some() { "failed" } else { "ok" })
        .bind(detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Âge de la dernière vérification réussie, en secondes.
    pub async fn seconds_since_last_verification(&self, app: &str) -> Result<Option<i64>> {
        let row = sqlx::query(
            "SELECT CAST(strftime('%s','now') AS INTEGER)
                    - CAST(strftime('%s', MAX(verified_at)) AS INTEGER) AS age
             FROM restore_verifications WHERE app = ?1 AND status = 'ok'",
        )
        .bind(app)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.try_get::<Option<i64>, _>("age").ok().flatten()))
    }

    /// Fige le digest résolu au déploiement (§7).
    ///
    /// Le manifest stocké est réécrit : c'est bien le digest qui fait foi ensuite,
    /// pas le tag.
    pub async fn set_app_digest(&self, name: &str, digest: &str) -> Result<()> {
        let mut m = self.app_manifest(name).await?;
        m.spec.image.digest = Some(digest.to_string());
        self.upsert_app(name, &m, self.app_domain(name).await?.as_deref())
            .await
    }

    pub async fn set_app_status(&self, name: &str, status: &str) -> Result<()> {
        sqlx::query(
            "UPDATE apps SET status = ?2, updated_at = datetime('now') WHERE name = ?1",
        )
        .bind(name)
        .bind(status)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn installed_apps(&self) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query("SELECT name, status FROM apps ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("name")?, r.try_get("status")?)))
            .collect()
    }

    /// Enregistre le plan sans écraser la progression déjà acquise.
    ///
    /// C'est le cœur de la reprise (§2ter.5) : relancer `apply` après un échec ne
    /// remet pas les actions déjà terminées à `pending`.
    pub async fn record_plan(&self, app: &str, actions: &[(String, String)]) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        for (seq, (kind, description)) in actions.iter().enumerate() {
            sqlx::query(
                "INSERT INTO plan_actions (app, seq, kind, description, status)
                 VALUES (?1, ?2, ?3, ?4, 'pending')
                 ON CONFLICT(app, seq) DO UPDATE SET
                     kind = excluded.kind,
                     description = excluded.description
                 WHERE plan_actions.status != 'done'",
            )
            .bind(app)
            .bind(seq as i64)
            .bind(kind)
            .bind(description)
            .execute(&mut *tx)
            .await?;
        }

        // Un plan raccourci ne doit pas laisser traîner d'anciennes actions.
        sqlx::query("DELETE FROM plan_actions WHERE app = ?1 AND seq >= ?2")
            .bind(app)
            .bind(actions.len() as i64)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn set_action_status(
        &self,
        app: &str,
        seq: usize,
        status: ActionStatus,
        error: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE plan_actions
             SET status = ?3, error = ?4, updated_at = datetime('now')
             WHERE app = ?1 AND seq = ?2",
        )
        .bind(app)
        .bind(seq as i64)
        .bind(status.as_str())
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn plan_actions(&self, app: &str) -> Result<Vec<ActionRecord>> {
        let rows = sqlx::query(
            "SELECT seq, kind, description, status, error
             FROM plan_actions WHERE app = ?1 ORDER BY seq",
        )
        .bind(app)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let status: String = r.try_get("status")?;
                Ok(ActionRecord {
                    seq: r.try_get("seq")?,
                    kind: r.try_get("kind")?,
                    description: r.try_get("description")?,
                    status: ActionStatus::parse(&status),
                    error: r.try_get("error")?,
                })
            })
            .collect()
    }

    /// Les actions déjà terminées, à ne pas rejouer.
    pub async fn completed_seqs(&self, app: &str) -> Result<Vec<i64>> {
        let rows = sqlx::query(
            "SELECT seq FROM plan_actions WHERE app = ?1 AND status = 'done' ORDER BY seq",
        )
        .bind(app)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok(r.try_get("seq")?)).collect()
    }

    /// Stocke un secret déjà chiffré. **Ne régénère jamais un secret existant** :
    /// un mot de passe déjà injecté dans un service ne doit pas changer sous ses pieds.
    ///
    /// Renvoie `true` si le secret a été créé, `false` s'il existait déjà.
    pub async fn store_secret_if_absent(
        &self,
        name: &str,
        ciphertext: &[u8],
        purpose: &str,
    ) -> Result<bool> {
        let res = sqlx::query(
            "INSERT INTO secrets (name, ciphertext, purpose) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO NOTHING",
        )
        .bind(name)
        .bind(ciphertext)
        .bind(purpose)
        .execute(&self.pool)
        .await?;

        Ok(res.rows_affected() > 0)
    }

    /// Remplace un secret existant (rotation).
    pub async fn rotate_secret(&self, name: &str, ciphertext: &[u8]) -> Result<()> {
        sqlx::query(
            "UPDATE secrets SET ciphertext = ?2, rotated_at = datetime('now')
             WHERE name = ?1",
        )
        .bind(name)
        .bind(ciphertext)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn secret(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query("SELECT ciphertext FROM secrets WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(Some(r.try_get("ciphertext")?)),
            None => Ok(None),
        }
    }

    /// Inventaire des secrets : noms et usages, **jamais les valeurs** (§9).
    pub async fn secret_names(&self) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query("SELECT name, purpose FROM secrets ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("name")?, r.try_get("purpose")?)))
            .collect()
    }

    pub async fn add_guide(
        &self,
        app: &str,
        id: &str,
        title: &str,
        blocking: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO pending_guides (id, app, title, blocking)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(app, id) DO UPDATE SET title = excluded.title",
        )
        .bind(id)
        .bind(app)
        .bind(title)
        .bind(blocking as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Marque une action manuelle comme traitée.
    ///
    /// ⚠️ Cette fonction ne vérifie RIEN par elle-même : elle enregistre une
    /// constatation faite ailleurs.
    ///
    /// Deux appelants, aux garanties opposées :
    ///
    /// - `hlb todo --verify` a d'abord exécuté le bloc `verify:` du manifest
    ///   (`hlb_guide::Verifier` : dns, http, tcp…). L'étape est **constatée**.
    /// - `hlb ack` n'a rien exécuté. C'est une **attestation** : le système croit
    ///   l'utilisateur sur parole, et le CLI le dit à chaque usage.
    ///
    /// Les confondre reviendrait à croire une app protégée parce que quelqu'un a
    /// affirmé l'avoir configurée.
    pub async fn verify_guide(&self, app: &str, id: &str) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE pending_guides SET verified_at = datetime('now')
             WHERE app = ?1 AND id = ?2 AND verified_at IS NULL",
        )
        .bind(app)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Les actions bloquantes encore non traitées pour une app donnée.
    pub async fn unverified_blocking(&self, app: &str) -> Result<usize> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM pending_guides
             WHERE app = ?1 AND blocking = 1 AND verified_at IS NULL",
        )
        .bind(app)
        .fetch_one(&self.pool)
        .await?;
        let n: i64 = row.try_get("n")?;
        Ok(n as usize)
    }

    /// La file du §4.6 : ce qui reste à faire à la main, non vérifié.
    pub async fn pending_guides(&self) -> Result<Vec<(String, String, String, bool)>> {
        let rows = sqlx::query(
            "SELECT app, id, title, blocking FROM pending_guides
             WHERE verified_at IS NULL ORDER BY blocking DESC, app, id",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let blocking: i64 = r.try_get("blocking")?;
                Ok((
                    r.try_get("app")?,
                    r.try_get("id")?,
                    r.try_get("title")?,
                    blocking != 0,
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(name: &str) -> Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name} }}\n\
             spec:\n  image: {{ repo: a/b, tag: \"1\" }}\n"
        );
        serde_yaml_ng::from_str(&y).expect("manifest de test")
    }

    async fn st() -> State {
        State::in_memory().await.expect("base en mémoire")
    }

    #[tokio::test]
    async fn sqlite_volumes_are_listed_apart() {
        // 🔴 Un volume SQLite ne peut pas être sauvegardé par copie de fichiers : le
        // fichier principal et son WAL seraient capturés à des instants différents,
        // et la base restaurée serait corrompue sans que rien ne l'ait signalé.
        let s = st().await;
        s.upsert_app("pocket-id", &manifest("pocket-id"), None).await.expect("upsert");
        s.add_volume("pocket-id", "pid-data", "/mnt/pid", true, true).await.expect("volume");
        s.add_volume("pocket-id", "pid-cache", "/mnt/cache", false, true).await.expect("volume");
        s.upsert_app("gitea", &manifest("gitea"), None).await.expect("upsert");
        s.add_volume("gitea", "g-data", "/mnt/g", true, false).await.expect("volume");

        let v = s.sqlite_volumes().await.expect("lecture");
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].1, "pid-data");
        // Un volume SQLite non sauvegardé n'a pas besoin d'instantané.
        assert!(!v.iter().any(|(_, n, _)| n == "pid-cache"));
    }

    #[tokio::test]
    async fn databases_come_from_the_frozen_manifest() {
        // 🔴 Le manifest FIGÉ, pas le catalogue courant (§4.8). Une app installée il
        // y a six mois doit être sauvegardée selon ce qu'elle demandait alors ; un
        // catalogue qui aurait renommé la base ferait sauvegarder du vide.
        let s = st().await;
        let y = "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\n\
                 spec:\n  image: { repo: a/b, tag: \"1\" }\n\
                 \x20 requires:\n    - kind: database\n      engine: postgres\n";
        let m: Manifest = serde_yaml_ng::from_str(y).expect("manifest");
        s.upsert_app("gitea", &m, None).await.expect("upsert");
        s.set_app_status("gitea", "running").await.expect("statut");

        let d = s.app_databases().await.expect("lecture");
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].0, "gitea");
        assert_eq!(d[0].1, "postgres");
        // Sans nom explicite, la base porte le nom de l'app — MÊME convention que
        // le résolveur. Les deux doivent rester alignés.
        assert_eq!(d[0].2, "gitea");
        assert_eq!(d[0].3, "gitea-db-password");
    }

    #[tokio::test]
    async fn an_app_without_a_database_is_not_listed() {
        let s = st().await;
        s.upsert_app("statique", &manifest("statique"), None).await.expect("upsert");
        s.set_app_status("statique", "running").await.expect("statut");
        assert!(s.app_databases().await.expect("lecture").is_empty());
    }

    #[tokio::test]
    async fn a_failed_app_is_skipped() {
        // Sa base n'a probablement jamais été provisionnée : la sauvegarder
        // produirait un échec à chaque tour de boucle, pour rien.
        let s = st().await;
        let y = "apiVersion: hlb/v1\nkind: App\nmetadata: { name: casse }\n\
                 spec:\n  image: { repo: a/b, tag: \"1\" }\n\
                 \x20 requires:\n    - kind: database\n      engine: postgres\n";
        let m: Manifest = serde_yaml_ng::from_str(y).expect("manifest");
        s.upsert_app("casse", &m, None).await.expect("upsert");
        s.set_app_status("casse", "failed").await.expect("statut");
        assert!(s.app_databases().await.expect("lecture").is_empty());
    }

    #[tokio::test]
    async fn base_backups_exclude_failures_and_other_kinds() {
        // 🔴 Une sauvegarde de base ratée ne restaure rien. La compter élargirait la
        // fenêtre PITR annoncée d'une garantie qu'on n'a pas.
        let s = st().await;
        s.record_backup("postgres", "pg-basebackup", Some("base-1"), None)
            .await
            .expect("réussite");
        s.record_backup("postgres", "pg-basebackup", None, Some("disque plein"))
            .await
            .expect("échec");
        // Un instantané de volume n'est pas un point de départ de rejeu WAL.
        s.record_backup("postgres", "volume", Some("vol-9"), None)
            .await
            .expect("volume");

        let b = s.base_backups("postgres").await.expect("lecture");
        assert_eq!(b.len(), 1, "{b:?}");
        assert_eq!(b[0].0, "base-1");
        assert!(b[0].1 > 0, "horodatage exploitable");
    }

    #[tokio::test]
    async fn base_backups_come_oldest_first() {
        // L'ordre importe : la borne de purge du WAL est la PLUS ANCIENNE base.
        let s = st().await;
        for id in ["b1", "b2", "b3"] {
            s.record_backup("postgres", "pg-basebackup", Some(id), None)
                .await
                .expect("base");
        }
        let b = s.base_backups("postgres").await.expect("lecture");
        assert_eq!(
            b.iter().map(|(i, _)| i.as_str()).collect::<Vec<_>>(),
            ["b1", "b2", "b3"]
        );
    }

    #[tokio::test]
    async fn the_schema_can_actually_go_back() {
        // 🔴 Écrire un `down` ne prouve rien : c'est de l'exécuter qui prouve que le
        // retour arrière fonctionne. Sans ce test, on découvrirait qu'un `down` est
        // cassé au pire moment — pendant un rollback, après un échec de mise à jour.
        let s = st().await;
        let avant = s.schema_version().await.expect("version").expect("migrée");
        assert!(avant >= 6, "toutes les migrations doivent être appliquées : {avant}");

        // On revient avant la migration du journal d'audit.
        s.undo_migrations(4).await.expect("retour arrière");
        assert_eq!(s.schema_version().await.expect("version"), Some(4));

        // Et la table concernée a bien disparu : le `down` a fait son travail.
        let existe: Option<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'",
        )
        .fetch_optional(&s.pool)
        .await
        .expect("lecture");
        assert!(existe.is_none(), "audit_log aurait dû être supprimée");
    }

    #[tokio::test]
    async fn going_back_then_forward_works() {
        // Le cycle complet : c'est ce qui se passe si un rollback est suivi d'une
        // nouvelle tentative de mise à jour.
        let s = st().await;
        s.undo_migrations(3).await.expect("retour");
        assert_eq!(s.schema_version().await.expect("v"), Some(3));

        sqlx::migrate!("./migrations")
            .run(&s.pool)
            .await
            .expect("réapplication");
        assert!(s.schema_version().await.expect("v").expect("v") >= 6);

        // Et l'état reste utilisable après l'aller-retour.
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("la base doit rester fonctionnelle");
    }

    #[test]
    fn every_migration_can_be_undone() {
        // 🔴 La condition qui débloque toute mise à jour (§7bis). Sans `down`, un
        // échec de la version N+1 laisse la base dans un état que le binaire N ne
        // comprend pas — et il n'y a plus de sortie. `hlb self update` REFUSE de
        // démarrer si cette règle est violée ; ce test l'attrape avant.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut ups = Vec::new();
        let mut downs = Vec::new();

        for e in std::fs::read_dir(&dir).expect("répertoire de migrations") {
            let nom = e.expect("entrée").file_name().to_string_lossy().to_string();
            if let Some(base) = nom.strip_suffix(".up.sql") {
                ups.push(base.to_string());
            } else if let Some(base) = nom.strip_suffix(".down.sql") {
                downs.push(base.to_string());
            } else {
                panic!("« {nom} » : une migration doit être .up.sql ou .down.sql");
            }
        }

        ups.sort();
        downs.sort();
        assert!(!ups.is_empty(), "aucune migration trouvée");
        assert_eq!(
            ups, downs,
            "chaque migration doit avoir son inverse — sinon plus aucune mise à jour \
             n'est possible"
        );
    }

    #[tokio::test]
    async fn migrations_run_on_open() {
        let s = st().await;
        assert!(s.installed_apps().await.expect("lecture").is_empty());
    }

    #[tokio::test]
    async fn manifest_is_frozen_at_deploy_time() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), Some("git.x.fr"))
            .await
            .expect("upsert");

        let stored = s.app_manifest("gitea").await.expect("relecture");
        assert_eq!(stored.metadata.name, "gitea");
        assert_eq!(stored.spec.image.tag, "1");
    }

    #[tokio::test]
    async fn unknown_app_is_reported() {
        let err = st().await.app_manifest("nexiste-pas").await.unwrap_err();
        assert!(matches!(err, Error::UnknownApp(_)), "{err}");
    }

    #[tokio::test]
    async fn completed_actions_survive_a_replan() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();

        let plan = vec![
            ("Deploy".to_string(), "déployer gitea".to_string()),
            ("Wait".to_string(), "attendre gitea".to_string()),
        ];
        s.record_plan("gitea", &plan).await.expect("plan");
        s.set_action_status("gitea", 0, ActionStatus::Done, None)
            .await
            .expect("statut");

        // Re-planification : l'action déjà faite ne doit pas repasser à pending.
        s.record_plan("gitea", &plan).await.expect("replan");

        let done = s.completed_seqs("gitea").await.expect("lecture");
        assert_eq!(done, vec![0], "la reprise ne doit pas rejouer le déjà-fait");
    }

    #[tokio::test]
    async fn shorter_plan_drops_stale_actions() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();

        let long = vec![
            ("A".to_string(), "a".to_string()),
            ("B".to_string(), "b".to_string()),
            ("C".to_string(), "c".to_string()),
        ];
        s.record_plan("gitea", &long).await.unwrap();
        assert_eq!(s.plan_actions("gitea").await.unwrap().len(), 3);

        s.record_plan("gitea", &long[..1]).await.unwrap();
        assert_eq!(s.plan_actions("gitea").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn failure_is_recorded_with_its_message() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();
        s.record_plan("gitea", &[("Deploy".into(), "déployer".into())])
            .await
            .unwrap();

        s.set_action_status("gitea", 0, ActionStatus::Failed, Some("image absente"))
            .await
            .unwrap();

        let a = &s.plan_actions("gitea").await.unwrap()[0];
        assert_eq!(a.status, ActionStatus::Failed);
        assert_eq!(a.error.as_deref(), Some("image absente"));
        // Un échec n'est pas terminal : il sera rejoué à la reprise.
        assert!(!a.status.is_terminal());
    }

    #[tokio::test]
    async fn a_secret_is_never_silently_regenerated() {
        // Un mot de passe déjà injecté dans un service ne doit pas changer sous ses pieds.
        let s = st().await;
        assert!(s.store_secret_if_absent("db-pw", b"chiffre-1", "base").await.unwrap());
        assert!(!s.store_secret_if_absent("db-pw", b"chiffre-2", "base").await.unwrap());
        assert_eq!(s.secret("db-pw").await.unwrap().as_deref(), Some(&b"chiffre-1"[..]));
    }

    #[tokio::test]
    async fn rotation_replaces_the_value() {
        let s = st().await;
        s.store_secret_if_absent("db-pw", b"ancien", "base").await.unwrap();
        s.rotate_secret("db-pw", b"nouveau").await.unwrap();
        assert_eq!(s.secret("db-pw").await.unwrap().as_deref(), Some(&b"nouveau"[..]));
    }

    #[tokio::test]
    async fn inventory_never_exposes_values() {
        let s = st().await;
        s.store_secret_if_absent("db-pw", b"tres-secret", "base gitea").await.unwrap();
        let inv = s.secret_names().await.unwrap();
        assert_eq!(inv, vec![("db-pw".to_string(), "base gitea".to_string())]);
    }

    #[tokio::test]
    async fn missing_secret_is_none_not_an_error() {
        assert!(st().await.secret("nexiste-pas").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn blocking_guides_come_first() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();
        s.add_guide("gitea", "tip", "une astuce", false).await.unwrap();
        s.add_guide("gitea", "admin", "créer l'admin", true).await.unwrap();

        let g = s.pending_guides().await.unwrap();
        assert_eq!(g.len(), 2);
        assert!(g[0].3, "les bloquantes d'abord");
        assert_eq!(g[0].1, "admin");
    }

    #[tokio::test]
    async fn audited_actions_are_retrievable_in_order() {
        let s = st().await;
        s.audit("cli", hlb_types::Role::Admin, "install", "gitea", "ok", None)
            .await
            .unwrap();
        s.audit("remy", hlb_types::Role::Operator, "purge", "vikunja", "refused", Some("rôle insuffisant"))
            .await
            .unwrap();

        let t = s.audit_trail(10).await.unwrap();
        assert_eq!(t.len(), 2);
        // Le plus récent d'abord : c'est ce qu'on veut voir en cas d'incident.
        assert_eq!(t[0].2, "purge");
        assert_eq!(t[0].4, "refused");
    }

    #[tokio::test]
    async fn refusals_are_audited_too() {
        // 🔴 Une tentative refusée est au moins aussi intéressante qu'une réussie :
        // c'est le signal d'un accès mal configuré, ou d'une intrusion.
        let s = st().await;
        s.audit("inconnu", hlb_types::Role::Viewer, "purge", "gitea", "refused", None)
            .await
            .unwrap();
        assert_eq!(s.audit_trail(10).await.unwrap()[0].4, "refused");
    }

    #[tokio::test]
    async fn a_failure_does_not_push_back_the_schedule() {
        // 🔴 Sinon une sauvegarde cassée se ferait de plus en plus rare.
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();

        assert_eq!(s.seconds_since_last_success("gitea").await.unwrap(), None);

        s.record_backup("gitea", "volume", None, Some("disque plein")).await.unwrap();
        assert_eq!(
            s.seconds_since_last_success("gitea").await.unwrap(),
            None,
            "un échec ne compte pas comme une réussite"
        );

        s.record_backup("gitea", "volume", Some("abc"), None).await.unwrap();
        assert!(s.seconds_since_last_success("gitea").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn the_latest_successful_snapshot_is_retrievable() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();

        s.record_backup("gitea", "volume", Some("ancien"), None).await.unwrap();
        s.record_backup("gitea", "volume", None, Some("échec")).await.unwrap();
        s.record_backup("gitea", "volume", Some("recent"), None).await.unwrap();

        assert_eq!(s.latest_snapshot("gitea").await.unwrap().as_deref(), Some("recent"));
    }

    #[tokio::test]
    async fn verifications_track_only_successes() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();

        s.record_verification("gitea", "abc", Some("contenu différent")).await.unwrap();
        assert_eq!(
            s.seconds_since_last_verification("gitea").await.unwrap(),
            None,
            "une vérification en échec ne prouve rien"
        );

        s.record_verification("gitea", "abc", None).await.unwrap();
        assert!(s.seconds_since_last_verification("gitea").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn volumes_are_recorded_with_their_real_path() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();

        s.add_volume("gitea", "gitea-data", "/var/lib/docker/volumes/gitea-data/_data", true, false)
            .await
            .unwrap();
        // Un cache : pas de sauvegarde.
        s.add_volume("gitea", "gitea-cache", "/ailleurs", false, false).await.unwrap();

        let v = s.volumes_to_backup("gitea").await.unwrap();
        assert_eq!(v.len(), 1, "seul le volume à sauvegarder doit remonter");
        assert_eq!(v[0].0, "gitea-data");
        assert!(v[0].1.ends_with("/_data"));
    }

    #[tokio::test]
    async fn recording_a_volume_twice_updates_it() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();
        s.add_volume("gitea", "d", "/ancien", true, false).await.unwrap();
        s.add_volume("gitea", "d", "/nouveau", true, false).await.unwrap();

        let v = s.volumes_to_backup("gitea").await.unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, "/nouveau");
    }

    #[tokio::test]
    async fn the_resolved_digest_is_frozen_in_the_manifest() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();
        assert!(s.app_manifest("gitea").await.unwrap().spec.image.digest.is_none());

        s.set_app_digest("gitea", "sha256:abc").await.unwrap();

        let m = s.app_manifest("gitea").await.unwrap();
        assert_eq!(m.spec.image.digest.as_deref(), Some("sha256:abc"));
        // C'est le digest qui est déployé, pas le tag.
        assert_eq!(m.spec.image.reference(), "a/b:1@sha256:abc");
    }

    #[tokio::test]
    async fn verifying_a_guide_unblocks_it() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();
        s.add_guide("gitea", "admin", "créer l'admin", true).await.unwrap();

        assert_eq!(s.unverified_blocking("gitea").await.unwrap(), 1);
        assert!(s.verify_guide("gitea", "admin").await.unwrap());
        assert_eq!(s.unverified_blocking("gitea").await.unwrap(), 0);

        // Deuxième acquittement : rien à faire, pas d'erreur.
        assert!(!s.verify_guide("gitea", "admin").await.unwrap());
        assert!(s.pending_guides().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleting_an_app_cascades() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();
        s.record_plan("gitea", &[("A".into(), "a".into())]).await.unwrap();
        s.add_guide("gitea", "x", "y", true).await.unwrap();

        sqlx::query("DELETE FROM apps WHERE name = 'gitea'")
            .execute(&s.pool)
            .await
            .unwrap();

        assert!(s.plan_actions("gitea").await.unwrap().is_empty());
        assert!(s.pending_guides().await.unwrap().is_empty());
    }
}
