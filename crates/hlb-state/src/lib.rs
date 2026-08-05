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
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO app_volumes (app, name, mountpoint, backup)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(app, name) DO UPDATE SET
                 mountpoint = excluded.mountpoint,
                 backup = excluded.backup",
        )
        .bind(app)
        .bind(name)
        .bind(mountpoint)
        .bind(backup as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
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
    /// ⚠️ Aujourd'hui c'est une attestation de l'utilisateur. La vérification
    /// automatique (bloc `verify:` du §4.6 : dns, http, tcp, api…) n'est pas encore
    /// écrite — tant qu'elle ne l'est pas, le système croit l'utilisateur sur parole.
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
    async fn volumes_are_recorded_with_their_real_path() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();

        s.add_volume("gitea", "gitea-data", "/var/lib/docker/volumes/gitea-data/_data", true)
            .await
            .unwrap();
        // Un cache : pas de sauvegarde.
        s.add_volume("gitea", "gitea-cache", "/ailleurs", false).await.unwrap();

        let v = s.volumes_to_backup("gitea").await.unwrap();
        assert_eq!(v.len(), 1, "seul le volume à sauvegarder doit remonter");
        assert_eq!(v[0].0, "gitea-data");
        assert!(v[0].1.ends_with("/_data"));
    }

    #[tokio::test]
    async fn recording_a_volume_twice_updates_it() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None).await.unwrap();
        s.add_volume("gitea", "d", "/ancien", true).await.unwrap();
        s.add_volume("gitea", "d", "/nouveau", true).await.unwrap();

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
