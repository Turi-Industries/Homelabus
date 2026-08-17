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

    /// Enregistre une sauvegarde en nommant sa DESTINATION.
    ///
    /// 🔴 C'est la destination qui rend la mesure honnête. `record_backup` sans elle
    /// agrège tout : un NAS sauvegardé toutes les 4 h ferait passer un hors-site mort
    /// depuis trois semaines pour une sauvegarde de 2 h, et l'on croirait la règle
    /// 3-2-1 tenue alors qu'il ne resterait qu'une copie.
    pub async fn record_backup_to(
        &self,
        app: &str,
        kind: &str,
        destination: &str,
        snapshot_id: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO backup_runs (app, kind, destination, snapshot_id, status, error, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))",
        )
        .bind(app)
        .bind(kind)
        .bind(destination)
        .bind(snapshot_id)
        .bind(if error.is_some() { "failed" } else { "ok" })
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Âge de la dernière réussite **sur une destination précise**.
    ///
    /// ⚠️ `None` veut dire « rien n'y est JAMAIS arrivé », ce qui n'est pas « en
    /// retard » : la cause est différente et souvent plus grave — le routage n'a
    /// peut-être jamais été branché.
    pub async fn seconds_since_last_success_on(
        &self,
        app: &str,
        destination: &str,
    ) -> Result<Option<i64>> {
        let row = sqlx::query(
            "SELECT CAST(strftime('%s','now') AS INTEGER)
                    - CAST(strftime('%s', MAX(finished_at)) AS INTEGER) AS age
             FROM backup_runs
             WHERE app = ?1 AND destination = ?2 AND status = 'ok'",
        )
        .bind(app)
        .bind(destination)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.try_get::<Option<i64>, _>("age").ok().flatten()))
    }

    /// Combien de tentatives ONT ÉCHOUÉ depuis la dernière réussite ?
    ///
    /// 🔴 La fraîcheur seule ne suffit pas. Une destination qui échoue à CHAQUE
    /// tentative reste « fraîche » jusqu'à ce que le seuil de péremption passe — douze
    /// heures avec l'intervalle par défaut. Pendant tout ce temps, le tableau de bord
    /// affiche un ✓ pour une destination qui ne reçoit plus rien.
    ///
    /// Un échec répété est un signal immédiat, pas un signal différé.
    pub async fn consecutive_failures_on(&self, app: &str, destination: &str) -> Result<i64> {
        // ⚠️ On ordonne par `id`, PAS par `finished_at`. `datetime('now')` a une
        // résolution d'une SECONDE : une réussite et l'échec qui la suit dans la même
        // seconde portent le même horodatage, et une comparaison stricte les exclut —
        // le compteur reste à zéro alors que tout échoue. L'identifiant est monotone
        // et n'a pas ce défaut.
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM backup_runs
             WHERE app = ?1 AND destination = ?2 AND status = 'failed'
               AND id > COALESCE(
                     (SELECT MAX(id) FROM backup_runs
                      WHERE app = ?1 AND destination = ?2 AND status = 'ok'),
                     0)",
        )
        .bind(app)
        .bind(destination)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get::<i64, _>("n").unwrap_or(0))
    }

    /// Déclare ou met à jour une destination.
    pub async fn upsert_destination(
        &self,
        name: &str,
        location: &str,
        classes: &str,
        credentials_secret: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO backup_destinations (name, location, classes, credentials_secret)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET
               location = ?2, classes = ?3, credentials_secret = ?4",
        )
        .bind(name)
        .bind(location)
        .bind(classes)
        .bind(credentials_secret)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Les destinations déclarées : `(nom, emplacement, classes, secret)`.
    pub async fn destinations(&self) -> Result<Vec<(String, String, String, Option<String>)>> {
        let rows = sqlx::query(
            "SELECT name, location, classes, credentials_secret
             FROM backup_destinations ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("name")?,
                    r.try_get("location")?,
                    r.try_get("classes")?,
                    r.try_get("credentials_secret")?,
                ))
            })
            .collect()
    }

    pub async fn remove_destination(&self, name: &str) -> Result<()> {
        sqlx::query("DELETE FROM backup_destinations WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Route une classe de données d'une app vers un ensemble de destinations.
    ///
    /// Remplace la route existante pour cette app et cette classe : additionner
    /// silencieusement ferait grossir le routage à chaque appel, et l'on finirait par
    /// envoyer des téraoctets à une destination qu'on croyait avoir retirée.
    pub async fn set_route(&self, app: &str, class: &str, destinations: &[String]) -> Result<()> {
        sqlx::query("DELETE FROM backup_routes WHERE app = ?1 AND class = ?2")
            .bind(app)
            .bind(class)
            .execute(&self.pool)
            .await?;

        for d in destinations {
            sqlx::query(
                "INSERT INTO backup_routes (app, class, destination) VALUES (?1, ?2, ?3)",
            )
            .bind(app)
            .bind(class)
            .bind(d)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Les destinations explicitement routées pour cette app et cette classe.
    ///
    /// Vide = aucune route explicite ; l'appelant retombe alors sur les classes que
    /// chaque destination accepte globalement.
    pub async fn route(&self, app: &str, class: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT destination FROM backup_routes
             WHERE app = ?1 AND class = ?2 ORDER BY destination",
        )
        .bind(app)
        .bind(class)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok(r.try_get("destination")?)).collect()
    }

    // ─────────────────── Comptes humains (§5bis.3) ───────────────────

    pub async fn upsert_user(&self, name: &str, profil: &str, pocket_id: Option<&str>) -> Result<()> {
        sqlx::query(
            "INSERT INTO users (name, profil, pocket_id) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET
               profil = ?2,
               -- ⚠️ On n'EFFACE jamais un identifiant déjà connu avec un NULL : une
               -- reprise qui repasse ici sans l'identité perdrait le lien vers
               -- PocketID, et le compte redeviendrait « à moitié créé » alors qu'il
               -- ne l'est pas.
               pocket_id = COALESCE(?3, users.pocket_id)",
        )
        .bind(name)
        .bind(profil)
        .bind(pocket_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// `(nom, profil, pocket_id)`.
    pub async fn users(&self) -> Result<Vec<(String, String, Option<String>)>> {
        let rows = sqlx::query("SELECT name, profil, pocket_id FROM users ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("name")?, r.try_get("profil")?, r.try_get("pocket_id")?)))
            .collect()
    }

    pub async fn add_mailbox(
        &self,
        user: &str,
        local: &str,
        domain: &str,
        is_default: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_mailboxes (user, local, domain, is_default)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT(user, local) DO NOTHING",
        )
        .bind(user)
        .bind(local)
        .bind(domain)
        .bind(i64::from(is_default))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// `(local, domaine, par_defaut)`.
    pub async fn mailboxes(&self, user: &str) -> Result<Vec<(String, String, bool)>> {
        let rows = sqlx::query(
            "SELECT local, domain, is_default FROM user_mailboxes
             WHERE user = ?1 ORDER BY is_default DESC, local",
        )
        .bind(user)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("local")?,
                    r.try_get("domain")?,
                    r.try_get::<i64, _>("is_default")? != 0,
                ))
            })
            .collect()
    }

    pub async fn remove_mailbox(&self, user: &str, local: &str) -> Result<()> {
        sqlx::query("DELETE FROM user_mailboxes WHERE user = ?1 AND local = ?2")
            .bind(user)
            .bind(local)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn add_alias(
        &self,
        user: &str,
        mailbox: &str,
        local: &str,
        expires_at: Option<i64>,
        hint: Option<&str>,
        note: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_aliases (user, mailbox, local, expires_at, hint, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(user)
        .bind(mailbox)
        .bind(local)
        .bind(expires_at)
        .bind(hint)
        .bind(note)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// `(boîte, local, expire_le, actif, indice, note)`.
    #[allow(clippy::type_complexity)]
    pub async fn aliases(
        &self,
        user: &str,
    ) -> Result<Vec<(String, String, Option<i64>, bool, Option<String>, Option<String>)>> {
        let rows = sqlx::query(
            "SELECT mailbox, local, expires_at, active, hint, note
             FROM user_aliases WHERE user = ?1 ORDER BY mailbox, local",
        )
        .bind(user)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("mailbox")?,
                    r.try_get("local")?,
                    r.try_get("expires_at")?,
                    r.try_get::<i64, _>("active")? != 0,
                    r.try_get("hint")?,
                    r.try_get("note")?,
                ))
            })
            .collect()
    }

    /// Les aliases temporaires expirés QUI SONT ENCORE ACTIFS.
    ///
    /// 🔴 Ce sont les promesses rompues : des adresses que leur propriétaire croit
    /// fermées et qui reçoivent encore. Les plus anciennement expirées d'abord — si la
    /// purge s'interrompt, ce sont les portes ouvertes depuis le plus longtemps qu'on
    /// aura refermées.
    pub async fn aliases_to_purge(&self, now: i64) -> Result<Vec<(String, String, String)>> {
        let rows = sqlx::query(
            "SELECT user, mailbox, local FROM user_aliases
             WHERE active = 1 AND expires_at IS NOT NULL AND expires_at <= ?1
             ORDER BY expires_at ASC",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| Ok((r.try_get("user")?, r.try_get("mailbox")?, r.try_get("local")?)))
            .collect()
    }

    /// Fixe le dossier de tri d'un alias.
    ///
    /// 🔴 `None` remet « rien n'a été décidé » (un défaut sera proposé) ; `Some("")`
    /// veut dire « pas de tri », et c'est un choix EXPLICITE qu'il faut respecter.
    /// Confondre les deux réimposerait un dossier à quelqu'un qui n'en veut pas, à
    /// chaque régénération.
    pub async fn set_alias_folder(
        &self,
        user: &str,
        local: &str,
        folder: Option<&str>,
    ) -> Result<()> {
        sqlx::query("UPDATE user_aliases SET folder = ?3 WHERE user = ?1 AND local = ?2")
            .bind(user)
            .bind(local)
            .bind(folder)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Les règles de tri d'une boîte : `(alias, dossier, indice)`.
    ///
    /// Les aliases INACTIFS sont exclus : trier le courrier d'une adresse qui n'existe
    /// plus produirait une règle morte, et le script grossirait indéfiniment.
    #[allow(clippy::type_complexity)]
    pub async fn alias_rules(
        &self,
        user: &str,
        mailbox: &str,
    ) -> Result<Vec<(String, Option<String>, Option<String>)>> {
        let rows = sqlx::query(
            "SELECT local, folder, hint FROM user_aliases
             WHERE user = ?1 AND mailbox = ?2 AND active = 1 ORDER BY local",
        )
        .bind(user)
        .bind(mailbox)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| Ok((r.try_get("local")?, r.try_get("folder")?, r.try_get("hint")?)))
            .collect()
    }

    /// Marque un alias comme retiré de Stalwart.
    pub async fn deactivate_alias(&self, user: &str, local: &str) -> Result<()> {
        sqlx::query("UPDATE user_aliases SET active = 0 WHERE user = ?1 AND local = ?2")
            .bind(user)
            .bind(local)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Consigne un exercice de reprise (§8.3).
    ///
    /// 🔴 Les échecs sont enregistrés comme les réussites. Ne garder que les
    /// réussites ferait apparaître une procédure « exercée le mois dernier » alors
    /// que l'exercice avait échoué — soit exactement l'inverse de ce qu'on veut
    /// savoir.
    pub async fn record_drill(
        &self,
        scope: &str,
        ok: bool,
        tables: Option<i64>,
        duration_s: i64,
        detail: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO dr_drills (scope, status, tables, duration_s, detail)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(scope)
        .bind(if ok { "ok" } else { "failed" })
        .bind(tables)
        .bind(duration_s)
        .bind(detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Jours depuis le dernier exercice **RÉUSSI**.
    ///
    /// ⚠️ Réussi seulement : un exercice qui échoue ne prouve rien sur la capacité à
    /// restaurer, et le compter remettrait le compteur à zéro sans raison.
    pub async fn days_since_successful_drill(&self) -> Result<Option<i64>> {
        let row = sqlx::query(
            "SELECT CAST((julianday('now') - julianday(MAX(finished_at))) AS INTEGER) AS d
             FROM dr_drills WHERE status = 'ok'",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.try_get::<Option<i64>, _>("d").ok().flatten()))
    }

    /// Les derniers exercices, le plus récent d'abord.
    pub async fn recent_drills(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, String, String, Option<i64>)>> {
        let rows = sqlx::query(
            "SELECT finished_at, scope, status, tables FROM dr_drills
             ORDER BY finished_at DESC, id DESC LIMIT ?1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("finished_at")?,
                    r.try_get("scope")?,
                    r.try_get("status")?,
                    r.try_get("tables")?,
                ))
            })
            .collect()
    }

    /// Enregistre un jeton d'accès (§9ter).
    ///
    /// 🔴 Seule l'empreinte est conservée : la valeur n'existe qu'une fois, au moment
    /// où elle est affichée à l'utilisateur.
    pub async fn store_token(&self, t: &hlb_types::StoredToken) -> Result<()> {
        sqlx::query(
            "INSERT INTO api_tokens (name, fingerprint, role) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET
                 fingerprint = excluded.fingerprint,
                 role = excluded.role,
                 created_at = datetime('now')",
        )
        .bind(&t.name)
        .bind(&t.fingerprint)
        .bind(t.role.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Retrouve le jeton correspondant à une valeur présentée.
    ///
    /// ⚠️ La recherche se fait par **empreinte**, donc en une requête indexée : on ne
    /// parcourt pas la table en comparant un à un, ce qui rendrait le temps de
    /// réponse dépendant du nombre de jetons — et donnerait un canal auxiliaire.
    pub async fn find_token(&self, presented: &str) -> Result<Option<hlb_types::StoredToken>> {
        let empreinte = hlb_types::token::fingerprint_of(presented);

        let row = sqlx::query("SELECT name, fingerprint, role FROM api_tokens WHERE fingerprint = ?1")
            .bind(&empreinte)
            .fetch_optional(&self.pool)
            .await?;

        let Some(r) = row else { return Ok(None) };
        let role: String = r.try_get("role")?;

        Ok(Some(hlb_types::StoredToken {
            name: r.try_get("name")?,
            fingerprint: r.try_get("fingerprint")?,
            // Un rôle illisible retombe sur le MOINS permissif : une valeur corrompue
            // ne doit jamais élargir des droits.
            role: hlb_types::Role::parse(&role).unwrap_or_default(),
        }))
    }

    /// Note l'usage d'un jeton, pour repérer ceux qu'on a oubliés.
    pub async fn touch_token(&self, name: &str) -> Result<()> {
        sqlx::query("UPDATE api_tokens SET last_used = datetime('now') WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Les jetons : noms, rôles, dernier usage. **Jamais les valeurs.**
    pub async fn list_tokens(&self) -> Result<Vec<(String, String, Option<String>)>> {
        let rows = sqlx::query(
            "SELECT name, role, last_used FROM api_tokens ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| Ok((r.try_get("name")?, r.try_get("role")?, r.try_get("last_used")?)))
            .collect()
    }

    /// Révoque un jeton. Renvoie `false` s'il n'existait pas.
    pub async fn revoke_token(&self, name: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM api_tokens WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Y a-t-il au moins un jeton ?
    ///
    /// 🔴 Sert au refus de démarrage : une API sans jeton et sans `--insecure-no-auth`
    /// serait grande ouverte sans que personne l'ait décidé.
    pub async fn has_tokens(&self) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM api_tokens")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get::<i64, _>("n")? > 0)
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
                if let hlb_types::Capability::Database { engine, name, .. } = c {
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
    async fn a_fresh_destination_never_masks_a_stale_one() {
        // 🔴 Le piège que la colonne `destination` supprime. Sans elle,
        // `seconds_since_last_success` agrège TOUTES les destinations : un NAS
        // sauvegardé toutes les 4 h ferait passer un hors-site mort depuis trois
        // semaines pour une sauvegarde de 2 h. On croirait la règle 3-2-1 tenue alors
        // qu'il ne reste qu'une copie, sur les mêmes machines.
        let s = State::in_memory().await.expect("état");

        s.record_backup_to("immich", "volume", "nas", Some("frais"), None)
            .await
            .expect("nas");

        // L'agrégat voit une sauvegarde récente…
        let global = s
            .seconds_since_last_success("immich")
            .await
            .expect("agrégat");
        assert!(global.is_some(), "l'agrégat voit bien quelque chose");

        // …mais le hors-site n'a JAMAIS rien reçu, et ça doit se voir.
        assert_eq!(
            s.seconds_since_last_success_on("immich", "offsite")
                .await
                .expect("par destination"),
            None,
            "une destination jamais servie ne doit pas hériter de la fraîcheur d'une autre"
        );

        assert!(s
            .seconds_since_last_success_on("immich", "nas")
            .await
            .expect("par destination")
            .is_some());
    }

    #[tokio::test]
    async fn a_failed_run_never_counts_as_a_copy() {
        // Une destination en échec est une destination configurée qui ne protège de
        // rien : elle ne doit pas rajeunir la mesure.
        let s = State::in_memory().await.expect("état");
        s.record_backup_to("immich", "volume", "offsite", None, Some("réseau coupé"))
            .await
            .expect("échec enregistré");

        assert_eq!(
            s.seconds_since_last_success_on("immich", "offsite")
                .await
                .expect("par destination"),
            None
        );
    }

    #[tokio::test]
    async fn repeated_failures_show_up_before_the_staleness_threshold() {
        // 🔴 Constaté en exécutant la boucle pour de vrai : une destination qui échoue
        // à CHAQUE tentative reste « fraîche » tant que le seuil de péremption n'est
        // pas franchi — douze heures avec l'intervalle par défaut. Le tableau de bord
        // affiche un ✓ pour une destination qui ne reçoit plus rien.
        let s = State::in_memory().await.expect("état");

        s.record_backup_to("demo", "volume", "offsite", Some("ok1"), None)
            .await
            .expect("réussite");
        assert_eq!(
            s.consecutive_failures_on("demo", "offsite").await.unwrap(),
            0
        );

        // ⚠️ Ces quatre écritures tombent dans la MÊME seconde. C'est ce qui a fait
        // échouer la première version, qui comparait des horodatages : `datetime('now')`
        // n'a qu'une résolution d'une seconde. L'ordre vient donc de l'`id`.
        for _ in 0..3 {
            s.record_backup_to("demo", "volume", "offsite", None, Some("injoignable"))
                .await
                .expect("échec");
        }
        assert_eq!(
            s.consecutive_failures_on("demo", "offsite").await.unwrap(),
            3,
            "trois échecs depuis la dernière réussite"
        );

        // Et une nouvelle réussite remet le compteur à zéro : c'est un compteur
        // d'échecs CONSÉCUTIFS, pas un total historique qui ne redescendrait jamais.
        s.record_backup_to("demo", "volume", "offsite", Some("ok2"), None)
            .await
            .expect("réussite");
        assert_eq!(
            s.consecutive_failures_on("demo", "offsite").await.unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn failures_on_one_destination_do_not_count_for_another() {
        let s = State::in_memory().await.expect("état");
        s.record_backup_to("demo", "volume", "offsite", None, Some("boum"))
            .await
            .expect("échec");
        assert_eq!(s.consecutive_failures_on("demo", "nas").await.unwrap(), 0);
        assert_eq!(s.consecutive_failures_on("demo", "offsite").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_route_replaces_instead_of_accumulating() {
        // Additionner ferait grossir le routage à chaque appel, et l'on finirait par
        // envoyer des téraoctets vers une destination qu'on croyait avoir retirée.
        let s = State::in_memory().await.expect("état");
        s.upsert_destination("nas", "/mnt/nas", "critique,volumineux", None)
            .await
            .expect("nas");
        s.upsert_destination("offsite", "s3:https://x/y", "critique", None)
            .await
            .expect("offsite");

        s.set_route("immich", "volumineux", &["nas".into(), "offsite".into()])
            .await
            .expect("route");
        assert_eq!(s.route("immich", "volumineux").await.unwrap().len(), 2);

        s.set_route("immich", "volumineux", &["nas".into()])
            .await
            .expect("route réduite");
        assert_eq!(
            s.route("immich", "volumineux").await.unwrap(),
            vec!["nas".to_string()],
            "la nouvelle route REMPLACE, elle ne s'ajoute pas"
        );
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
    async fn a_failed_drill_does_not_reset_the_clock() {
        // 🔴 Un exercice qui échoue ne prouve RIEN sur la capacité à restaurer. Le
        // compter ferait apparaître une procédure « exercée le mois dernier » alors
        // qu'elle avait échoué — l'inverse de ce qu'on veut savoir.
        let s = st().await;
        s.record_drill("postgres", false, Some(0), 12, "base vide")
            .await
            .expect("échec consigné");

        assert_eq!(
            s.days_since_successful_drill().await.expect("lecture"),
            None,
            "un échec ne doit pas compter comme un exercice réussi"
        );

        // Mais il reste VISIBLE : c'est l'information la plus utile.
        let v = s.recent_drills(10).await.expect("lecture");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].2, "failed");
    }

    #[tokio::test]
    async fn a_successful_drill_starts_the_clock() {
        let s = st().await;
        s.record_drill("postgres", true, Some(14), 30, "")
            .await
            .expect("réussite");
        assert_eq!(s.days_since_successful_drill().await.expect("lecture"), Some(0));
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
