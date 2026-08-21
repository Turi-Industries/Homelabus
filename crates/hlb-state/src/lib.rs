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

/// Une exécution de sauvegarde, telle qu'on la relit.
///
/// ## Pourquoi ce type existe
///
/// Seuls les **âges** étaient lisibles (`seconds_since_last_success_on`). C'est assez
/// pour dire « ça va » ou « ça ne va pas », pas pour répondre à « depuis quand ça ne
/// marche plus, et qu'est-ce qui a changé ce jour-là ». La frise du §11bis — une
/// colonne par jour, une ligne par destination — a besoin des lignes, pas de leur
/// résumé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRun {
    pub id: i64,
    pub app: String,
    /// `volume` | `database` | `pg-basebackup`…
    pub kind: String,
    /// `None` pour les lignes antérieures aux destinations multiples (migration 0009).
    pub destination: Option<String>,
    pub snapshot_id: Option<String>,
    /// `ok` | `failed`.
    pub status: String,
    pub error: Option<String>,
    pub finished_at: String,
}

impl BackupRun {
    pub fn a_reussi(&self) -> bool {
        self.status == "ok"
    }
}

/// Une vérification par restauration réelle (§8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationRun {
    pub id: i64,
    pub app: String,
    pub snapshot_id: String,
    pub status: String,
    pub detail: Option<String>,
    pub verified_at: String,
}

/// Une entrée du journal d'audit, telle qu'on la relit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub id: i64,
    pub at: String,
    pub actor: String,
    /// Le rôle **au moment de l'action**, pas celui d'aujourd'hui. Une personne
    /// rétrogradée depuis n'efface pas ce qu'elle a fait quand elle pouvait le faire.
    pub role: String,
    pub action: String,
    pub target: String,
    /// `ok` | `refused` | `failed`. Un refus n'est pas un échec : c'est le système qui
    /// a protégé l'utilisateur.
    pub outcome: String,
    /// Le diff, ou ce qui explique l'issue.
    pub detail: Option<String>,
}

/// Verdict du chaînage du journal (§9ter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditIntegrity {
    Intacte {
        verifiees: usize,
        /// Entrées antérieures au chaînage : elles ne sont pas suspectes, elles sont
        /// simplement hors de portée de la garantie.
        non_chainees: usize,
        /// L'identifiant de la première entrée couverte. `None` = aucune ne l'est.
        depuis_l_entree: Option<i64>,
    },
    /// 🔴 Une entrée a été modifiée, retirée ou insérée.
    Rompue { a_l_entree: i64, detail: String },
}

impl AuditIntegrity {
    pub fn est_intacte(&self) -> bool {
        matches!(self, Self::Intacte { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Intacte {
                verifiees: 0,
                non_chainees,
                ..
            } => format!(
                "aucune entrée chaînée ({non_chainees} antérieure(s) au chaînage, hors garantie)"
            ),
            Self::Intacte {
                verifiees,
                non_chainees: 0,
                ..
            } => format!("chaîne intacte, {verifiees} entrée(s) vérifiée(s)"),
            Self::Intacte {
                verifiees,
                non_chainees,
                depuis_l_entree,
            } => format!(
                "chaîne intacte depuis l'entrée {} : {verifiees} vérifiée(s), \
                 {non_chainees} antérieure(s) au chaînage et donc hors garantie",
                depuis_l_entree.unwrap_or(0)
            ),
            Self::Rompue { a_l_entree, detail } => {
                format!("🔴 CHAÎNE ROMPUE à l'entrée {a_l_entree} : {detail}")
            }
        }
    }
}

/// Une ligne de `backup_runs`.
fn ligne_backup(r: &sqlx::sqlite::SqliteRow) -> Result<BackupRun> {
    Ok(BackupRun {
        id: r.try_get("id")?,
        app: r.try_get("app")?,
        kind: r.try_get("kind")?,
        destination: r.try_get("destination")?,
        snapshot_id: r.try_get("snapshot_id")?,
        status: r.try_get("status")?,
        error: r.try_get("error")?,
        finished_at: r.try_get("finished_at")?,
    })
}

/// « 7B8CFF » → `[0x7B, 0x8C, 0xFF]`.
///
/// Rend `None` sur tout ce qui n'est pas exactement six chiffres hexadécimaux : une
/// couleur à moitié lue donnerait un accent aberrant, plus difficile à diagnostiquer
/// qu'un accent absent.
fn hex_rvb(s: &str) -> Option<[u8; 3]> {
    let s = s.trim().trim_start_matches('#');
    if s.len() != 6 {
        return None;
    }
    let d = |i: usize| u8::from_str_radix(&s[i..i + 2], 16).ok();
    Some([d(0)?, d(2)?, d(4)?])
}

/// L'empreinte d'une entrée de journal, chaînée à la précédente.
///
/// `champs` est ordonné : `[at, actor, role, action, target, outcome]`. Positionnel
/// pour que les deux appelants — l'écriture et la vérification — ne puissent pas
/// diverger sur l'ordre sans que le tableau change de forme.
///
/// 🔴 Chaque champ est **préfixé de sa longueur** avant d'être concaténé. Une simple
/// concaténation séparée par `|` permettrait de déplacer du texte d'un champ au
/// suivant sans changer l'empreinte : une cible `gitea|ok` deviendrait une cible
/// `gitea` avec l'issue `ok`, et la chaîne resterait valide.
fn empreinte_entree(prev: Option<&str>, champs: [&str; 6], detail: Option<&str>) -> String {
    let mut buf = String::new();
    for champ in [prev.unwrap_or("")]
        .into_iter()
        .chain(champs)
        .chain([detail.unwrap_or("")])
    {
        buf.push_str(&champ.len().to_string());
        buf.push(':');
        buf.push_str(champ);
    }
    hlb_types::token::sha256_hex(buf.as_bytes())
}

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

    /// TOUS les volumes d'une app : (nom, point de montage, sauvegardé, sqlite).
    ///
    /// ⚠️ Y compris ceux qui ne sont **pas** sauvegardés, contrairement à
    /// [`Self::volumes_to_backup`]. Sur un écran de détail, un volume absent de la
    /// liste se lit « il n'existe pas » ; ce qu'on veut voir, c'est qu'il existe et
    /// qu'il n'est pas protégé.
    pub async fn app_volumes(&self, app: &str) -> Result<Vec<(String, String, bool, bool)>> {
        let rows = sqlx::query(
            "SELECT name, mountpoint, backup, sqlite FROM app_volumes
             WHERE app = ?1 ORDER BY name",
        )
        .bind(app)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("name")?,
                    r.try_get("mountpoint")?,
                    r.try_get::<i64, _>("backup")? != 0,
                    r.try_get::<i64, _>("sqlite")? != 0,
                ))
            })
            .collect()
    }

    /// Le journal d'audit filtré sur une cible.
    pub async fn audit_pour(&self, cible: &str, limite: usize) -> Result<Vec<AuditRecord>> {
        let rows = sqlx::query(
            "SELECT id, at, actor, role, action, target, outcome, detail FROM audit_log
             WHERE target = ?1 ORDER BY at DESC, id DESC LIMIT ?2",
        )
        .bind(cible)
        .bind(limite as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok(AuditRecord {
                    id: r.try_get("id")?,
                    at: r.try_get("at")?,
                    actor: r.try_get("actor")?,
                    role: r.try_get("role")?,
                    action: r.try_get("action")?,
                    target: r.try_get("target")?,
                    outcome: r.try_get("outcome")?,
                    detail: r.try_get("detail")?,
                })
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

    /// Consigne une action dans le journal d'audit (§9), en chaînant les entrées.
    ///
    /// 🔴 Append-only : ce crate n'expose aucun moyen de supprimer ni de modifier une
    /// entrée. Mais une convention ne protège pas un fichier SQLite qu'on peut ouvrir :
    /// chaque entrée porte donc l'empreinte de la précédente (migration `0015`), si
    /// bien qu'une modification a posteriori casse la chaîne et se voit.
    ///
    /// L'insertion se fait dans une transaction **immédiate** : sans elle, deux actions
    /// simultanées liraient la même empreinte de tête et produiraient deux entrées qui
    /// se réclament du même prédécesseur — une chaîne fourchue, donc invérifiable.
    pub async fn audit(
        &self,
        actor: &str,
        role: hlb_types::Role,
        action: &str,
        target: &str,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        let precedent: Option<String> =
            sqlx::query("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
                .fetch_optional(&mut *tx)
                .await?
                .and_then(|r| r.try_get::<Option<String>, _>("hash").ok().flatten());

        // `datetime('now')` est calculé ici plutôt que laissé au DEFAULT : l'empreinte
        // doit porter sur la valeur réellement enregistrée, or on ne peut pas hacher ce
        // que la base n'a pas encore écrit.
        let at: String = sqlx::query("SELECT datetime('now') AS maintenant")
            .fetch_one(&mut *tx)
            .await?
            .try_get("maintenant")?;

        let empreinte = empreinte_entree(
            precedent.as_deref(),
            [&at, actor, role.as_str(), action, target, outcome],
            detail,
        );

        sqlx::query(
            "INSERT INTO audit_log (at, actor, role, action, target, outcome, detail, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&at)
        .bind(actor)
        .bind(role.as_str())
        .bind(action)
        .bind(target)
        .bind(outcome)
        .bind(detail)
        .bind(precedent.as_deref())
        .bind(&empreinte)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Les dernières entrées du journal, les plus récentes d'abord.
    ///
    /// Rend un type nommé plutôt qu'un n-uplet : à sept champs, `t.4` ne veut plus rien
    /// dire, et une inversion de deux colonnes de même type passerait la compilation.
    pub async fn audit_trail(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        let rows = sqlx::query(
            "SELECT id, at, actor, role, action, target, outcome, detail FROM audit_log
             ORDER BY at DESC, id DESC LIMIT ?1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok(AuditRecord {
                    id: r.try_get("id")?,
                    at: r.try_get("at")?,
                    actor: r.try_get("actor")?,
                    role: r.try_get("role")?,
                    action: r.try_get("action")?,
                    target: r.try_get("target")?,
                    outcome: r.try_get("outcome")?,
                    detail: r.try_get("detail")?,
                })
            })
            .collect()
    }

    /// Vérifie l'intégrité du chaînage du journal (§9ter).
    ///
    /// 🔴 Rend un verdict **qui dit depuis quand il vaut**. Les entrées antérieures à la
    /// migration `0015` n'ont pas d'empreinte et n'en auront jamais : les calculer
    /// aujourd'hui produirait une chaîne d'apparence complète bâtie sur un contenu
    /// éventuellement déjà falsifié. Une garantie qu'on n'a pas ne doit pas ressembler
    /// à une garantie qu'on a.
    pub async fn verify_audit_chain(&self) -> Result<AuditIntegrity> {
        let rows = sqlx::query(
            "SELECT id, at, actor, role, action, target, outcome, detail, prev_hash, hash
             FROM audit_log ORDER BY id ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut verifiees = 0usize;
        let mut non_chainees = 0usize;
        let mut depuis: Option<i64> = None;
        let mut attendu: Option<String> = None;

        for r in &rows {
            let id: i64 = r.try_get("id")?;
            let hash: Option<String> = r.try_get("hash")?;
            let Some(hash) = hash else {
                // Antérieure au chaînage : on la compte et on continue.
                non_chainees += 1;
                continue;
            };

            let prev: Option<String> = r.try_get("prev_hash")?;
            if depuis.is_none() {
                // La première entrée chaînée n'a pas de prédécesseur à confronter :
                // `attendu` vaut encore `None` et le restera jusqu'à la fin du tour.
                depuis = Some(id);
            } else if prev.as_deref() != attendu.as_deref() {
                return Ok(AuditIntegrity::Rompue {
                    a_l_entree: id,
                    detail: "l'entrée ne désigne pas l'empreinte de celle qui la précède : \
                             une entrée a été retirée ou insérée"
                        .to_string(),
                });
            }

            let (at, actor, role, action, target, outcome) = (
                r.try_get::<String, _>("at")?,
                r.try_get::<String, _>("actor")?,
                r.try_get::<String, _>("role")?,
                r.try_get::<String, _>("action")?,
                r.try_get::<String, _>("target")?,
                r.try_get::<String, _>("outcome")?,
            );
            let recalcule = empreinte_entree(
                prev.as_deref(),
                [&at, &actor, &role, &action, &target, &outcome],
                r.try_get::<Option<String>, _>("detail")?.as_deref(),
            );
            if recalcule != hash {
                return Ok(AuditIntegrity::Rompue {
                    a_l_entree: id,
                    detail: "le contenu de l'entrée ne correspond plus à son empreinte : \
                             elle a été modifiée après coup"
                        .to_string(),
                });
            }

            attendu = Some(hash);
            verifiees += 1;
        }

        Ok(AuditIntegrity::Intacte {
            verifiees,
            non_chainees,
            depuis_l_entree: depuis,
        })
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

    /// L'historique brut des sauvegardes d'une app, la plus récente d'abord.
    ///
    /// 🔴 Les ÉCHECS y sont, et c'est le but. Ne rendre que les réussites donnerait une
    /// frise où rien ne s'est jamais mal passé, et une destination qui échoue depuis
    /// trois semaines y ressemblerait à une destination qu'on n'utilise pas.
    pub async fn backup_history(&self, app: &str, limite: usize) -> Result<Vec<BackupRun>> {
        let rows = sqlx::query(
            "SELECT id, app, kind, destination, snapshot_id, status, error, finished_at
             FROM backup_runs WHERE app = ?1
             ORDER BY id DESC LIMIT ?2",
        )
        .bind(app)
        .bind(limite as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(ligne_backup).collect()
    }

    /// L'historique de TOUTES les apps — pour la frise globale.
    pub async fn backup_history_all(&self, limite: usize) -> Result<Vec<BackupRun>> {
        let rows = sqlx::query(
            "SELECT id, app, kind, destination, snapshot_id, status, error, finished_at
             FROM backup_runs ORDER BY id DESC LIMIT ?1",
        )
        .bind(limite as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(ligne_backup).collect()
    }

    /// Les vérifications par restauration, la plus récente d'abord.
    ///
    /// C'est le seul indicateur fiable que les sauvegardes fonctionnent vraiment
    /// (§8.3) : une sauvegarde jamais restaurée est une hypothèse, pas une garantie.
    pub async fn verifications(&self, app: &str, limite: usize) -> Result<Vec<VerificationRun>> {
        let rows = sqlx::query(
            "SELECT id, app, snapshot_id, status, detail, verified_at
             FROM restore_verifications WHERE app = ?1
             ORDER BY id DESC LIMIT ?2",
        )
        .bind(app)
        .bind(limite as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok(VerificationRun {
                    id: r.try_get("id")?,
                    app: r.try_get("app")?,
                    snapshot_id: r.try_get("snapshot_id")?,
                    status: r.try_get("status")?,
                    detail: r.try_get("detail")?,
                    verified_at: r.try_get("verified_at")?,
                })
            })
            .collect()
    }

    /// Recule l'horodatage de la dernière sauvegarde d'une app sur une destination.
    ///
    /// ⚠️ **Uniquement pour fabriquer des états**, en test et en mode démonstration :
    /// une sauvegarde de deux heures et une de trois semaines ne s'affichent pas pareil,
    /// et c'est précisément l'affichage qu'on veut vérifier. Il n'existe aucune raison
    /// légitime d'antidater une vraie sauvegarde — le faire mentirait sur la seule
    /// donnée qui dit si les données sont protégées.
    ///
    /// Ne touche qu'à la ligne la plus récente, celle qui décide de la fraîcheur.
    pub async fn backdate_backup(&self, app: &str, destination: &str, secondes: i64) -> Result<()> {
        sqlx::query(
            "UPDATE backup_runs
             SET finished_at = datetime(finished_at, ?3)
             WHERE id = (SELECT id FROM backup_runs
                         WHERE app = ?1 AND destination = ?2
                         ORDER BY id DESC LIMIT 1)",
        )
        .bind(app)
        .bind(destination)
        .bind(format!("-{secondes} seconds"))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Antidate une entrée du journal d'audit, par identifiant.
    ///
    /// ⚠️ Même réserve que `backdate_backup` : **uniquement** pour fabriquer un état de
    /// démonstration. Une frise chronologique dont tous les événements portent la même
    /// minute ne montre rien — or c'est exactement ce qu'elle existe pour montrer :
    /// « l'app est tombée à 3 h 12 » à côté de « mise à jour appliquée à 3 h 10 ».
    ///
    /// 🔴 N'est PAS exposée par l'API : réécrire un horodatage d'audit casserait le
    /// chaînage, et c'est bien le but du chaînage de rendre cela visible.
    pub async fn backdate_audit(&self, id: i64, secondes: i64) -> Result<()> {
        sqlx::query("UPDATE audit_log SET at = datetime(at, ?2) WHERE id = ?1")
            .bind(id)
            .bind(format!("-{secondes} seconds"))
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
            sqlx::query("INSERT INTO backup_routes (app, class, destination) VALUES (?1, ?2, ?3)")
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

    pub async fn upsert_user(
        &self,
        name: &str,
        profil: &str,
        pocket_id: Option<&str>,
    ) -> Result<()> {
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
            .map(|r| {
                Ok((
                    r.try_get("name")?,
                    r.try_get("profil")?,
                    r.try_get("pocket_id")?,
                ))
            })
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
    ) -> Result<
        Vec<(
            String,
            String,
            Option<i64>,
            bool,
            Option<String>,
            Option<String>,
        )>,
    > {
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
            .map(|r| {
                Ok((
                    r.try_get("user")?,
                    r.try_get("mailbox")?,
                    r.try_get("local")?,
                ))
            })
            .collect()
    }

    /// La destination d'un jeton : `(utilisateur, boîte)`.
    ///
    /// 🔴 La boîte vit sur le JETON parce que le protocole addy.io n'a aucun champ
    /// pour la choisir — Bitwarden n'envoie que `domain` et `description`. Un jeton
    /// par boîte, et changer de destination revient à changer de jeton dans les
    /// réglages du gestionnaire de mots de passe : explicite, et ça se relit.
    ///
    /// La boîte est `None` pour « celle par défaut », qui est le cas courant.
    pub async fn token_target(&self, token_name: &str) -> Result<(Option<String>, Option<String>)> {
        let row = sqlx::query("SELECT user, mailbox FROM api_tokens WHERE name = ?1")
            .bind(token_name)
            .fetch_optional(&self.pool)
            .await?;

        Ok(match row {
            Some(r) => (
                r.try_get::<Option<String>, _>("user").ok().flatten(),
                r.try_get::<Option<String>, _>("mailbox").ok().flatten(),
            ),
            None => (None, None),
        })
    }

    /// Fixe la boîte visée par un jeton.
    pub async fn set_token_mailbox(&self, token_name: &str, mailbox: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE api_tokens SET mailbox = ?2 WHERE name = ?1")
            .bind(token_name)
            .bind(mailbox)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Rattache un jeton d'API à un utilisateur.
    ///
    /// 🔴 Sans ce lien, l'API d'aliases devrait recevoir le nom de l'utilisateur dans
    /// le corps de la requête — et un jeton volé pourrait alors créer des aliases sur
    /// la boîte de n'importe qui.
    pub async fn set_token_user(&self, token_name: &str, user: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE api_tokens SET user = ?2 WHERE name = ?1")
            .bind(token_name)
            .bind(user)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// L'utilisateur auquel ce jeton est rattaché, s'il y en a un.
    ///
    /// `None` = jeton de service : il n'a pas le droit d'agir au nom de quelqu'un.
    pub async fn token_user(&self, token_name: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT user FROM api_tokens WHERE name = ?1")
            .bind(token_name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| r.try_get::<Option<String>, _>("user").ok().flatten()))
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
            .map(|r| {
                Ok((
                    r.try_get("local")?,
                    r.try_get("folder")?,
                    r.try_get("hint")?,
                ))
            })
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

        let row =
            sqlx::query("SELECT name, fingerprint, role FROM api_tokens WHERE fingerprint = ?1")
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
        let rows = sqlx::query("SELECT name, role, last_used FROM api_tokens ORDER BY name")
            .fetch_all(&self.pool)
            .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("name")?,
                    r.try_get("role")?,
                    r.try_get("last_used")?,
                ))
            })
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
        tracing::warn!(
            cible,
            "🔴 retour arrière du schéma — opération destructrice"
        );
        sqlx::migrate!("./migrations")
            .undo(&self.pool, cible)
            .await?;
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

    /// ⚠️ `reussie` est un argument à part ENTIÈRE, et non déduit de `detail`.
    ///
    /// La signature précédente concluait « détail présent donc échec » : un appelant
    /// qui décrivait une vérification réussie (« 1 284 fichiers relus ») l'enregistrait
    /// comme un échec, et l'app restait éternellement « jamais vérifiée » alors que la
    /// vérification avait eu lieu. Le compilateur ne pouvait pas le dire — c'est le
    /// genre de couplage implicite dont le projet se méfie ailleurs.
    pub async fn record_verification(
        &self,
        app: &str,
        snapshot_id: &str,
        reussie: bool,
        detail: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO restore_verifications (app, snapshot_id, status, detail)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(app)
        .bind(snapshot_id)
        .bind(if reussie { "ok" } else { "failed" })
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

    /// Enregistre ce qui vient d'être RÉELLEMENT publié (§9.10).
    ///
    /// 🔴 Remplace tout le jeu, dans une transaction : une route retirée de la
    /// configuration doit disparaître d'ici aussi, sinon l'écran d'exposition
    /// signalerait éternellement une divergence déjà corrigée — et l'on cesserait de
    /// le lire.
    pub async fn record_ingress(&self, routes: &[(String, String, bool)]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM ingress_publie")
            .execute(&mut *tx)
            .await?;
        for (host, app, public) in routes {
            sqlx::query("INSERT INTO ingress_publie (host, app, public) VALUES (?1, ?2, ?3)")
                .bind(host)
                .bind(app)
                .bind(if *public { 1 } else { 0 })
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Ce qui est publié selon la dernière application.
    ///
    /// ⚠️ Une liste vide veut dire « la configuration d'entrée n'a jamais été
    /// appliquée », **pas** « rien n'est publié ». L'appelant doit distinguer les deux :
    /// les confondre annoncerait un cluster fermé alors qu'on n'en sait rien.
    pub async fn ingress_publie(&self) -> Result<Vec<(String, String, bool)>> {
        let rows = sqlx::query("SELECT host, app, public FROM ingress_publie ORDER BY host")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("host")?,
                    r.try_get("app")?,
                    r.try_get::<i64, _>("public")? != 0,
                ))
            })
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
        sqlx::query("UPDATE apps SET status = ?2, updated_at = datetime('now') WHERE name = ?1")
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

    /// Enregistre un plan sous un nom (§10.4).
    ///
    /// ⚠️ Écrase un plan du même nom : c'est le dernier préparé qui compte. Refuser
    /// obligerait à inventer des noms à rallonge, et l'on finirait avec « migration-2 »,
    /// « migration-2-bis » sans savoir lequel est bon.
    #[allow(clippy::too_many_arguments)]
    pub async fn enregistrer_plan(
        &self,
        nom: &str,
        methode: &str,
        chemin: &str,
        corps: &str,
        resume: &str,
        par: &str,
        note: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO plans_nommes (nom, methode, chemin, corps, resume, cree_par, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(nom) DO UPDATE SET
                 methode = excluded.methode, chemin = excluded.chemin,
                 corps = excluded.corps, resume = excluded.resume,
                 cree_par = excluded.cree_par, cree_le = datetime('now'),
                 note = excluded.note",
        )
        .bind(nom)
        .bind(methode)
        .bind(chemin)
        .bind(corps)
        .bind(resume)
        .bind(par)
        .bind(note)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Les plans enregistrés : `(nom, méthode, chemin, corps, résumé, par, âge)`.
    pub async fn plans_nommes(
        &self,
    ) -> Result<Vec<(String, String, String, String, String, String, i64)>> {
        let rows = sqlx::query(
            "SELECT nom, methode, chemin, corps, resume, cree_par,
                    CAST(strftime('%s','now') AS INTEGER)
                      - CAST(strftime('%s', cree_le) AS INTEGER) AS age
             FROM plans_nommes ORDER BY cree_le DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("nom")?,
                    r.try_get("methode")?,
                    r.try_get("chemin")?,
                    r.try_get("corps")?,
                    r.try_get("resume")?,
                    r.try_get("cree_par")?,
                    r.try_get::<Option<i64>, _>("age")?.unwrap_or(0),
                ))
            })
            .collect()
    }

    /// Oublie un plan.
    pub async fn oublier_plan(&self, nom: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM plans_nommes WHERE nom = ?1")
            .bind(nom)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Atteste un garde-fou d'accès de secours (§5.7bis).
    ///
    /// ⚠️ Écrase l'attestation précédente : c'est la DERNIÈRE vérification qui compte,
    /// pas la première. Garder l'historique ferait afficher « vérifié il y a deux ans »
    /// à côté d'une vérification d'hier.
    pub async fn attester_breakglass(&self, id: &str, par: &str, note: Option<&str>) -> Result<()> {
        sqlx::query(
            "INSERT INTO breakglass (id, atteste_par, note) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                 atteste_le = datetime('now'),
                 atteste_par = excluded.atteste_par,
                 note = excluded.note",
        )
        .bind(id)
        .bind(par)
        .bind(note)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Les attestations : `(id, âge en secondes, qui)`.
    pub async fn breakglass(&self) -> Result<Vec<(String, i64, String)>> {
        let rows = sqlx::query(
            "SELECT id, atteste_par,
                    CAST(strftime('%s','now') AS INTEGER)
                      - CAST(strftime('%s', atteste_le) AS INTEGER) AS age
             FROM breakglass",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("id")?,
                    r.try_get::<Option<i64>, _>("age")?.unwrap_or(0),
                    r.try_get("atteste_par")?,
                ))
            })
            .collect()
    }

    /// Les secrets avec leur âge, pour l'assistant de rotation (§9quater).
    ///
    /// ⚠️ L'âge est celui de la dernière ROTATION, ou de la création si le secret n'a
    /// jamais été tourné. Rendre l'âge de création dans les deux cas ferait passer un
    /// secret tourné hier pour un secret de trois ans.
    ///
    /// 🔴 Aucune valeur ne sort d'ici, chiffrée ou non : ce que cette méthode ne peut
    /// pas représenter ne peut pas fuiter.
    pub async fn secrets_ages(&self) -> Result<Vec<(String, String, i64, bool)>> {
        let rows = sqlx::query(
            "SELECT name, purpose,
                    CAST(strftime('%s','now') AS INTEGER)
                      - CAST(strftime('%s', COALESCE(rotated_at, created_at)) AS INTEGER)
                      AS age,
                    rotated_at IS NULL AS jamais
             FROM secrets ORDER BY age DESC, name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("name")?,
                    r.try_get("purpose")?,
                    r.try_get::<Option<i64>, _>("age")?.unwrap_or(0),
                    r.try_get::<i64, _>("jamais")? != 0,
                ))
            })
            .collect()
    }

    pub async fn add_guide(&self, app: &str, id: &str, title: &str, blocking: bool) -> Result<()> {
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

/// Une session de navigateur, telle qu'on la présente à son propriétaire.
///
/// 🔴 Aucun champ ne porte la valeur du cookie : on ne peut pas fuiter ce qu'on ne peut
/// pas représenter. Même garantie structurelle que `SecretItem` et `StoredToken`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// Les premiers caractères de l'empreinte, pour désigner une session sans la
    /// nommer par un secret. Suffisant pour distinguer les siennes.
    pub reference: String,
    pub user: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_seen: i64,
    pub user_agent: Option<String>,
}

impl State {
    /// Reconstruit le compte complet d'une personne : profil, identité, boîtes, aliases.
    ///
    /// 🔴 Existe ici plutôt que dans le CLI, où elle vivait, parce que **deux
    /// reconstructions divergentes du même compte est exactement ce qui fait qu'un
    /// quota s'applique en ligne de commande et pas dans l'API**. C'était le cas :
    /// `POST /api/v1/aliases` ignorait les profils alors qu'un commentaire affirmait le
    /// contraire.
    ///
    /// `hlb-users` ne peut pas l'héberger : ce crate ne touche jamais la base, et c'est
    /// ce qui le rend testable sans serveur.
    pub async fn compte(&self, nom: &str) -> Result<hlb_users::Compte> {
        use hlb_users::{Alias, Boite, Compte, Duree};

        let inscrit = self.users().await?.into_iter().find(|(n, _, _)| n == nom);

        let (profil, pocket_id) = match inscrit {
            Some((_, p, id)) => (p, id),
            None => ("standard".to_string(), None),
        };

        let mut c = Compte::nouveau(nom, profil);
        c.pocket_id = pocket_id;

        let aliases = self.aliases(nom).await?;
        for (local, domaine, par_defaut) in self.mailboxes(nom).await? {
            let siens: Vec<Alias> = aliases
                .iter()
                .filter(|(boite, ..)| boite == &local)
                .map(|(_, l, expire, actif, _hint, note)| Alias {
                    local: l.clone(),
                    duree: match expire {
                        Some(e) => Duree::Temporaire { expire_le: *e },
                        None => Duree::Permanent,
                    },
                    actif: *actif,
                    note: note.clone(),
                })
                .collect();

            c.boites.push(Boite {
                local,
                domaine,
                par_defaut,
                aliases: siens,
            });
        }
        Ok(c)
    }

    // ---------------------------------------------------------------------------
    // Sessions (§9ter — connexion des personnes, par opposition aux jetons machine)
    // ---------------------------------------------------------------------------

    /// Ouvre une session pour une personne déjà authentifiée par PocketID.
    ///
    /// `presented` est la valeur du cookie ; **seule son empreinte est conservée**.
    pub async fn open_session(
        &self,
        presented: &str,
        user: &str,
        subject: Option<&str>,
        now: i64,
        duree_s: i64,
        user_agent: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO sessions
               (fingerprint, user, subject, created_at, expires_at, last_seen, user_agent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?4, ?6)",
        )
        .bind(hlb_types::token::fingerprint_of(presented))
        .bind(user)
        .bind(subject)
        .bind(now)
        .bind(now.saturating_add(duree_s))
        .bind(user_agent)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// À qui appartient ce cookie, s'il est encore valide ?
    ///
    /// 🔴 L'expiration est filtrée **en SQL**, pas dans l'appelant : une session
    /// expirée ne doit pas pouvoir être authentifiée par un appelant qui oublierait la
    /// comparaison. La recherche se fait par empreinte, sur la clé primaire — le temps
    /// de réponse ne dépend pas du nombre de sessions.
    ///
    /// Rend `(user, subject)`. Le **rôle n'est délibérément pas rendu ici** : il est relu
    /// séparément par [`Self::user_role`], pour qu'une révocation prenne effet à la
    /// requête suivante et non à l'expiration du cookie.
    pub async fn find_session(
        &self,
        presented: &str,
        now: i64,
    ) -> Result<Option<(String, Option<String>)>> {
        let row = sqlx::query(
            "SELECT user, subject FROM sessions WHERE fingerprint = ?1 AND expires_at > ?2",
        )
        .bind(hlb_types::token::fingerprint_of(presented))
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            None => Ok(None),
            Some(r) => Ok(Some((r.try_get("user")?, r.try_get("subject")?))),
        }
    }

    /// Prolonge une session vivante (expiration glissante) et note son dernier usage.
    ///
    /// Détaché de [`Self::find_session`] pour la même raison que `touch_token` l'est de
    /// `find_token` : noter l'usage ne doit ni ralentir ni faire échouer une requête.
    pub async fn touch_session(&self, presented: &str, now: i64, duree_s: i64) -> Result<()> {
        sqlx::query(
            "UPDATE sessions SET last_seen = ?2, expires_at = ?3
             WHERE fingerprint = ?1 AND expires_at > ?2",
        )
        .bind(hlb_types::token::fingerprint_of(presented))
        .bind(now)
        .bind(now.saturating_add(duree_s))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Ferme une session précise (déconnexion).
    pub async fn close_session(&self, presented: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM sessions WHERE fingerprint = ?1")
            .bind(hlb_types::token::fingerprint_of(presented))
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Ferme une session désignée par sa référence courte (« déconnecter cet appareil »).
    pub async fn close_session_by_reference(&self, user: &str, reference: &str) -> Result<bool> {
        let r =
            sqlx::query("DELETE FROM sessions WHERE user = ?1 AND substr(fingerprint, 1, ?3) = ?2")
                .bind(user)
                .bind(reference)
                .bind(reference.len() as i64)
                .execute(&self.pool)
                .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Ferme TOUTES les sessions d'une personne.
    ///
    /// C'est le geste qu'on fait quand on soupçonne une compromission, et il doit être
    /// atteignable en une commande.
    pub async fn close_all_sessions(&self, user: &str) -> Result<u64> {
        let r = sqlx::query("DELETE FROM sessions WHERE user = ?1")
            .bind(user)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    /// Les sessions vivantes d'une personne, la plus récemment vue d'abord.
    pub async fn sessions_of(&self, user: &str, now: i64) -> Result<Vec<SessionInfo>> {
        let rows = sqlx::query(
            "SELECT fingerprint, user, created_at, expires_at, last_seen, user_agent
             FROM sessions WHERE user = ?1 AND expires_at > ?2
             ORDER BY last_seen DESC",
        )
        .bind(user)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let f: String = r.try_get("fingerprint")?;
                Ok(SessionInfo {
                    reference: f.chars().take(8).collect(),
                    user: r.try_get("user")?,
                    created_at: r.try_get("created_at")?,
                    expires_at: r.try_get("expires_at")?,
                    last_seen: r.try_get("last_seen")?,
                    user_agent: r.try_get("user_agent")?,
                })
            })
            .collect()
    }

    /// Toutes les sessions vivantes, tous comptes confondus (écran de sécurité).
    pub async fn all_sessions(&self, now: i64) -> Result<Vec<SessionInfo>> {
        let rows = sqlx::query(
            "SELECT fingerprint, user, created_at, expires_at, last_seen, user_agent
             FROM sessions WHERE expires_at > ?1 ORDER BY last_seen DESC",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let f: String = r.try_get("fingerprint")?;
                Ok(SessionInfo {
                    reference: f.chars().take(8).collect(),
                    user: r.try_get("user")?,
                    created_at: r.try_get("created_at")?,
                    expires_at: r.try_get("expires_at")?,
                    last_seen: r.try_get("last_seen")?,
                    user_agent: r.try_get("user_agent")?,
                })
            })
            .collect()
    }

    /// Efface les sessions périmées.
    ///
    /// Elles ne sont plus authentifiantes (le filtre est en SQL), mais les garder
    /// indéfiniment ferait de la table un historique de connexions que personne n'a
    /// demandé — et qui partirait dans les sauvegardes.
    pub async fn purge_expired_sessions(&self, now: i64) -> Result<u64> {
        let r = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    /// Le compte Homelabus rattaché à cette identité PocketID.
    ///
    /// 🔴 On rattache par le `sub`, pas par le nom d'utilisateur : le `sub` est stable
    /// alors qu'un nom se renomme. Un rattachement par le nom perdrait le lien au
    /// premier renommage, en silence — la personne se reconnecterait et se verrait
    /// refuser l'accès sans que rien n'explique pourquoi.
    pub async fn user_by_pocket_id(&self, sub: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT name FROM users WHERE pocket_id = ?1")
            .bind(sub)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some(r.try_get("name")?)),
        }
    }

    /// Consigne le lien identité PocketID ↔ compte, à la première connexion.
    ///
    /// Idempotent, et ne touche à rien d'autre : le profil et les boîtes ne regardent
    /// pas la connexion.
    pub async fn upsert_user_pocket_id(&self, user: &str, sub: &str) -> Result<()> {
        sqlx::query("UPDATE users SET pocket_id = ?2 WHERE name = ?1")
            .bind(user)
            .bind(sub)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Annonces (lot 7.2)
    // ---------------------------------------------------------------------------

    /// Publie une annonce.
    ///
    /// ⚠️ Huit paramètres, et c'est assumé : les regrouper dans une structure
    /// obligerait chaque appelant à la construire, pour une seule fonction. Ils sont de
    /// types distincts, donc une inversion ne compile pas.
    #[allow(clippy::too_many_arguments)]
    pub async fn publier_annonce(
        &self,
        titre: &str,
        corps: &str,
        niveau: hlb_api::NiveauAnnonce,
        epinglee: bool,
        audience: Option<hlb_types::Role>,
        auteur: &str,
        expire_le: Option<i64>,
    ) -> Result<i64> {
        let r = sqlx::query(
            "INSERT INTO annonces (titre, corps, niveau, epinglee, audience, auteur, expire_le)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(titre)
        .bind(corps)
        .bind(niveau.as_str())
        .bind(i64::from(epinglee))
        .bind(audience.map(|r| r.as_str()))
        .bind(auteur)
        .bind(expire_le)
        .execute(&self.pool)
        .await?;
        Ok(r.last_insert_rowid())
    }

    /// Ajoute une nouvelle au fil d'une annonce.
    ///
    /// 🔴 Une mise à jour s'AJOUTE, elle ne remplace pas : c'est la chronologie qu'on
    /// relit après un incident — à quelle heure on a su, compris, réglé. Réécrire le
    /// corps d'origine l'effacerait.
    pub async fn suivre_annonce(&self, annonce: i64, corps: &str, auteur: &str) -> Result<()> {
        sqlx::query("INSERT INTO annonce_maj (annonce, corps, auteur) VALUES (?1, ?2, ?3)")
            .bind(annonce)
            .bind(corps)
            .bind(auteur)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Les annonces visibles par ce rôle.
    ///
    /// ⚠️ Filtrées par audience : une annonce d'exploitation n'intéresse pas
    /// l'utilisateur du portail, et l'inonder de messages qui ne le concernent pas lui
    /// fait cesser de les lire — au moment précis où l'un d'eux comptera.
    pub async fn annonces(
        &self,
        role: hlb_types::Role,
        maintenant: i64,
        inclure_expirees: bool,
    ) -> Result<Vec<hlb_api::Annonce>> {
        let rows = sqlx::query(
            "SELECT id, titre, corps, niveau, epinglee, audience, auteur, publiee_le, expire_le
             FROM annonces
             WHERE (?2 = 1 OR expire_le IS NULL OR expire_le > ?1)
             ORDER BY epinglee DESC, id DESC LIMIT 50",
        )
        .bind(maintenant)
        .bind(i64::from(inclure_expirees))
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::new();
        for r in &rows {
            // L'audience : `None` = tout le monde. Un rôle illisible en base rend
            // l'annonce visible de tous plutôt que de personne — une annonce qu'on ne
            // voit pas ne sert à rien, et le contenu est de toute façon public.
            let requis = r
                .try_get::<Option<String>, _>("audience")?
                .and_then(|a| hlb_types::Role::parse(&a));
            if requis.is_some_and(|req| role < req) {
                continue;
            }

            let id: i64 = r.try_get("id")?;
            out.push(hlb_api::Annonce {
                id,
                titre: r.try_get("titre")?,
                corps: r.try_get("corps")?,
                niveau: hlb_api::NiveauAnnonce::parse(&r.try_get::<String, _>("niveau")?),
                epinglee: r.try_get::<i64, _>("epinglee")? != 0,
                auteur: r.try_get("auteur")?,
                publiee_le: r.try_get("publiee_le")?,
                expire_dans_s: r
                    .try_get::<Option<i64>, _>("expire_le")?
                    .map(|e| e - maintenant),
                suivi: self.suivi_de(id).await?,
            });
        }
        Ok(out)
    }

    async fn suivi_de(&self, annonce: i64) -> Result<Vec<hlb_api::MajAnnonce>> {
        let rows = sqlx::query(
            "SELECT corps, auteur, at FROM annonce_maj WHERE annonce = ?1 ORDER BY id ASC",
        )
        .bind(annonce)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok(hlb_api::MajAnnonce {
                    corps: r.try_get("corps")?,
                    auteur: r.try_get("auteur")?,
                    at: r.try_get("at")?,
                })
            })
            .collect()
    }

    /// Retire une annonce.
    pub async fn retirer_annonce(&self, id: i64) -> Result<bool> {
        let r = sqlx::query("DELETE FROM annonces WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    // ---------------------------------------------------------------------------
    // Invitations (lot 6.2)
    // ---------------------------------------------------------------------------

    /// Crée une invitation. **Seule l'empreinte est conservée.**
    ///
    /// `usages_max` : combien de personnes peuvent s'en servir. **1 par défaut**, le
    /// cas sûr — un lien à N usages qui fuite fait entrer N personnes.
    #[allow(clippy::too_many_arguments)]
    pub async fn creer_invitation(
        &self,
        presente: &str,
        cree_par: &str,
        profil: &str,
        role: hlb_types::Role,
        domaine: Option<&str>,
        maintenant: i64,
        duree_s: i64,
        usages_max: i64,
        note: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO invitations
               (fingerprint, cree_par, profil, role, domaine, cree_le, expire_le,
                usages_max, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(hlb_types::token::fingerprint_of(presente))
        .bind(cree_par)
        .bind(profil)
        .bind(role.as_str())
        .bind(domaine)
        .bind(maintenant)
        .bind(maintenant.saturating_add(duree_s))
        // ⚠️ Borné à 1 au minimum : un `usages_max` de zéro créerait une invitation
        // inutilisable dès sa création, ce qui ressemble à une panne.
        .bind(usages_max.max(1))
        .bind(note)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Consomme une invitation : la marque utilisée et rend ce qu'elle accorde.
    ///
    /// 🔴 **Marquée AVANT toute création**, dans la même requête que la lecture : une
    /// invitation consommée ne doit pas pouvoir resservir, même si la création échoue
    /// ensuite. L'inverse permettrait de créer plusieurs comptes avec un lien qu'on
    /// croit à usage unique — et le second compte porterait le même rôle.
    ///
    /// Rend `(profil, rôle, domaine)`, ou `None` si l'invitation est inconnue, expirée
    /// ou déjà utilisée. Les trois cas sont indistincts **à dessein** : les séparer
    /// dirait à qui essaie des jetons si l'un d'eux a existé.
    pub async fn consommer_invitation(
        &self,
        presente: &str,
        compte: &str,
        maintenant: i64,
    ) -> Result<Option<(String, hlb_types::Role, Option<String>)>> {
        let empreinte = hlb_types::token::fingerprint_of(presente);
        let mut tx = self.pool.begin().await?;

        // 🔴 `usages < usages_max` **dans la requête**, pas dans l'appelant : deux
        // inscriptions simultanées liraient le même compteur et passeraient toutes les
        // deux. La transaction rend l'incrément atomique.
        let row = sqlx::query(
            "SELECT profil, role, domaine FROM invitations
             WHERE fingerprint = ?1 AND usages < usages_max AND expire_le > ?2",
        )
        .bind(&empreinte)
        .bind(maintenant)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(r) = row else {
            return Ok(None);
        };

        // La marque, dans la MÊME transaction : deux inscriptions simultanées avec le
        // même lien ne peuvent pas passer toutes les deux.
        sqlx::query(
            // `compte` garde le DERNIER inscrit ; la trace complète vit au journal
            // d'audit, où chaque inscription est consignée avec son nom.
            "UPDATE invitations
             SET usages = usages + 1, utilise_le = datetime('now'), compte = ?2
             WHERE fingerprint = ?1",
        )
        .bind(&empreinte)
        .bind(compte)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(Some((
            r.try_get("profil")?,
            r.try_get::<String, _>("role")?
                .parse()
                .ok()
                .and_then(|s: String| hlb_types::Role::parse(&s))
                .unwrap_or_default(),
            r.try_get("domaine")?,
        )))
    }

    /// Les invitations, la plus récente d'abord.
    pub async fn invitations(&self, maintenant: i64) -> Result<Vec<hlb_api::InvitationSummary>> {
        let rows = sqlx::query(
            "SELECT fingerprint, cree_par, profil, role, expire_le, utilise_le, note,
                    usages, usages_max
             FROM invitations ORDER BY cree_le DESC LIMIT 100",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let f: String = r.try_get("fingerprint")?;
                Ok(hlb_api::InvitationSummary {
                    reference: f.chars().take(8).collect(),
                    cree_par: r.try_get("cree_par")?,
                    profil: r.try_get("profil")?,
                    role: r.try_get("role")?,
                    expire_dans_s: r.try_get::<i64, _>("expire_le")? - maintenant,
                    utilisee_le: r.try_get("utilise_le")?,
                    usages: r.try_get::<i64, _>("usages")? as usize,
                    usages_max: r.try_get::<i64, _>("usages_max")? as usize,
                    note: r.try_get("note")?,
                })
            })
            .collect()
    }

    /// Révoque une invitation par sa référence courte.
    pub async fn revoquer_invitation(&self, reference: &str) -> Result<bool> {
        // ⚠️ On révoque en ÉPUISANT, pas en supprimant : une invitation qui a déjà
        // servi porte la trace de qui l'a créée et de qui est entré. L'effacer perdrait
        // cette trace au moment précis où on en a besoin — quand un lien a fuité.
        let r = sqlx::query(
            "UPDATE invitations SET usages = usages_max
             WHERE substr(fingerprint, 1, ?2) = ?1 AND usages < usages_max",
        )
        .bind(reference)
        .bind(reference.len() as i64)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    // ---------------------------------------------------------------------------
    // Apparence : marque et préférences
    // ---------------------------------------------------------------------------

    /// La marque de l'installation.
    ///
    /// ⚠️ Retombe sur le défaut si la ligne manque : une base restaurée d'une version
    /// antérieure ne doit pas laisser l'interface sans en-tête.
    pub async fn marque(&self) -> Result<hlb_api::Marque> {
        let row = sqlx::query(
            "SELECT nom, produit, accent, pied, theme_defaut, logo IS NOT NULL AS a_logo
             FROM apparence WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(r) = row else {
            return Ok(hlb_api::Marque::default());
        };

        Ok(hlb_api::Marque {
            nom: r.try_get("nom")?,
            produit: r.try_get("produit")?,
            accent: r
                .try_get::<Option<String>, _>("accent")?
                .as_deref()
                .and_then(hex_rvb),
            logo: r.try_get::<i64, _>("a_logo")? != 0,
            pied: r.try_get("pied")?,
            theme_defaut: r.try_get("theme_defaut")?,
        })
    }

    /// Enregistre la marque. Ne touche pas au logo, qui a sa propre opération.
    pub async fn set_marque(&self, m: &hlb_api::Marque) -> Result<()> {
        let accent = m.accent.map(|[r, v, b]| format!("{r:02X}{v:02X}{b:02X}"));
        sqlx::query(
            "INSERT INTO apparence (id, nom, produit, accent, pied, theme_defaut)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
               nom = excluded.nom, produit = excluded.produit,
               accent = excluded.accent, pied = excluded.pied,
               theme_defaut = excluded.theme_defaut,
               modifie_le = datetime('now')",
        )
        .bind(&m.nom)
        .bind(&m.produit)
        .bind(accent)
        .bind(&m.pied)
        .bind(&m.theme_defaut)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Le logo, s'il y en a un.
    pub async fn logo(&self) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query("SELECT logo FROM apparence WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?;
        match row {
            None => Ok(None),
            Some(r) => Ok(r.try_get("logo")?),
        }
    }

    /// Pose ou retire le logo.
    pub async fn set_logo(&self, png: Option<&[u8]>) -> Result<()> {
        sqlx::query("UPDATE apparence SET logo = ?1, modifie_le = datetime('now') WHERE id = 1")
            .bind(png)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Le thème choisi par une personne. `None` = celui de l'installation.
    pub async fn theme_de(&self, user: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT theme FROM user_prefs WHERE user = ?1")
            .bind(user)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            None => Ok(None),
            Some(r) => Ok(r.try_get("theme")?),
        }
    }

    pub async fn set_theme_de(&self, user: &str, theme: Option<&str>) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_prefs (user, theme) VALUES (?1, ?2)
             ON CONFLICT(user) DO UPDATE SET theme = excluded.theme,
                                             modifie_le = datetime('now')",
        )
        .bind(user)
        .bind(theme)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Rôles des personnes
    // ---------------------------------------------------------------------------

    /// Attribue un rôle à une personne.
    pub async fn set_user_role(
        &self,
        user: &str,
        role: hlb_types::Role,
        granted_by: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_roles (user, role, granted_by) VALUES (?1, ?2, ?3)
             ON CONFLICT(user) DO UPDATE SET
               role = excluded.role,
               granted_by = excluded.granted_by,
               granted_at = datetime('now')",
        )
        .bind(user)
        .bind(role.as_str())
        .bind(granted_by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Le rôle d'une personne.
    ///
    /// 🔴 L'absence de ligne — et un rôle illisible en base — valent
    /// `Role::default()`, c'est-à-dire `utilisateur`. Une identité PocketID inconnue de
    /// Homelabus entre au plus bas, jamais plus : le défaut doit toujours aller dans le
    /// sens sûr.
    pub async fn user_role(&self, user: &str) -> Result<hlb_types::Role> {
        let row = sqlx::query("SELECT role FROM user_roles WHERE user = ?1")
            .bind(user)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row
            .and_then(|r| r.try_get::<String, _>("role").ok())
            .and_then(|s| hlb_types::Role::parse(&s))
            .unwrap_or_default())
    }

    /// Retire l'attribution explicite : la personne retombe au rôle par défaut.
    pub async fn clear_user_role(&self, user: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM user_roles WHERE user = ?1")
            .bind(user)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Tous les comptes et leur rôle : (compte, rôle, accordé par, accordé le).
    ///
    /// Les comptes sans attribution explicite apparaissent avec le rôle par défaut —
    /// les omettre laisserait croire qu'ils n'ont aucun accès, alors qu'ils ont celui
    /// d'un utilisateur.
    pub async fn users_with_roles(
        &self,
    ) -> Result<Vec<(String, hlb_types::Role, Option<String>, Option<String>)>> {
        let rows = sqlx::query(
            "SELECT u.name AS name, r.role AS role, r.granted_by AS granted_by,
                    r.granted_at AS granted_at
             FROM users u LEFT JOIN user_roles r ON r.user = u.name
             ORDER BY u.name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let role = r
                    .try_get::<Option<String>, _>("role")?
                    .and_then(|s| hlb_types::Role::parse(&s))
                    .unwrap_or_default();
                Ok((
                    r.try_get("name")?,
                    role,
                    r.try_get("granted_by")?,
                    r.try_get("granted_at")?,
                ))
            })
            .collect()
    }

    /// Y a-t-il au moins un administrateur ?
    ///
    /// 🔴 Sert à refuser la rétrogradation du dernier admin : un système sans personne
    /// pour accorder des droits ne se répare qu'en éditant la base à la main.
    pub async fn has_other_admin(&self, sauf: &str) -> Result<bool> {
        let row =
            sqlx::query("SELECT COUNT(*) AS n FROM user_roles WHERE role = 'admin' AND user <> ?1")
                .bind(sauf)
                .fetch_one(&self.pool)
                .await?;
        Ok(row.try_get::<i64, _>("n")? > 0)
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
    async fn a_successful_verification_is_never_recorded_as_a_failure() {
        // 🔴 Le défaut tel qu'il s'est présenté : la signature déduisait l'échec de la
        // présence d'un détail. Une vérification réussie DÉCRITE (« 1 284 fichiers
        // relus ») était donc enregistrée en échec, et l'app restait « jamais
        // vérifiée » — un écran rouge sur un travail effectivement fait, ce qui pousse
        // à refaire la vérification indéfiniment.
        let s = State::in_memory().await.expect("état en mémoire");

        s.record_verification("gitea", "a1b2c3d4", true, Some("1 284 fichiers relus"))
            .await
            .expect("enregistrement");

        let age = s
            .seconds_since_last_verification("gitea")
            .await
            .expect("lecture");
        assert!(age.is_some(), "la vérification réussie doit compter");
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
        assert_eq!(
            s.consecutive_failures_on("demo", "offsite").await.unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn a_token_can_target_a_specific_mailbox() {
        // 🔴 Le protocole addy.io n'a AUCUN champ pour choisir la boîte : Bitwarden
        // n'envoie que `domain` et `description`. Le jeton est donc le seul endroit
        // qui reste — un jeton par boîte, et changer de destination revient à changer
        // de jeton dans les réglages du gestionnaire de mots de passe.
        let s = State::in_memory().await.expect("état");
        s.upsert_user("remy", "standard", None)
            .await
            .expect("compte");

        let (_, jeton) = hlb_types::generate_token(
            "bw-photo",
            hlb_types::Role::Operator,
            [7u8; hlb_types::token::TOKEN_BYTES],
        );
        s.store_token(&jeton).await.expect("jeton");
        s.set_token_user("bw-photo", Some("remy"))
            .await
            .expect("rattachement");
        s.set_token_mailbox("bw-photo", Some("photo"))
            .await
            .expect("boîte");

        assert_eq!(
            s.token_target("bw-photo").await.expect("cible"),
            (Some("remy".into()), Some("photo".into()))
        );
    }

    #[tokio::test]
    async fn a_service_token_targets_nobody() {
        // Un jeton sans identité ne doit pas pouvoir agir au nom de quelqu'un : le
        // voler donnerait sinon le pouvoir de créer des adresses sur la boîte d'autrui.
        let s = State::in_memory().await.expect("état");
        let (_, jeton) = hlb_types::generate_token(
            "service",
            // Même en ADMIN : le privilège ne remplace pas l'identité.
            hlb_types::Role::Admin,
            [3u8; hlb_types::token::TOKEN_BYTES],
        );
        s.store_token(&jeton).await.expect("jeton");

        assert_eq!(
            s.token_target("service").await.expect("cible"),
            (None, None)
        );
    }

    #[tokio::test]
    async fn a_token_without_a_mailbox_falls_back_to_the_default_one() {
        // Le cas courant : un seul jeton, la boîte par défaut, rien à configurer.
        let s = State::in_memory().await.expect("état");
        s.upsert_user("remy", "standard", None)
            .await
            .expect("compte");
        let (_, jeton) = hlb_types::generate_token(
            "bw",
            hlb_types::Role::Operator,
            [9u8; hlb_types::token::TOKEN_BYTES],
        );
        s.store_token(&jeton).await.expect("jeton");
        s.set_token_user("bw", Some("remy"))
            .await
            .expect("rattachement");

        let (u, b) = s.token_target("bw").await.expect("cible");
        assert_eq!(u.as_deref(), Some("remy"));
        assert!(b.is_none(), "aucune boîte visée = celle par défaut");
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
        s.upsert_app("pocket-id", &manifest("pocket-id"), None)
            .await
            .expect("upsert");
        s.add_volume("pocket-id", "pid-data", "/mnt/pid", true, true)
            .await
            .expect("volume");
        s.add_volume("pocket-id", "pid-cache", "/mnt/cache", false, true)
            .await
            .expect("volume");
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("upsert");
        s.add_volume("gitea", "g-data", "/mnt/g", true, false)
            .await
            .expect("volume");

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
        s.upsert_app("statique", &manifest("statique"), None)
            .await
            .expect("upsert");
        s.set_app_status("statique", "running")
            .await
            .expect("statut");
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
        assert_eq!(
            s.days_since_successful_drill().await.expect("lecture"),
            Some(0)
        );
    }

    #[tokio::test]
    async fn the_schema_can_actually_go_back() {
        // 🔴 Écrire un `down` ne prouve rien : c'est de l'exécuter qui prouve que le
        // retour arrière fonctionne. Sans ce test, on découvrirait qu'un `down` est
        // cassé au pire moment — pendant un rollback, après un échec de mise à jour.
        let s = st().await;
        let avant = s.schema_version().await.expect("version").expect("migrée");
        assert!(
            avant >= 6,
            "toutes les migrations doivent être appliquées : {avant}"
        );

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
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();

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
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();

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
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
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
        assert!(s
            .store_secret_if_absent("db-pw", b"chiffre-1", "base")
            .await
            .unwrap());
        assert!(!s
            .store_secret_if_absent("db-pw", b"chiffre-2", "base")
            .await
            .unwrap());
        assert_eq!(
            s.secret("db-pw").await.unwrap().as_deref(),
            Some(&b"chiffre-1"[..])
        );
    }

    #[tokio::test]
    async fn rotation_replaces_the_value() {
        let s = st().await;
        s.store_secret_if_absent("db-pw", b"ancien", "base")
            .await
            .unwrap();
        s.rotate_secret("db-pw", b"nouveau").await.unwrap();
        assert_eq!(
            s.secret("db-pw").await.unwrap().as_deref(),
            Some(&b"nouveau"[..])
        );
    }

    #[tokio::test]
    async fn inventory_never_exposes_values() {
        let s = st().await;
        s.store_secret_if_absent("db-pw", b"tres-secret", "base gitea")
            .await
            .unwrap();
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
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
        s.add_guide("gitea", "tip", "une astuce", false)
            .await
            .unwrap();
        s.add_guide("gitea", "admin", "créer l'admin", true)
            .await
            .unwrap();

        let g = s.pending_guides().await.unwrap();
        assert_eq!(g.len(), 2);
        assert!(g[0].3, "les bloquantes d'abord");
        assert_eq!(g[0].1, "admin");
    }

    // -----------------------------------------------------------------------
    // Sessions, rôles et intégrité du journal (lot 1)
    // -----------------------------------------------------------------------

    /// Un compte, prérequis de toute session (la table a une clé étrangère).
    async fn avec_compte(s: &State, nom: &str) {
        s.upsert_user(nom, "standard", Some("pid-1"))
            .await
            .expect("compte");
    }

    #[tokio::test]
    async fn every_volume_is_listed_even_the_unprotected_ones() {
        // ⚠️ Un volume absent de la liste se lit « il n'existe pas ». Ce qu'on veut
        // voir sur un écran de détail, c'est qu'il existe ET qu'il n'est pas protégé.
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        s.add_volume("gitea", "gitea-data", "/data", true, false)
            .await
            .expect("volume");
        s.add_volume("gitea", "gitea-cache", "/cache", false, false)
            .await
            .expect("volume");

        let tous = s.app_volumes("gitea").await.expect("volumes");
        assert_eq!(tous.len(), 2, "le cache non sauvegardé doit apparaître");

        let a_sauvegarder = s.volumes_to_backup("gitea").await.expect("volumes");
        assert_eq!(a_sauvegarder.len(), 1, "mais il ne part pas au dépôt");
    }

    #[tokio::test]
    async fn the_audit_can_be_filtered_on_one_app() {
        // Sur l'écran d'une app, le journal global est illisible : on veut ce qui la
        // concerne, elle.
        let s = st().await;
        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "install",
            "gitea",
            "ok",
            None,
        )
        .await
        .expect("audit");
        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "install",
            "vikunja",
            "ok",
            None,
        )
        .await
        .expect("audit");

        let j = s.audit_pour("gitea", 10).await.expect("journal");
        assert_eq!(j.len(), 1);
        assert_eq!(j[0].target, "gitea");
    }

    #[tokio::test]
    async fn the_history_keeps_the_failures() {
        // 🔴 Ne rendre que les réussites donnerait une frise où rien ne s'est jamais
        // mal passé — et une destination qui échoue depuis trois semaines y
        // ressemblerait à une destination qu'on n'utilise pas.
        let s = st().await;
        s.record_backup_to("immich", "volume", "nas", Some("abc"), None)
            .await
            .expect("réussite");
        s.record_backup_to("immich", "volume", "offsite", None, Some("réseau coupé"))
            .await
            .expect("échec");

        let h = s.backup_history("immich", 10).await.expect("historique");
        assert_eq!(h.len(), 2);
        assert!(h.iter().any(|r| !r.a_reussi()), "l'échec doit être là");
        let echec = h.iter().find(|r| !r.a_reussi()).expect("l'échec");
        assert_eq!(echec.error.as_deref(), Some("réseau coupé"));
        assert_eq!(echec.destination.as_deref(), Some("offsite"));
    }

    #[tokio::test]
    async fn the_history_is_newest_first() {
        // ⚠️ Ordonné par `id` et non par `finished_at` : `datetime('now')` a une
        // résolution d'une SECONDE, et deux lignes de la même seconde s'ordonneraient
        // au hasard. C'est le même piège que le compteur d'échecs consécutifs.
        let s = st().await;
        for n in 0..5 {
            s.record_backup_to("gitea", "volume", "nas", Some(&format!("s{n}")), None)
                .await
                .expect("sauvegarde");
        }
        let h = s.backup_history("gitea", 10).await.expect("historique");
        assert_eq!(
            h[0].snapshot_id.as_deref(),
            Some("s4"),
            "la plus récente d'abord"
        );
        for f in h.windows(2) {
            assert!(f[0].id > f[1].id);
        }
    }

    #[tokio::test]
    async fn the_history_is_bounded() {
        // Une app sauvegardée toutes les quatre heures pendant un an fait 2 190 lignes.
        // Les rendre toutes à chaque affichage d'écran serait payé par le controller.
        let s = st().await;
        for n in 0..20 {
            s.record_backup_to("gitea", "volume", "nas", Some(&format!("s{n}")), None)
                .await
                .expect("sauvegarde");
        }
        assert_eq!(
            s.backup_history("gitea", 5)
                .await
                .expect("historique")
                .len(),
            5
        );
    }

    #[tokio::test]
    async fn verifications_are_readable_not_just_their_age() {
        // C'est le seul indicateur fiable que les sauvegardes fonctionnent vraiment.
        // Ne rendre que l'âge empêchait de savoir CE QUI avait été vérifié.
        let s = st().await;
        s.record_verification("gitea", "abc123", true, Some("1 284 fichiers relus"))
            .await
            .expect("vérification");

        let v = s.verifications("gitea", 10).await.expect("vérifications");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].snapshot_id, "abc123");
        assert_eq!(v[0].detail.as_deref(), Some("1 284 fichiers relus"));
    }

    #[tokio::test]
    async fn the_global_history_spans_every_app() {
        // La frise globale du §11bis : une colonne par jour, toutes apps confondues.
        let s = st().await;
        s.record_backup_to("gitea", "volume", "nas", Some("a"), None)
            .await
            .expect("sauvegarde");
        s.record_backup_to("immich", "volume", "nas", Some("b"), None)
            .await
            .expect("sauvegarde");

        let h = s.backup_history_all(10).await.expect("historique");
        assert_eq!(h.len(), 2);
        let apps: std::collections::BTreeSet<&str> = h.iter().map(|r| r.app.as_str()).collect();
        assert_eq!(apps.len(), 2);
    }

    #[tokio::test]
    async fn an_incident_is_followed_never_rewritten() {
        // 🔴 C'est la chronologie qu'on relit après coup : à quelle heure on a su,
        // compris, réglé. Réécrire le corps d'origine l'effacerait.
        let s = st().await;
        let id = s
            .publier_annonce(
                "Panne de gitea",
                "On cherche.",
                hlb_api::NiveauAnnonce::Incident,
                true,
                None,
                "remy",
                None,
            )
            .await
            .expect("annonce");

        s.suivre_annonce(id, "Cause : disque plein.", "remy")
            .await
            .expect("suivi");
        s.suivre_annonce(id, "Résolu.", "remy")
            .await
            .expect("suivi");

        let v = s
            .annonces(hlb_types::Role::User, 1_000, false)
            .await
            .expect("liste");
        assert_eq!(v.len(), 1);
        // Le message d'origine est INTACT…
        assert_eq!(v[0].corps, "On cherche.");
        // …et la chronologie est là, dans l'ordre.
        assert_eq!(v[0].suivi.len(), 2);
        assert_eq!(v[0].suivi[0].corps, "Cause : disque plein.");
        assert_eq!(v[0].derniere_nouvelle(), "Résolu.");
    }

    #[tokio::test]
    async fn an_operations_announcement_does_not_reach_the_portal() {
        // ⚠️ Inonder l'utilisateur de messages qui ne le concernent pas lui fait cesser
        // de les lire — au moment précis où l'un d'eux comptera.
        let s = st().await;
        s.publier_annonce(
            "Redémarrage des bases",
            "PostgreSQL redémarre à 3 h.",
            hlb_api::NiveauAnnonce::Maintenance,
            false,
            Some(hlb_types::Role::Operator),
            "remy",
            None,
        )
        .await
        .expect("annonce");
        s.publier_annonce(
            "Nouveau webmail",
            "Bulwark est disponible.",
            hlb_api::NiveauAnnonce::Info,
            false,
            None,
            "remy",
            None,
        )
        .await
        .expect("annonce");

        let portail = s
            .annonces(hlb_types::Role::User, 1_000, false)
            .await
            .expect("liste");
        assert_eq!(
            portail.len(),
            1,
            "l'annonce d'exploitation a fuité au portail"
        );
        assert_eq!(portail[0].titre, "Nouveau webmail");

        let admin = s
            .annonces(hlb_types::Role::Admin, 1_000, false)
            .await
            .expect("liste");
        assert_eq!(admin.len(), 2, "l'admin doit voir les deux");
    }

    #[tokio::test]
    async fn pinned_announcements_come_first() {
        let s = st().await;
        for (titre, epingle) in [
            ("ancienne", false),
            ("importante", true),
            ("récente", false),
        ] {
            s.publier_annonce(
                titre,
                "x",
                hlb_api::NiveauAnnonce::Info,
                epingle,
                None,
                "remy",
                None,
            )
            .await
            .expect("annonce");
        }
        let v = s
            .annonces(hlb_types::Role::User, 1_000, false)
            .await
            .expect("liste");
        assert_eq!(v[0].titre, "importante");
    }

    #[tokio::test]
    async fn an_expired_announcement_leaves_the_portal_but_stays_in_the_record() {
        // 🔴 C'est l'historique des incidents, et c'est ce qu'on relit après coup.
        let s = st().await;
        s.publier_annonce(
            "Panne passée",
            "x",
            hlb_api::NiveauAnnonce::Incident,
            false,
            None,
            "remy",
            Some(500),
        )
        .await
        .expect("annonce");

        let portail = s
            .annonces(hlb_types::Role::Admin, 1_000, false)
            .await
            .expect("liste");
        assert!(portail.is_empty(), "une annonce expirée reste au portail");

        let archive = s
            .annonces(hlb_types::Role::Admin, 1_000, true)
            .await
            .expect("liste");
        assert_eq!(archive.len(), 1, "l'historique a été perdu");
    }

    #[tokio::test]
    async fn an_invitation_is_never_stored_in_clear() {
        // 🔴 La base part dans les sauvegardes, donc hors site. Y stocker des jetons
        // utilisables ferait de chaque copie un trousseau de clés.
        let s = st().await;
        s.creer_invitation(
            "lien-secret-52-caracteres",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            1_000,
            604_800,
            1,
            None,
        )
        .await
        .expect("invitation");

        let brut: String = sqlx::query("SELECT group_concat(fingerprint) AS tout FROM invitations")
            .fetch_one(&s.pool)
            .await
            .expect("lecture")
            .try_get("tout")
            .expect("colonne");
        assert!(!brut.contains("lien-secret"), "{brut}");
        assert_eq!(brut.len(), 64, "une empreinte SHA-256");
    }

    #[tokio::test]
    async fn an_invitation_can_only_be_used_once() {
        // 🔴 La réutiliser créerait un second compte avec les mêmes droits, au nom de
        // quelqu'un qui n'a rien demandé.
        let s = st().await;
        s.creer_invitation(
            "lien",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            1_000,
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");

        let premier = s
            .consommer_invitation("lien", "alice", 1_100)
            .await
            .expect("conso");
        assert!(premier.is_some(), "la première fois doit marcher");

        let second = s
            .consommer_invitation("lien", "mallory", 1_200)
            .await
            .expect("conso");
        assert!(second.is_none(), "un lien à usage unique a resservi");
    }

    #[tokio::test]
    async fn an_expired_invitation_is_refused() {
        let s = st().await;
        s.creer_invitation(
            "lien",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            1_000,
            60,
            1,
            None,
        )
        .await
        .expect("invitation");

        assert!(s
            .consommer_invitation("lien", "a", 1_050)
            .await
            .expect("conso")
            .is_some());

        // Une autre, déjà expirée.
        s.creer_invitation(
            "lien2",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            1_000,
            60,
            1,
            None,
        )
        .await
        .expect("invitation");
        assert!(
            s.consommer_invitation("lien2", "b", 2_000)
                .await
                .expect("conso")
                .is_none(),
            "une invitation périmée a été acceptée"
        );
    }

    #[tokio::test]
    async fn the_invited_never_chooses_their_own_role() {
        // 🔴 Le rôle est fixé à l'INVITATION. Le laisser choisir permettrait de
        // s'inscrire administrateur.
        let s = st().await;
        s.creer_invitation(
            "lien",
            "remy",
            "invite",
            hlb_types::Role::Viewer,
            None,
            1_000,
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");

        let (profil, role, _) = s
            .consommer_invitation("lien", "alice", 1_100)
            .await
            .expect("conso")
            .expect("utilisable");
        assert_eq!(profil, "invite");
        assert_eq!(role, hlb_types::Role::Viewer);
    }

    #[tokio::test]
    async fn an_unknown_invitation_is_indistinguishable_from_an_expired_one() {
        // Les séparer dirait à qui essaie des jetons si l'un d'eux a existé.
        let s = st().await;
        assert!(s
            .consommer_invitation("jamais-cree", "a", 1_000)
            .await
            .expect("conso")
            .is_none());
    }

    #[tokio::test]
    async fn listing_invitations_never_exposes_a_usable_value() {
        let s = st().await;
        s.creer_invitation(
            "lien",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            1_000,
            3_600,
            1,
            Some("pour camille"),
        )
        .await
        .expect("invitation");

        let v = s.invitations(1_100).await.expect("liste");
        assert_eq!(v.len(), 1);
        assert_eq!(
            v[0].reference.len(),
            8,
            "une référence courte, pas le jeton"
        );
        assert!(v[0].utilisable());
        assert_eq!(v[0].expire_dans_s, 3_500);
        assert_eq!(v[0].note.as_deref(), Some("pour camille"));
    }

    #[tokio::test]
    async fn a_multi_use_invitation_serves_exactly_its_quota() {
        // Inviter cinq personnes avec un lien : ni quatre, ni six.
        let s = st().await;
        s.creer_invitation(
            "lien",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            1_000,
            3_600,
            3,
            None,
        )
        .await
        .expect("invitation");

        for (n, qui) in ["a", "b", "c"].iter().enumerate() {
            assert!(
                s.consommer_invitation("lien", qui, 1_100)
                    .await
                    .expect("conso")
                    .is_some(),
                "l'usage {} devait passer",
                n + 1
            );
        }
        assert!(
            s.consommer_invitation("lien", "d", 1_100)
                .await
                .expect("conso")
                .is_none(),
            "le quatrième usage a été accepté sur un lien à trois"
        );
    }

    #[tokio::test]
    async fn the_use_count_is_visible_before_it_runs_out() {
        // 🔴 Un lien largement ouvert qui traîne est une porte d'entrée : le nombre
        // restant doit se voir AVANT qu'il soit épuisé.
        let s = st().await;
        s.creer_invitation(
            "lien",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            1_000,
            3_600,
            5,
            None,
        )
        .await
        .expect("invitation");
        s.consommer_invitation("lien", "a", 1_100)
            .await
            .expect("conso");

        let v = s.invitations(1_200).await.expect("liste");
        assert_eq!(v[0].usages, 1);
        assert_eq!(v[0].usages_max, 5);
        assert_eq!(v[0].restants(), 4);
        assert!(
            v[0].largement_ouverte(),
            "un lien à quatre entrées restantes"
        );
        assert_eq!(v[0].etat(), "partiellement utilisée");
    }

    #[tokio::test]
    async fn zero_uses_is_corrected_to_one_rather_than_creating_a_dead_link() {
        // ⚠️ Une invitation à zéro usage serait inutilisable dès sa création, ce qui
        // ressemble à une panne — on chercherait le problème ailleurs.
        let s = st().await;
        s.creer_invitation(
            "lien",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            1_000,
            3_600,
            0,
            None,
        )
        .await
        .expect("invitation");

        assert!(s
            .consommer_invitation("lien", "a", 1_100)
            .await
            .expect("conso")
            .is_some());
    }

    #[tokio::test]
    async fn revoking_a_partially_used_link_closes_it_without_erasing_history() {
        // 🔴 Le geste qu'on fait quand un lien a FUITÉ : le fermer immédiatement. Le
        // supprimer perdrait la trace de qui l'a créé et de qui est déjà entré —
        // exactement au moment où on en a besoin.
        let s = st().await;
        s.creer_invitation(
            "lien",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            1_000,
            3_600,
            10,
            None,
        )
        .await
        .expect("invitation");
        s.consommer_invitation("lien", "alice", 1_100)
            .await
            .expect("conso");

        let reference: String = hlb_types::token::fingerprint_of("lien")
            .chars()
            .take(8)
            .collect();
        assert!(s.revoquer_invitation(&reference).await.expect("révocation"));

        // Fermée…
        assert!(s
            .consommer_invitation("lien", "mallory", 1_200)
            .await
            .expect("conso")
            .is_none());
        // …mais l'historique est là.
        let v = s.invitations(1_200).await.expect("liste");
        assert_eq!(
            v.len(),
            1,
            "l'invitation a été effacée au lieu d'être fermée"
        );
        assert_eq!(v[0].cree_par, "remy");
        assert_eq!(v[0].etat(), "épuisée");
    }

    #[tokio::test]
    async fn an_exhausted_invitation_has_nothing_left_to_revoke() {
        // Elle est déjà fermée : la « révoquer » n'aurait aucun effet, et rendre
        // « fait » laisserait croire à une action qui n'a rien changé.
        let s = st().await;
        s.creer_invitation(
            "lien",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            1_000,
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");
        let reference: String = hlb_types::token::fingerprint_of("lien")
            .chars()
            .take(8)
            .collect();

        s.consommer_invitation("lien", "alice", 1_100)
            .await
            .expect("conso");
        assert!(
            !s.revoquer_invitation(&reference).await.expect("révocation"),
            "une invitation utilisée ne doit pas s'effacer"
        );
    }

    #[tokio::test]
    async fn a_pending_invitation_can_be_revoked() {
        let s = st().await;
        s.creer_invitation(
            "lien",
            "remy",
            "standard",
            hlb_types::Role::User,
            None,
            1_000,
            3_600,
            1,
            None,
        )
        .await
        .expect("invitation");
        let reference: String = hlb_types::token::fingerprint_of("lien")
            .chars()
            .take(8)
            .collect();

        assert!(s.revoquer_invitation(&reference).await.expect("révocation"));
        assert!(s
            .consommer_invitation("lien", "a", 1_100)
            .await
            .expect("conso")
            .is_none());
    }

    #[tokio::test]
    async fn the_brand_exists_before_anyone_configures_it() {
        // Au premier démarrage, l'interface doit avoir quelque chose à afficher plutôt
        // qu'un en-tête vide qu'on prendrait pour un défaut de chargement.
        let s = st().await;
        let m = s.marque().await.expect("marque");
        assert_eq!(m.nom, "Turi Industries");
        assert!(!m.logo);
    }

    #[tokio::test]
    async fn a_brand_survives_a_round_trip_including_its_accent() {
        let s = st().await;
        let mut m = s.marque().await.expect("marque");
        m.nom = "Autre Maison".into();
        m.accent = Some([0x7B, 0x8C, 0xFF]);
        m.pied = Some("astreinte : 06 00 00 00 00".into());
        s.set_marque(&m).await.expect("écriture");

        let relue = s.marque().await.expect("relecture");
        assert_eq!(relue.nom, "Autre Maison");
        assert_eq!(relue.accent, Some([0x7B, 0x8C, 0xFF]));
        assert_eq!(relue.pied.as_deref(), Some("astreinte : 06 00 00 00 00"));
    }

    #[tokio::test]
    async fn writing_the_brand_never_drops_the_logo() {
        // Le logo a sa propre opération : l'écraser à chaque changement de nom ferait
        // disparaître une image qu'on a téléversée une fois, sans prévenir.
        let s = st().await;
        s.set_logo(Some(b"\x89PNG-faux")).await.expect("logo");

        let mut m = s.marque().await.expect("marque");
        assert!(m.logo);
        m.nom = "Renommee".into();
        s.set_marque(&m).await.expect("écriture");

        assert!(s.marque().await.expect("marque").logo, "le logo a disparu");
        assert!(s.logo().await.expect("logo").is_some());
    }

    #[tokio::test]
    async fn there_can_only_ever_be_one_brand() {
        // 🔴 Deux lignes donneraient une marque qui change selon l'ordre de lecture —
        // un défaut qu'on ne reproduirait jamais. La contrainte est dans le schéma.
        let s = st().await;
        let r = sqlx::query("INSERT INTO apparence (id, nom, produit) VALUES (2, 'x', 'y')")
            .execute(&s.pool)
            .await;
        assert!(r.is_err(), "une seconde marque a été acceptée");
    }

    #[tokio::test]
    async fn a_theme_is_a_preference_not_a_right() {
        // Les préférences sont séparées des rôles : mélanger les deux ferait passer un
        // changement de couleur par le contrôle d'accès aux droits.
        let s = st().await;
        avec_compte(&s, "remy").await;
        assert_eq!(s.theme_de("remy").await.expect("thème"), None);

        s.set_theme_de("remy", Some("Turi clair"))
            .await
            .expect("écriture");
        assert_eq!(
            s.theme_de("remy").await.expect("thème").as_deref(),
            Some("Turi clair")
        );
    }

    #[test]
    fn a_half_read_colour_is_refused_rather_than_guessed() {
        // Un accent aberrant est plus difficile à diagnostiquer qu'un accent absent.
        assert_eq!(hex_rvb("7B8CFF"), Some([0x7B, 0x8C, 0xFF]));
        assert_eq!(hex_rvb("#7B8CFF"), Some([0x7B, 0x8C, 0xFF]));
        assert_eq!(hex_rvb("7B8C"), None);
        assert_eq!(hex_rvb("ZZZZZZ"), None);
        assert_eq!(hex_rvb(""), None);
    }

    #[tokio::test]
    async fn a_session_cookie_is_never_stored_in_clear() {
        // 🔴 Même discipline que les jetons d'API : une base qui fuite — et elle part
        // dans les sauvegardes, donc hors site — ne doit pas être un trousseau de clés.
        let s = st().await;
        avec_compte(&s, "remy").await;
        s.open_session(
            "cookie-secret-52-caracteres",
            "remy",
            Some("sub-1"),
            1000,
            3600,
            None,
        )
        .await
        .expect("session");

        let brut: String = sqlx::query("SELECT group_concat(fingerprint) AS tout FROM sessions")
            .fetch_one(&s.pool)
            .await
            .expect("lecture")
            .try_get("tout")
            .expect("colonne");
        assert!(
            !brut.contains("cookie-secret"),
            "la valeur du cookie ne doit jamais toucher le disque : {brut}"
        );
        assert_eq!(brut.len(), 64, "une empreinte SHA-256 hexadécimale");
    }

    #[tokio::test]
    async fn an_expired_session_authenticates_nobody() {
        // 🔴 L'expiration est filtrée en SQL, pas laissée à l'appelant : un appelant
        // qui oublierait la comparaison authentifierait une session morte.
        let s = st().await;
        avec_compte(&s, "remy").await;
        s.open_session("c", "remy", None, 1000, 60, None)
            .await
            .expect("session");

        assert!(s.find_session("c", 1030).await.expect("avant").is_some());
        assert!(
            s.find_session("c", 1061).await.expect("après").is_none(),
            "une session périmée ne doit plus rien authentifier"
        );
    }

    #[tokio::test]
    async fn a_revoked_role_takes_effect_at_the_next_request() {
        // 🔴 Le rôle n'est PAS copié dans la session. S'il l'était, retirer les droits
        // d'administrateur à quelqu'un n'aurait aucun effet pendant douze heures — or
        // on retire des droits précisément quand on est pressé de le faire.
        let s = st().await;
        avec_compte(&s, "remy").await;
        s.set_user_role("remy", hlb_types::Role::Admin, Some("cli"))
            .await
            .expect("rôle");
        s.open_session("c", "remy", None, 1000, 3600, None)
            .await
            .expect("session");

        assert_eq!(
            s.user_role("remy").await.expect("rôle"),
            hlb_types::Role::Admin
        );

        s.set_user_role("remy", hlb_types::Role::Viewer, Some("cli"))
            .await
            .expect("rétrogradation");

        // La session vit toujours…
        assert!(s.find_session("c", 1010).await.expect("session").is_some());
        // …mais elle ne donne plus les mêmes droits.
        assert_eq!(
            s.user_role("remy").await.expect("rôle"),
            hlb_types::Role::Viewer
        );
    }

    #[tokio::test]
    async fn deleting_an_account_closes_its_sessions() {
        // Une personne révoquée ne doit pas rester connectée jusqu'à l'expiration de
        // son cookie.
        let s = st().await;
        avec_compte(&s, "remy").await;
        s.open_session("c", "remy", None, 1000, 3600, None)
            .await
            .expect("session");

        sqlx::query("DELETE FROM users WHERE name = 'remy'")
            .execute(&s.pool)
            .await
            .expect("suppression");

        assert!(s.find_session("c", 1010).await.expect("session").is_none());
    }

    #[tokio::test]
    async fn a_person_is_matched_by_a_stable_subject_not_by_their_name() {
        // 🔴 Un nom d'utilisateur se renomme chez PocketID ; le `sub` ne bouge pas.
        // Se rattacher au nom perdrait le lien au premier renommage, et la personne se
        // verrait refuser l'accès sans qu'aucun message n'explique pourquoi.
        let s = st().await;
        s.upsert_user("remy", "standard", Some("sub-stable"))
            .await
            .expect("compte");

        assert_eq!(
            s.user_by_pocket_id("sub-stable").await.expect("recherche"),
            Some("remy".into())
        );
        assert_eq!(
            s.user_by_pocket_id("autre-sub").await.expect("recherche"),
            None
        );
    }

    #[tokio::test]
    async fn linking_an_identity_touches_nothing_else() {
        // La connexion ne regarde ni le profil ni les boîtes : les écraser au passage
        // ferait perdre un quota à la première connexion.
        let s = st().await;
        s.upsert_user("remy", "illimite", None)
            .await
            .expect("compte");
        s.add_mailbox("remy", "remy", "turi.fr", true)
            .await
            .expect("boîte");

        s.upsert_user_pocket_id("remy", "sub-1")
            .await
            .expect("lien");

        let c = s.compte("remy").await.expect("compte");
        assert_eq!(c.profil, "illimite");
        assert_eq!(c.pocket_id.as_deref(), Some("sub-1"));
        assert_eq!(c.boites.len(), 1);
    }

    #[tokio::test]
    async fn an_unknown_person_gets_the_least_privileged_role() {
        // Une identité PocketID que Homelabus ne connaît pas entre au plus bas.
        let s = st().await;
        assert_eq!(
            s.user_role("jamais-vu").await.expect("rôle"),
            hlb_types::Role::User
        );
    }

    #[tokio::test]
    async fn an_unreadable_role_falls_back_to_the_default() {
        // Une colonne corrompue ne doit jamais accorder plus de droits.
        let s = st().await;
        avec_compte(&s, "remy").await;
        sqlx::query("INSERT INTO user_roles (user, role) VALUES ('remy', 'superadmin')")
            .execute(&s.pool)
            .await
            .expect("rôle bidon");
        assert_eq!(
            s.user_role("remy").await.expect("rôle"),
            hlb_types::Role::User
        );
    }

    #[tokio::test]
    async fn accounts_without_an_explicit_role_still_appear() {
        // Les omettre laisserait croire qu'ils n'ont aucun accès, alors qu'ils ont
        // celui d'un utilisateur.
        let s = st().await;
        avec_compte(&s, "alice").await;
        avec_compte(&s, "bob").await;
        s.set_user_role("alice", hlb_types::Role::Operator, None)
            .await
            .expect("rôle");

        let tous = s.users_with_roles().await.expect("liste");
        assert_eq!(tous.len(), 2);
        assert_eq!(tous[0].1, hlb_types::Role::Operator, "alice");
        assert_eq!(tous[1].1, hlb_types::Role::User, "bob, par défaut");
    }

    #[tokio::test]
    async fn a_session_can_be_named_without_naming_a_secret() {
        // On doit pouvoir dire « déconnecte cet appareil » sans manipuler le cookie.
        let s = st().await;
        avec_compte(&s, "remy").await;
        s.open_session("portable", "remy", None, 1000, 3600, Some("Firefox"))
            .await
            .expect("session");

        let vues = s.sessions_of("remy", 1010).await.expect("sessions");
        assert_eq!(vues.len(), 1);
        assert_eq!(vues[0].reference.len(), 8);
        assert_eq!(vues[0].user_agent.as_deref(), Some("Firefox"));

        assert!(s
            .close_session_by_reference("remy", &vues[0].reference)
            .await
            .expect("fermeture"));
        assert!(s
            .find_session("portable", 1010)
            .await
            .expect("session")
            .is_none());
    }

    #[tokio::test]
    async fn the_audit_chain_holds_across_entries() {
        let s = st().await;
        for n in 0..5 {
            s.audit(
                "cli",
                hlb_types::Role::Admin,
                "install",
                &format!("app{n}"),
                "ok",
                None,
            )
            .await
            .expect("audit");
        }
        let v = s.verify_audit_chain().await.expect("vérification");
        assert!(v.est_intacte(), "{}", v.describe());
        match v {
            AuditIntegrity::Intacte {
                verifiees,
                non_chainees,
                ..
            } => {
                assert_eq!(verifiees, 5);
                assert_eq!(non_chainees, 0);
            }
            AuditIntegrity::Rompue { .. } => panic!("chaîne rompue sans raison"),
        }
    }

    #[tokio::test]
    async fn a_tampered_entry_breaks_the_chain() {
        // 🔴 L'intérêt du chaînage : « append-only » n'est qu'une convention tant que
        // le fichier SQLite est ouvrable. Une réécriture reste possible, mais elle se
        // voit — ce qui est la seule garantie atteignable sans tiers de confiance.
        let s = st().await;
        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "install",
            "gitea",
            "ok",
            None,
        )
        .await
        .expect("audit");
        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "purge",
            "vikunja",
            "ok",
            None,
        )
        .await
        .expect("audit");

        sqlx::query("UPDATE audit_log SET target = 'innocent' WHERE action = 'purge'")
            .execute(&s.pool)
            .await
            .expect("falsification");

        let v = s.verify_audit_chain().await.expect("vérification");
        assert!(!v.est_intacte(), "une entrée modifiée doit se voir");
        assert!(v.describe().contains("ROMPUE"), "{}", v.describe());
    }

    #[tokio::test]
    async fn a_removed_entry_breaks_the_chain() {
        // Le cas qu'un attaquant tenterait en premier : effacer la trace de son
        // passage plutôt que la modifier.
        let s = st().await;
        for n in 0..3 {
            s.audit(
                "cli",
                hlb_types::Role::Admin,
                "install",
                &format!("app{n}"),
                "ok",
                None,
            )
            .await
            .expect("audit");
        }
        sqlx::query("DELETE FROM audit_log WHERE target = 'app1'")
            .execute(&s.pool)
            .await
            .expect("suppression");

        let v = s.verify_audit_chain().await.expect("vérification");
        assert!(!v.est_intacte(), "une entrée retirée doit se voir");
    }

    #[tokio::test]
    async fn entries_older_than_the_chain_are_named_not_hidden() {
        // 🔴 Backfiller les empreintes des anciennes entrées produirait une chaîne
        // d'apparence complète, bâtie sur un contenu peut-être déjà falsifié. Le
        // verdict doit donc dire DEPUIS QUAND il vaut.
        let s = st().await;
        sqlx::query(
            "INSERT INTO audit_log (actor, role, action, target, outcome)
             VALUES ('ancien', 'admin', 'install', 'gitea', 'ok')",
        )
        .execute(&s.pool)
        .await
        .expect("entrée pré-chaînage");

        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "install",
            "vikunja",
            "ok",
            None,
        )
        .await
        .expect("audit");

        let v = s.verify_audit_chain().await.expect("vérification");
        assert!(v.est_intacte());
        match v {
            AuditIntegrity::Intacte {
                verifiees,
                non_chainees,
                depuis_l_entree,
            } => {
                assert_eq!(verifiees, 1);
                assert_eq!(
                    non_chainees, 1,
                    "l'entrée antérieure est comptée, pas cachée"
                );
                assert!(depuis_l_entree.is_some());
            }
            AuditIntegrity::Rompue { .. } => panic!("pas de rupture attendue"),
        }
    }

    #[tokio::test]
    async fn moving_text_between_fields_does_not_preserve_the_hash() {
        // 🔴 Sans préfixe de longueur, une cible « gitea|ok » et une cible « gitea »
        // suivie de l'issue « ok » donneraient la même empreinte : on pourrait
        // requalifier un échec en réussite sans casser la chaîne.
        let a = empreinte_entree(
            None,
            ["t", "cli", "admin", "purge", "gitea|ok", "failed"],
            None,
        );
        let b = empreinte_entree(
            None,
            ["t", "cli", "admin", "purge", "gitea", "|okfailed"],
            None,
        );
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn the_audit_trail_carries_the_role_and_the_diff() {
        // Le §9ter demande « qui, quoi, quand, avec le diff » ; le diff manquait.
        let s = st().await;
        s.audit(
            "remy",
            hlb_types::Role::Operator,
            "config",
            "backup.interval",
            "ok",
            Some("4h → 2h"),
        )
        .await
        .expect("audit");

        let t = s.audit_trail(10).await.expect("journal");
        assert_eq!(t[0].role, "operator");
        assert_eq!(t[0].detail.as_deref(), Some("4h → 2h"));
    }

    #[tokio::test]
    async fn the_last_admin_cannot_be_identified_as_replaceable() {
        // Sert au refus de rétrograder le dernier admin : sans lui, plus personne ne
        // peut accorder de droits et le système ne se répare qu'à la main dans SQLite.
        let s = st().await;
        avec_compte(&s, "remy").await;
        avec_compte(&s, "alice").await;
        s.set_user_role("remy", hlb_types::Role::Admin, None)
            .await
            .expect("rôle");

        assert!(
            !s.has_other_admin("remy").await.expect("compte"),
            "il est le seul"
        );

        s.set_user_role("alice", hlb_types::Role::Admin, None)
            .await
            .expect("rôle");
        assert!(
            s.has_other_admin("remy").await.expect("compte"),
            "alice prend le relais"
        );
    }

    #[tokio::test]
    async fn audited_actions_are_retrievable_in_order() {
        let s = st().await;
        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "install",
            "gitea",
            "ok",
            None,
        )
        .await
        .unwrap();
        s.audit(
            "remy",
            hlb_types::Role::Operator,
            "purge",
            "vikunja",
            "refused",
            Some("rôle insuffisant"),
        )
        .await
        .unwrap();

        let t = s.audit_trail(10).await.unwrap();
        assert_eq!(t.len(), 2);
        // Le plus récent d'abord : c'est ce qu'on veut voir en cas d'incident.
        assert_eq!(t[0].action, "purge");
        assert_eq!(t[0].outcome, "refused");
    }

    #[tokio::test]
    async fn refusals_are_audited_too() {
        // 🔴 Une tentative refusée est au moins aussi intéressante qu'une réussie :
        // c'est le signal d'un accès mal configuré, ou d'une intrusion.
        let s = st().await;
        s.audit(
            "inconnu",
            hlb_types::Role::Viewer,
            "purge",
            "gitea",
            "refused",
            None,
        )
        .await
        .unwrap();
        assert_eq!(s.audit_trail(10).await.unwrap()[0].outcome, "refused");
    }

    #[tokio::test]
    async fn a_failure_does_not_push_back_the_schedule() {
        // 🔴 Sinon une sauvegarde cassée se ferait de plus en plus rare.
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();

        assert_eq!(s.seconds_since_last_success("gitea").await.unwrap(), None);

        s.record_backup("gitea", "volume", None, Some("disque plein"))
            .await
            .unwrap();
        assert_eq!(
            s.seconds_since_last_success("gitea").await.unwrap(),
            None,
            "un échec ne compte pas comme une réussite"
        );

        s.record_backup("gitea", "volume", Some("abc"), None)
            .await
            .unwrap();
        assert!(s
            .seconds_since_last_success("gitea")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn the_latest_successful_snapshot_is_retrievable() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();

        s.record_backup("gitea", "volume", Some("ancien"), None)
            .await
            .unwrap();
        s.record_backup("gitea", "volume", None, Some("échec"))
            .await
            .unwrap();
        s.record_backup("gitea", "volume", Some("recent"), None)
            .await
            .unwrap();

        assert_eq!(
            s.latest_snapshot("gitea").await.unwrap().as_deref(),
            Some("recent")
        );
    }

    #[tokio::test]
    async fn verifications_track_only_successes() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();

        s.record_verification("gitea", "abc", false, Some("contenu différent"))
            .await
            .unwrap();
        assert_eq!(
            s.seconds_since_last_verification("gitea").await.unwrap(),
            None,
            "une vérification en échec ne prouve rien"
        );

        s.record_verification("gitea", "abc", true, None)
            .await
            .unwrap();
        assert!(s
            .seconds_since_last_verification("gitea")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn volumes_are_recorded_with_their_real_path() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();

        s.add_volume(
            "gitea",
            "gitea-data",
            "/var/lib/docker/volumes/gitea-data/_data",
            true,
            false,
        )
        .await
        .unwrap();
        // Un cache : pas de sauvegarde.
        s.add_volume("gitea", "gitea-cache", "/ailleurs", false, false)
            .await
            .unwrap();

        let v = s.volumes_to_backup("gitea").await.unwrap();
        assert_eq!(v.len(), 1, "seul le volume à sauvegarder doit remonter");
        assert_eq!(v[0].0, "gitea-data");
        assert!(v[0].1.ends_with("/_data"));
    }

    #[tokio::test]
    async fn recording_a_volume_twice_updates_it() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
        s.add_volume("gitea", "d", "/ancien", true, false)
            .await
            .unwrap();
        s.add_volume("gitea", "d", "/nouveau", true, false)
            .await
            .unwrap();

        let v = s.volumes_to_backup("gitea").await.unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, "/nouveau");
    }

    #[tokio::test]
    async fn the_resolved_digest_is_frozen_in_the_manifest() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
        assert!(s
            .app_manifest("gitea")
            .await
            .unwrap()
            .spec
            .image
            .digest
            .is_none());

        s.set_app_digest("gitea", "sha256:abc").await.unwrap();

        let m = s.app_manifest("gitea").await.unwrap();
        assert_eq!(m.spec.image.digest.as_deref(), Some("sha256:abc"));
        // C'est le digest qui est déployé, pas le tag.
        assert_eq!(m.spec.image.reference(), "a/b:1@sha256:abc");
    }

    #[tokio::test]
    async fn verifying_a_guide_unblocks_it() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
        s.add_guide("gitea", "admin", "créer l'admin", true)
            .await
            .unwrap();

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
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
        s.record_plan("gitea", &[("A".into(), "a".into())])
            .await
            .unwrap();
        s.add_guide("gitea", "x", "y", true).await.unwrap();

        sqlx::query("DELETE FROM apps WHERE name = 'gitea'")
            .execute(&s.pool)
            .await
            .unwrap();

        assert!(s.plan_actions("gitea").await.unwrap().is_empty());
        assert!(s.pending_guides().await.unwrap().is_empty());
    }
}
