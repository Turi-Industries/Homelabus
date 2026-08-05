//! Pilotage de restic (§8 du plan).
//!
//! restic n'est pas une bibliothèque : on invoque le binaire. Mais **où** ? Ni restic
//! ni `pg_dump` ne sont garantis présents sur l'hôte, et le controller peut tourner sur
//! une distribution qui ne les package pas.
//!
//! D'où le trait [`Runner`] : l'agent utilisera le binaire local (accès direct aux
//! volumes, pas de surcoût), tandis que le développement et les tests passent par un
//! conteneur. Même code métier des deux côtés.

use serde::Deserialize;

use crate::retention::RetentionPolicy;
use crate::{Error, Result};

/// Comment exécuter une commande restic.
#[async_trait::async_trait]
pub trait Runner: Send + Sync {
    /// Exécute `restic <args>` avec les variables d'environnement fournies.
    async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<Output>;
}

#[derive(Debug, Clone)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }
}

/// Un instantané, tel que restic le décrit en JSON.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    pub id: String,
    pub time: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub hostname: String,
}

impl Snapshot {
    /// Identifiant court, celui qu'affiche restic et qu'un humain recopie.
    pub fn short_id(&self) -> &str {
        &self.id[..self.id.len().min(8)]
    }
}

/// Identité par défaut des instantanés. Stable par construction.
pub const DEFAULT_HOST: &str = "homelabus";

/// Un dépôt restic, avec son emplacement et son mot de passe.
pub struct Repository<R: Runner> {
    runner: R,
    location: String,
    /// Vient du coffre `age`. N'est jamais écrit sur disque en clair, ni journalisé.
    password: String,
    /// 🔴 Identité stable des instantanés — voir [`Repository::host`].
    host: String,
}

impl<R: Runner> Repository<R> {
    pub fn new(runner: R, location: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            runner,
            location: location.into(),
            password: password.into(),
            host: DEFAULT_HOST.to_string(),
        }
    }

    /// Fixe l'identité portée par les instantanés.
    ///
    /// 🔴 **Indispensable, et le piège le plus vicieux de restic.** `forget` groupe
    /// les instantanés par `host,paths` : chaque groupe applique la politique de
    /// rétention *séparément*. Si l'hôte varie d'une sauvegarde à l'autre — ce qui
    /// arrive dès qu'on exécute restic dans un conteneur, chacun ayant un hostname
    /// aléatoire, ou dès que l'agent change de nœud — chaque sauvegarde forme son
    /// propre groupe, et **plus rien n'est jamais supprimé**.
    ///
    /// Le symptôme est silencieux : la rétention est configurée, `forget` s'exécute
    /// sans erreur, et le disque se remplit quand même (§9bis).
    ///
    /// L'hôte doit donc identifier **le cluster**, pas la machine qui a lancé restic.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    pub fn location(&self) -> &str {
        &self.location
    }

    /// Le mot de passe passe par l'environnement, jamais en argument : la ligne de
    /// commande d'un processus est lisible par tout le monde sur la machine.
    fn env(&self) -> Vec<(String, String)> {
        vec![
            ("RESTIC_REPOSITORY".into(), self.location.clone()),
            ("RESTIC_PASSWORD".into(), self.password.clone()),
        ]
    }

    async fn exec(&self, args: &[&str]) -> Result<Output> {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let out = self.runner.run(&args, &self.env()).await?;
        if !out.ok() {
            return Err(Error::Restic {
                command: args.join(" "),
                stderr: out.stderr.trim().to_string(),
            });
        }
        Ok(out)
    }

    /// Crée le dépôt. Idempotent : un dépôt déjà initialisé n'est pas une erreur.
    pub async fn init(&self) -> Result<()> {
        let args = vec!["init".to_string()];
        let out = self.runner.run(&args, &self.env()).await?;

        if out.ok() {
            tracing::info!(repo = %self.location, "dépôt restic créé");
            return Ok(());
        }
        if out.stderr.contains("already initialized")
            || out.stderr.contains("already exists")
            || out.stdout.contains("already initialized")
        {
            tracing::debug!(repo = %self.location, "dépôt déjà initialisé");
            return Ok(());
        }
        Err(Error::Restic {
            command: "init".into(),
            stderr: out.stderr.trim().to_string(),
        })
    }

    /// Sauvegarde un chemin, étiqueté par l'app à laquelle il appartient.
    pub async fn backup(&self, path: &str, tags: &[&str]) -> Result<String> {
        let mut args = vec!["backup", path, "--json", "--host", &self.host];
        for t in tags {
            args.push("--tag");
            args.push(t);
        }
        let out = self.exec(&args).await?;

        // La sortie `--json` est une ligne par événement ; le résumé est en dernier.
        let id = out
            .stdout
            .lines()
            .rev()
            .find_map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).ok()?;
                if v.get("message_type")?.as_str()? == "summary" {
                    Some(v.get("snapshot_id")?.as_str()?.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::Unexpected(
                "restic n'a pas renvoyé d'identifiant d'instantané".into(),
            ))?;

        tracing::info!(id = %&id[..8.min(id.len())], path, "instantané créé");
        Ok(id)
    }

    pub async fn snapshots(&self, tag: Option<&str>) -> Result<Vec<Snapshot>> {
        let mut args = vec!["snapshots", "--json"];
        if let Some(t) = tag {
            args.push("--tag");
            args.push(t);
        }
        let out = self.exec(&args).await?;
        serde_json::from_str(&out.stdout).map_err(|e| Error::Unexpected(format!(
            "liste d'instantanés illisible : {e}"
        )))
    }

    /// Restaure un instantané vers `target`.
    pub async fn restore(&self, snapshot: &str, target: &str) -> Result<()> {
        self.exec(&["restore", snapshot, "--target", target]).await?;
        tracing::info!(snapshot, target, "restauration effectuée");
        Ok(())
    }

    /// Applique la rétention, puis libère l'espace.
    ///
    /// 🔴 Refuse une politique qui ne garde rien : ce serait un `rm -rf` déguisé.
    pub async fn forget(&self, policy: &RetentionPolicy, prune: bool) -> Result<()> {
        if !policy.keeps_something() {
            return Err(Error::EmptyRetention);
        }

        let mut args = vec!["forget".to_string()];
        args.extend(policy.to_args());
        if prune {
            args.push("--prune".to_string());
        }

        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.exec(&refs).await?;
        Ok(())
    }

    /// Vérifie l'intégrité du dépôt.
    ///
    /// §8.3 — un dépôt corrompu qu'on découvre le jour de la restauration, c'est un
    /// backup qui n'existait pas.
    pub async fn check(&self) -> Result<()> {
        self.exec(&["check"]).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Runner scriptable : rend des sorties dictées, enregistre les appels.
    struct Fake {
        outputs: Mutex<Vec<Output>>,
        calls: Mutex<Vec<Vec<String>>>,
        envs: Mutex<Vec<Vec<(String, String)>>>,
    }

    impl Fake {
        fn returning(outs: Vec<Output>) -> Self {
            Self {
                outputs: Mutex::new(outs),
                calls: Mutex::new(Vec::new()),
                envs: Mutex::new(Vec::new()),
            }
        }
        fn ok(stdout: &str) -> Self {
            Self::returning(vec![Output {
                status: 0,
                stdout: stdout.into(),
                stderr: String::new(),
            }])
        }
    }

    #[async_trait::async_trait]
    impl Runner for Fake {
        async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<Output> {
            self.calls.lock().expect("mutex").push(args.to_vec());
            self.envs.lock().expect("mutex").push(env.to_vec());
            let mut o = self.outputs.lock().expect("mutex");
            Ok(if o.len() > 1 { o.remove(0) } else { o[0].clone() })
        }
    }

    fn repo(f: Fake) -> Repository<Fake> {
        Repository::new(f, "/tmp/depot", "motdepasse")
    }

    #[tokio::test]
    async fn the_password_never_reaches_the_command_line() {
        // 🔴 La ligne de commande d'un processus est lisible par tout utilisateur
        // de la machine. Le mot de passe passe donc par l'environnement.
        let r = repo(Fake::ok("[]"));
        r.snapshots(None).await.expect("appel");

        let calls = r.runner.calls.lock().expect("mutex");
        assert!(
            !calls[0].iter().any(|a| a.contains("motdepasse")),
            "mot de passe trouvé dans les arguments : {:?}",
            calls[0]
        );

        let envs = r.runner.envs.lock().expect("mutex");
        assert!(envs[0]
            .iter()
            .any(|(k, v)| k == "RESTIC_PASSWORD" && v == "motdepasse"));
    }

    #[tokio::test]
    async fn init_is_idempotent() {
        let r = repo(Fake::returning(vec![Output {
            status: 1,
            stdout: String::new(),
            stderr: "Fatal: create repository at /tmp/depot failed: already initialized".into(),
        }]));
        assert!(r.init().await.is_ok(), "un dépôt déjà créé n'est pas une erreur");
    }

    #[tokio::test]
    async fn a_real_init_failure_is_reported() {
        let r = repo(Fake::returning(vec![Output {
            status: 1,
            stdout: String::new(),
            stderr: "Fatal: permission denied".into(),
        }]));
        let err = r.init().await.unwrap_err();
        assert!(err.to_string().contains("permission denied"), "{err}");
    }

    #[tokio::test]
    async fn the_snapshot_id_is_read_from_the_summary() {
        let json = r#"{"message_type":"status","percent_done":0.5}
{"message_type":"summary","snapshot_id":"abc123def456","files_new":3}"#;
        let r = repo(Fake::ok(json));
        let id = r.backup("/data", &["app:gitea"]).await.expect("sauvegarde");
        assert_eq!(id, "abc123def456");
    }

    #[tokio::test]
    async fn backups_carry_a_stable_host() {
        // 🔴 Sans `--host` fixe, `forget` groupe par hôte et ne supprime jamais rien.
        let r = repo(Fake::ok(r#"{"message_type":"summary","snapshot_id":"aaa"}"#));
        r.backup("/data", &[]).await.expect("sauvegarde");

        let calls = r.runner.calls.lock().expect("mutex");
        let joined = calls[0].join(" ");
        assert!(
            joined.contains("--host homelabus"),
            "hôte absent des arguments : {joined}"
        );
    }

    #[tokio::test]
    async fn tags_are_passed_through() {
        let r = repo(Fake::ok(
            r#"{"message_type":"summary","snapshot_id":"aaa"}"#,
        ));
        r.backup("/data", &["app:gitea", "kind:volume"]).await.expect("sauvegarde");

        let calls = r.runner.calls.lock().expect("mutex");
        let joined = calls[0].join(" ");
        assert!(joined.contains("--tag app:gitea"));
        assert!(joined.contains("--tag kind:volume"));
    }

    #[tokio::test]
    async fn an_empty_retention_is_refused() {
        // 🔴 `restic forget` sans aucun `--keep-*` supprime TOUT.
        let r = repo(Fake::ok(""));
        let vide = RetentionPolicy {
            hourly: 0,
            daily: 0,
            weekly: 0,
            monthly: 0,
            yearly: 0,
        };
        let err = r.forget(&vide, true).await.unwrap_err();
        assert!(matches!(err, Error::EmptyRetention), "{err}");

        // Et surtout : rien n'a été exécuté.
        assert!(r.runner.calls.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn forget_passes_the_policy_and_prunes() {
        let r = repo(Fake::ok(""));
        r.forget(&RetentionPolicy::default(), true).await.expect("forget");

        let calls = r.runner.calls.lock().expect("mutex");
        let joined = calls[0].join(" ");
        assert!(joined.contains("--keep-daily 14"));
        assert!(joined.contains("--prune"));
    }

    #[test]
    fn snapshots_deserialize_from_restic_json() {
        let json = r#"[{"id":"abcdef1234567890","time":"2026-08-05T03:00:00Z",
                        "paths":["/data"],"tags":["app:gitea"],"hostname":"node1"}]"#;
        let s: Vec<Snapshot> = serde_json::from_str(json).expect("analysable");
        assert_eq!(s[0].short_id(), "abcdef12");
        assert_eq!(s[0].tags, vec!["app:gitea"]);
    }
}
