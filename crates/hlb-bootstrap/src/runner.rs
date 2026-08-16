//! Exécution des commandes de bootstrap, en local ou à distance.
//!
//! Le même code de décision pilote les deux : le maître se configure lui-même, les
//! autres nœuds sont joints par SSH. Sans cette abstraction, on aurait deux
//! implémentations qui divergeraient.
//!
//! 🔴 **L'accès SSH est temporaire** (§2ter.2). Il sert à poser l'agent et le mesh
//! WireGuard ; ensuite le controller parle à l'agent en mTLS. Une clé SSH qui reste
//! valable indéfiniment sur tous les nœuds est un accès permanent qu'on n'a pas
//! choisi.

use std::process::Stdio;

use tokio::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("exécution de « {command} » : {source}")]
    Spawn {
        command: String,
        #[source]
        source: std::io::Error,
    },

    #[error("ssh vers {host} : {detail}")]
    Ssh { host: String, detail: String },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }

    /// La première ligne de sortie, nettoyée. Le cas courant pour lire une version.
    pub fn first_line(&self) -> Option<String> {
        self.stdout.lines().next().map(|l| l.trim().to_string()).filter(|l| !l.is_empty())
    }
}

/// Où exécuter une commande.
#[async_trait::async_trait]
pub trait Runner: Send + Sync {
    /// Lance une commande. Une commande qui échoue n'est **pas** une erreur : on veut
    /// pouvoir sonder l'absence d'un binaire sans que ça remonte en `Err`.
    async fn run(&self, argv: &[String]) -> Result<Output>;

    /// Lit un fichier. Séparé de `run` parce que `cat` n'existe pas partout de la
    /// même façon, et que l'implémentation locale peut faire mieux.
    async fn read_file(&self, path: &str) -> Result<Option<String>>;

    /// Étiquette lisible, pour les messages.
    fn label(&self) -> String;
}

/// La machine locale.
#[derive(Default)]
pub struct LocalRunner;

#[async_trait::async_trait]
impl Runner for LocalRunner {
    async fn run(&self, argv: &[String]) -> Result<Output> {
        let Some((prog, args)) = argv.split_first() else {
            return Ok(Output { status: -1, stdout: String::new(), stderr: "commande vide".into() });
        };

        let out = Command::new(prog)
            .args(args)
            .output()
            .await
            .map_err(|source| Error::Spawn {
                command: argv.join(" "),
                source,
            })?;

        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }

    async fn read_file(&self, path: &str) -> Result<Option<String>> {
        Ok(tokio::fs::read_to_string(path).await.ok())
    }

    fn label(&self) -> String {
        "local".into()
    }
}

/// Un nœud distant, joint par le client `ssh` du système.
///
/// On s'appuie sur le binaire plutôt que sur une bibliothèque : il respecte déjà la
/// configuration de l'utilisateur (`~/.ssh/config`, agent, ProxyJump, clés
/// matérielles). Réimplémenter tout ça serait à la fois long et moins sûr.
pub struct SshRunner {
    host: String,
    user: Option<String>,
    port: Option<u16>,
    identity: Option<String>,
}

impl SshRunner {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            user: None,
            port: None,
            identity: None,
        }
    }

    pub fn user(mut self, u: impl Into<String>) -> Self {
        self.user = Some(u.into());
        self
    }

    pub fn port(mut self, p: u16) -> Self {
        self.port = Some(p);
        self
    }

    pub fn identity(mut self, path: impl Into<String>) -> Self {
        self.identity = Some(path.into());
        self
    }

    fn base_args(&self) -> Vec<String> {
        let mut a = vec![
            // Pas d'invite interactive : un bootstrap qui attend une saisie sur un
            // nœud distant se bloque sans message.
            "-o".into(), "BatchMode=yes".into(),
            "-o".into(), "ConnectTimeout=10".into(),
        ];
        if let Some(p) = self.port {
            a.push("-p".into());
            a.push(p.to_string());
        }
        if let Some(i) = &self.identity {
            a.push("-i".into());
            a.push(i.clone());
        }
        a.push(match &self.user {
            Some(u) => format!("{u}@{}", self.host),
            None => self.host.clone(),
        });
        a
    }
}

#[async_trait::async_trait]
impl Runner for SshRunner {
    async fn run(&self, argv: &[String]) -> Result<Output> {
        let mut args = self.base_args();
        // On passe la commande échappée : les noms de paquets viennent de constantes,
        // mais on ne construit jamais une ligne de commande distante sans échapper.
        args.push(argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" "));

        let out = Command::new("ssh")
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|source| Error::Spawn {
                command: format!("ssh {}", self.host),
                source,
            })?;

        let status = out.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();

        // 255 est le code de ssh lui-même : la commande distante n'a jamais tourné.
        // Le confondre avec un échec applicatif enverrait sur une fausse piste.
        if status == 255 {
            return Err(Error::Ssh {
                host: self.host.clone(),
                detail: stderr.trim().to_string(),
            });
        }

        Ok(Output {
            status,
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr,
        })
    }

    async fn read_file(&self, path: &str) -> Result<Option<String>> {
        let out = self.run(&["cat".to_string(), path.to_string()]).await?;
        Ok(out.ok().then_some(out.stdout))
    }

    fn label(&self) -> String {
        match &self.user {
            Some(u) => format!("{u}@{}", self.host),
            None => self.host.clone(),
        }
    }
}

/// Échappement pour un shell distant.
fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_=./:@".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// Écrit un fichier sur la cible.
///
/// 🔴 Le contenu passe par l'**entrée standard**, jamais en argument de commande :
/// la ligne de commande d'un processus est lisible par tout utilisateur de la
/// machine, ce qui est inacceptable pour une clé WireGuard ou un certificat.
#[async_trait::async_trait]
pub trait WriteFile {
    async fn write_file(&self, path: &str, content: &str) -> Result<()>;
}

#[async_trait::async_trait]
impl WriteFile for LocalRunner {
    async fn write_file(&self, path: &str, content: &str) -> Result<()> {
        tokio::fs::write(path, content)
            .await
            .map_err(|source| Error::Spawn {
                command: format!("écriture de {path}"),
                source,
            })
    }
}

#[async_trait::async_trait]
impl WriteFile for SshRunner {
    async fn write_file(&self, path: &str, content: &str) -> Result<()> {
        let mut args = self.base_args();
        args.push(format!("cat > {}", shell_quote(path)));

        let mut child = Command::new("ssh")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| Error::Spawn {
                command: format!("écriture de {path} sur {}", self.host),
                source,
            })?;

        if let Some(mut si) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            si.write_all(content.as_bytes())
                .await
                .map_err(|source| Error::Spawn {
                    command: format!("envoi du contenu de {path}"),
                    source,
                })?;
            let _ = si.shutdown().await;
        }

        let out = child.wait_with_output().await.map_err(|source| Error::Spawn {
            command: format!("écriture de {path}"),
            source,
        })?;

        if !out.status.success() {
            return Err(Error::Ssh {
                host: self.host.clone(),
                detail: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_arguments_pass_through_unquoted() {
        assert_eq!(shell_quote("apt-get"), "apt-get");
        assert_eq!(shell_quote("--no-install-recommends"), "--no-install-recommends");
        assert_eq!(shell_quote("/etc/os-release"), "/etc/os-release");
        assert_eq!(shell_quote("root@node1"), "root@node1");
    }

    #[test]
    fn dangerous_arguments_are_quoted() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("; rm -rf /"), "'; rm -rf /'");
        assert_eq!(shell_quote("$(whoami)"), "'$(whoami)'");
        assert_eq!(shell_quote("`id`"), "'`id`'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn embedded_quotes_survive() {
        assert_eq!(shell_quote("l'apostrophe"), r"'l'\''apostrophe'");
    }

    #[test]
    fn ssh_never_prompts() {
        // 🔴 Un bootstrap qui attend une saisie sur un nœud distant se bloque sans
        // message, jusqu'au délai d'attente.
        let args = SshRunner::new("node1").user("root").base_args().join(" ");
        assert!(args.contains("BatchMode=yes"), "{args}");
        assert!(args.contains("ConnectTimeout"), "{args}");
        assert!(args.contains("root@node1"), "{args}");
    }

    #[test]
    fn ssh_options_are_carried() {
        let args = SshRunner::new("node1")
            .port(2222)
            .identity("/tmp/cle")
            .base_args()
            .join(" ");
        assert!(args.contains("-p 2222"));
        assert!(args.contains("-i /tmp/cle"));
    }

    #[test]
    fn the_label_identifies_the_target() {
        assert_eq!(LocalRunner.label(), "local");
        assert_eq!(SshRunner::new("n1").user("hlb").label(), "hlb@n1");
        assert_eq!(SshRunner::new("n1").label(), "n1");
    }

    #[tokio::test]
    async fn a_local_command_runs() {
        let out = LocalRunner
            .run(&["echo".to_string(), "bonjour".to_string()])
            .await
            .expect("exécution");
        assert!(out.ok());
        assert_eq!(out.first_line().as_deref(), Some("bonjour"));
    }

    #[tokio::test]
    async fn a_failing_command_is_not_an_error() {
        // Sonder l'absence d'un binaire doit rester possible sans remonter en Err.
        let out = LocalRunner
            .run(&["sh".to_string(), "-c".to_string(), "exit 3".to_string()])
            .await
            .expect("exécution");
        assert!(!out.ok());
        assert_eq!(out.status, 3);
    }

    #[tokio::test]
    async fn a_missing_binary_is_reported_as_an_error() {
        // Là en revanche, on n'a rien pu lancer du tout.
        let r = LocalRunner
            .run(&["cette-commande-nexiste-pas-du-tout".to_string()])
            .await;
        assert!(matches!(r, Err(Error::Spawn { .. })));
    }

    #[tokio::test]
    async fn reading_a_missing_file_gives_none() {
        assert!(LocalRunner
            .read_file("/nexiste/vraiment/pas")
            .await
            .expect("lecture")
            .is_none());
    }

    #[tokio::test]
    async fn an_empty_command_does_not_panic() {
        let out = LocalRunner.run(&[]).await.expect("exécution");
        assert!(!out.ok());
    }
}
