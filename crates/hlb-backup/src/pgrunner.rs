//! Exécution des outils clients PostgreSQL dans un conteneur.
//!
//! Même raisonnement que pour restic : `pg_dump` n'est pas garanti présent sur
//! l'hôte, et surtout **sa version doit correspondre au serveur** — un `pg_dump` 15
//! refuse de sauvegarder un PostgreSQL 17. Passer par l'image officielle garantit
//! l'appariement.

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::pgdump::{DumpRunner, RawOutput};
use crate::{Error, Result};

pub struct PgContainerRunner {
    image: String,
    /// Réseau Docker sur lequel le serveur est joignable.
    network: Option<String>,
}

impl PgContainerRunner {
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            network: None,
        }
    }

    /// Rejoint un réseau pour atteindre le serveur par son nom de service.
    pub fn network(mut self, net: impl Into<String>) -> Self {
        self.network = Some(net.into());
        self
    }
}

impl Default for PgContainerRunner {
    fn default() -> Self {
        Self::new("postgres:17-alpine")
    }
}

#[async_trait::async_trait]
impl DumpRunner for PgContainerRunner {
    async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<RawOutput> {
        // Le contenu à restaurer arrive encodé pour traverser l'environnement ; on le
        // renvoie sur l'entrée standard du conteneur.
        let stdin_b64 = env
            .iter()
            .find(|(k, _)| k == "HLB_STDIN_B64")
            .map(|(_, v)| v.clone());

        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm", "-i"]);

        if let Some(n) = &self.network {
            cmd.arg("--network");
            cmd.arg(n);
        }
        for (k, v) in env {
            // Inutile de passer la charge utile en variable : elle transite par stdin.
            if k != "HLB_STDIN_B64" {
                cmd.arg("-e");
                cmd.arg(format!("{k}={v}"));
            }
        }

        cmd.arg("--entrypoint");
        cmd.arg("sh");
        cmd.arg(&self.image);
        cmd.arg("-c");

        let inner = args
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ");

        if stdin_b64.is_some() {
            // `base64 -d` reconstitue le dump binaire avant de le donner à pg_restore.
            cmd.arg(format!("base64 -d | {inner}"));
        } else {
            cmd.arg(inner);
        }

        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| Error::ResticMissing(format!("docker introuvable : {e}")))?;

        if let Some(b64) = stdin_b64 {
            if let Some(mut si) = child.stdin.take() {
                si.write_all(b64.as_bytes())
                    .await
                    .map_err(|e| Error::Unexpected(format!("écriture stdin : {e}")))?;
                si.shutdown()
                    .await
                    .map_err(|e| Error::Unexpected(format!("fermeture stdin : {e}")))?;
            }
        } else {
            drop(child.stdin.take());
        }

        let out = child
            .wait_with_output()
            .await
            .map_err(|e| Error::Unexpected(format!("attente du conteneur : {e}")))?;

        Ok(RawOutput {
            status: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }
}

/// Échappement pour `sh -c`. Les noms de base viennent de manifests, pas d'une
/// saisie libre, mais on ne construit jamais une ligne de commande sans échapper.
fn shell_quote(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "-_=./:".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_arguments_are_left_alone() {
        assert_eq!(shell_quote("pg_dump"), "pg_dump");
        assert_eq!(shell_quote("--format=custom"), "--format=custom");
    }

    #[test]
    fn dangerous_arguments_are_quoted() {
        assert_eq!(shell_quote("ma base"), "'ma base'");
        assert_eq!(shell_quote("a;rm -rf /"), "'a;rm -rf /'");
        assert_eq!(shell_quote("l'apostrophe"), r"'l'\''apostrophe'");
    }
}
