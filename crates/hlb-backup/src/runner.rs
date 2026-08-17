//! Les deux façons d'exécuter restic.
//!
//! `HostRunner` suppose le binaire présent : c'est ce qu'utilisera l'agent, qui a un
//! accès direct aux volumes. `ContainerRunner` n'a besoin que de Docker — c'est le
//! chemin du développement, et le repli quand la distribution ne package pas restic.

use tokio::process::Command;

use crate::restic::{Output, Runner};
use crate::{Error, Result};

/// Invoque le binaire `restic` du système.
pub struct HostRunner {
    binary: String,
}

impl Default for HostRunner {
    fn default() -> Self {
        Self { binary: "restic".into() }
    }
}

impl HostRunner {
    /// Vérifie la disponibilité du binaire. À appeler au démarrage plutôt que de
    /// découvrir l'absence au milieu d'une sauvegarde.
    pub async fn probe(&self) -> Result<String> {
        let out = Command::new(&self.binary)
            .arg("version")
            .output()
            .await
            .map_err(|e| Error::ResticMissing(e.to_string()))?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

#[async_trait::async_trait]
impl Runner for HostRunner {
    async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<Output> {
        let mut cmd = Command::new(&self.binary);
        cmd.args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }

        let out = cmd
            .output()
            .await
            .map_err(|e| Error::ResticMissing(e.to_string()))?;

        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }
}

/// Exécute restic dans un conteneur jetable.
pub struct ContainerRunner {
    image: String,
    /// Montages `hôte:conteneur` — le dépôt et les données à sauvegarder.
    mounts: Vec<(String, String)>,
    /// Réseau Docker à rejoindre.
    ///
    /// ⚠️ Indispensable pour un dépôt S3 servi DANS le cluster (Garage) : sans lui, le
    /// conteneur restic ne résout pas `garage` et échoue sur un « no such host » qui
    /// ressemble à une panne du service alors que c'est le réseau qui manque.
    network: Option<String>,
}

impl ContainerRunner {
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            mounts: Vec::new(),
            network: None,
        }
    }

    pub fn network(mut self, net: impl Into<String>) -> Self {
        self.network = Some(net.into());
        self
    }

    pub fn mount(mut self, host: impl Into<String>, container: impl Into<String>) -> Self {
        self.mounts.push((host.into(), container.into()));
        self
    }
}

impl Default for ContainerRunner {
    fn default() -> Self {
        Self::new("restic/restic:latest")
    }
}

#[async_trait::async_trait]
impl Runner for ContainerRunner {
    async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<Output> {
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm"]);

        for (k, v) in env {
            cmd.arg("-e");
            cmd.arg(format!("{k}={v}"));
        }
        for (h, c) in &self.mounts {
            cmd.arg("-v");
            cmd.arg(format!("{h}:{c}"));
        }
        if let Some(n) = &self.network {
            cmd.arg("--network");
            cmd.arg(n);
        }

        cmd.arg(&self.image);
        cmd.args(args);

        let out = cmd
            .output()
            .await
            .map_err(|e| Error::ResticMissing(format!("docker introuvable : {e}")))?;

        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }
}
