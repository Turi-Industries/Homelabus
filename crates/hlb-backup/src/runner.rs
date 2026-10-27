//! The two ways of running restic.
//!
//! `HostRunner` assumes the binary is present: that is what the agent will use, having
//! direct access to the volumes. `ContainerRunner` only needs Docker — the development
//! path, and the fallback when the distribution does not package restic.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;

use crate::restic::{Output, Runner};
use crate::{Error, Result};

/// Invokes the system's `restic` binary.
pub struct HostRunner {
    binary: String,
}

impl Default for HostRunner {
    fn default() -> Self {
        Self {
            binary: "restic".into(),
        }
    }
}

impl HostRunner {
    fn command(&self, args: &[String], env: &[(String, String)]) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd
    }

    /// Checks the binary is available. Call it at startup rather than discovering it
    /// missing halfway through a backup.
    pub async fn probe(&self) -> Result<String> {
        let out = Command::new(&self.binary)
            .arg("version")
            .output()
            .await
            .map_err(|e| Error::ResticMissing(e.to_string()))?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

/// Runs `cmd` with `input` as its standard input, its standard output copied into
/// `out` when given — kept otherwise. Both ends move at once: restic reads while the
/// archive is written, and a full pipe on one side would stop the other.
///
/// 🔴 An input that breaks kills the container `name` BEFORE its standard input closes.
/// Closed first, restic would read the end of a stream and save the half it got as a
/// good snapshot; and killing the `docker` client alone leaves the container running,
/// to do exactly that.
async fn streamed(
    mut cmd: Command,
    name: &str,
    input: Option<&mut (dyn AsyncRead + Send + Unpin)>,
    out: Option<&mut (dyn AsyncWrite + Send + Unpin)>,
) -> Result<Output> {
    cmd.stdin(if input.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    })
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::ResticMissing(format!("docker not found: {e}")))?;
    let stdin = child.stdin.take();
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();

    let feed = async {
        let (Some(mut si), Some(i)) = (stdin, input) else {
            return Ok(());
        };
        match tokio::io::copy(i, &mut si).await {
            Ok(_) => si.shutdown().await,
            Err(e) => {
                let _ = Command::new("docker").args(["kill", name]).output().await;
                drop(si);
                Err(e)
            }
        }
    };
    let drain = async {
        let mut kept = Vec::new();
        if let Some(so) = stdout.as_mut() {
            match out {
                Some(o) => {
                    tokio::io::copy(so, o).await?;
                    o.flush().await?;
                }
                None => {
                    so.read_to_end(&mut kept).await?;
                }
            }
        }
        Ok::<Vec<u8>, std::io::Error>(kept)
    };
    let errors = async {
        let mut e = Vec::new();
        if let Some(se) = stderr.as_mut() {
            se.read_to_end(&mut e).await?;
        }
        Ok::<Vec<u8>, std::io::Error>(e)
    };
    let (fed, kept, errors) = tokio::join!(feed, drain, errors);
    let status = child.wait().await?;
    let stderr = String::from_utf8_lossy(&errors?).to_string();
    if let Err(e) = fed {
        return Err(Error::Restic {
            command: "fed a stream".into(),
            stderr: format!(
                "{e} — stopped before it could save a part of it ({})",
                stderr.trim()
            ),
        });
    }
    Ok(Output {
        status: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&kept?).to_string(),
        stderr,
    })
}

#[async_trait::async_trait]
impl Runner for HostRunner {
    async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<Output> {
        let mut cmd = self.command(args, env);

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

/// Runs restic in a disposable container.
pub struct ContainerRunner {
    image: String,
    /// `host:container` mounts — the repository and the data to back up.
    mounts: Vec<(String, String)>,
    /// Docker network to join.
    ///
    /// ⚠️ Indispensable for an S3 repository served INSIDE the cluster (Garage): without
    /// it, the restic container does not resolve `garage` and fails on a "no such host"
    /// that looks like a service outage when the network is what is missing.
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
        Self::new(crate::images::RESTIC)
    }
}

impl ContainerRunner {
    /// The `docker run` restic is started by; `-i` when it is handed a stream.
    fn command(&self, args: &[String], env: &[(String, String)]) -> Command {
        self.docker(args, env, None)
    }

    /// `name`: the container's, so a stream that breaks can kill it.
    fn docker(&self, args: &[String], env: &[(String, String)], name: Option<&str>) -> Command {
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm"]);
        if let Some(n) = name {
            cmd.args(["-i", "--name", n]);
        }

        crate::docker_env::pass_by_name(&mut cmd, env);
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
        cmd
    }
}

#[async_trait::async_trait]
impl Runner for ContainerRunner {
    async fn run_from(
        &self,
        args: &[String],
        env: &[(String, String)],
        input: &mut (dyn AsyncRead + Send + Unpin),
    ) -> Result<Output> {
        let name = format!("hlb-restic-{}", crate::verify::public_token());
        streamed(
            self.docker(args, env, Some(&name)),
            &name,
            Some(input),
            None,
        )
        .await
    }

    async fn run_into(
        &self,
        args: &[String],
        env: &[(String, String)],
        out: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<Output> {
        let name = format!("hlb-restic-{}", crate::verify::public_token());
        streamed(self.docker(args, env, Some(&name)), &name, None, Some(out)).await
    }

    async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<Output> {
        let out = self
            .command(args, env)
            .output()
            .await
            .map_err(|e| Error::ResticMissing(format!("docker not found: {e}")))?;

        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_secret_reaches_restics_docker_command_line() {
        let r = ContainerRunner::default().mount("/srv", "/data");
        let env = [
            ("RESTIC_PASSWORD".to_string(), "repo-pass-1".to_string()),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "s3-secret-2".to_string(),
            ),
        ];
        let cmd = r.command(&["snapshots".to_string()], &env);
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for (_, secret) in &env {
            assert!(
                !args.iter().any(|a| a.contains(secret.as_str())),
                "{args:?}"
            );
        }
        assert!(
            args.windows(2).any(|w| w == ["-e", "RESTIC_PASSWORD"]),
            "{args:?}"
        );
    }
}
