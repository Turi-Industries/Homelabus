//! Running bootstrap commands, locally or remotely.
//!
//! The same decision code drives both: the leader configures itself, the other nodes
//! are reached over SSH. Without this abstraction there would be two implementations
//! that would drift apart.
//!
//! 🔴 **SSH access is temporary.** It exists to install the agent and the WireGuard
//! mesh; after that the controller talks to the agent over mTLS. An SSH key that stays
//! valid indefinitely on every node is permanent access nobody chose.

use std::process::Stdio;

use tokio::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("running \"{command}\": {source}")]
    Spawn {
        command: String,
        #[source]
        source: std::io::Error,
    },

    #[error("ssh to {host}: {detail}")]
    Ssh { host: String, detail: String },

    /// 🔴 A deliberate refusal of a dangerous operation. Not a failure: the system
    /// protecting the user from themselves.
    #[error("{0}")]
    Refused(String),
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

    /// The first output line, trimmed. The common case for reading a version.
    pub fn first_line(&self) -> Option<String> {
        self.stdout
            .lines()
            .next()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
    }
}

/// Where to run a command.
#[async_trait::async_trait]
pub trait Runner: Send + Sync {
    /// Runs a command. A failing command is **not** an error: probing for a missing
    /// binary must not surface as `Err`.
    async fn run(&self, argv: &[String]) -> Result<Output>;

    /// Reads a file. Separate from `run` because `cat` is not the same everywhere, and
    /// the local implementation can do better.
    async fn read_file(&self, path: &str) -> Result<Option<String>>;

    /// Writes a file, creating it readable by its owner only.
    ///
    /// 🔴 The content goes through **standard input**, never as a command argument: a
    /// process's command line is readable by any user of the machine, which is
    /// unacceptable for a WireGuard key or a certificate. Callers that want another
    /// mode or an atomic replacement go through [`crate::provision::install_file`].
    async fn write_file(&self, path: &str, content: &str) -> Result<()>;

    /// A readable label, for messages.
    fn label(&self) -> String;
}

/// The local machine.
#[derive(Default)]
pub struct LocalRunner;

#[async_trait::async_trait]
impl Runner for LocalRunner {
    async fn run(&self, argv: &[String]) -> Result<Output> {
        let Some((prog, args)) = argv.split_first() else {
            return Ok(Output {
                status: -1,
                stdout: String::new(),
                stderr: "empty command".into(),
            });
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

    async fn write_file(&self, path: &str, content: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let spawn = |source| Error::Spawn {
            command: format!("writing {path}"),
            source,
        };
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        // The mode applies at creation: a key written under the default umask is
        // world-readable for as long as it takes to chmod it.
        #[cfg(unix)]
        options.mode(0o600);
        let mut f = options.open(path).await.map_err(spawn)?;
        f.write_all(content.as_bytes()).await.map_err(spawn)?;
        f.flush().await.map_err(spawn)
    }

    fn label(&self) -> String {
        "local".into()
    }
}

/// A remote node, reached through the system's `ssh` client.
///
/// The binary is used rather than a library: it already honours the user's
/// configuration (`~/.ssh/config`, the agent, ProxyJump, hardware keys).
/// Reimplementing all that would be both long and less safe.
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
            // No interactive prompt: a bootstrap waiting for input on a remote node
            // hangs with no message.
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "ConnectTimeout=10".into(),
            // A machine being added has never been seen: with BatchMode alone its first
            // contact fails on "Host key verification failed", and `node add` could
            // never reach a fresh node without a manual step first. `accept-new`
            // records the key on first contact and still REFUSES one that changes
            // afterwards — the case that is an attack rather than a new machine.
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
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

    /// The machine's Docker API on the local socket `local`, for as long as the returned
    /// bridge lives: each connection made to it is one `docker system dial-stdio` run
    /// over SSH — what `DOCKER_HOST=ssh://` does.
    ///
    /// 🔴 Not `ssh -L`: Homelabus's key is granted `no-port-forwarding` (`access`), and
    /// sshd refuses a socket forward under it — measured on the lab's VPS, the client
    /// saw only a connection closed. A command is what the key may run, and nothing
    /// listens on TCP. Proved once before returning, so a site whose Docker does not
    /// answer is said here rather than as the first API call's broken pipe.
    pub async fn docker_socket(&self, local: &std::path::Path) -> Result<DockerBridge> {
        let mut args = self.base_args();
        args.extend(["docker", "system", "dial-stdio"].map(String::from));
        let listener = tokio::net::UnixListener::bind(local).map_err(|source| Error::Spawn {
            command: format!("listening on {}", local.display()),
            source,
        })?;
        let task = tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let args = args.clone();
                tokio::spawn(async move {
                    let Ok(mut child) = Command::new("ssh")
                        .args(&args)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .kill_on_drop(true)
                        .spawn()
                    else {
                        return;
                    };
                    let (Some(mut to), Some(mut from)) = (child.stdin.take(), child.stdout.take())
                    else {
                        return;
                    };
                    let (mut read, mut write) = conn.into_split();
                    // Each half ends on its own: the client's end of request closes
                    // dial-stdio's input, and the daemon's answer still comes back.
                    let up = async {
                        let _ = tokio::io::copy(&mut read, &mut to).await;
                        drop(to);
                    };
                    let down = async {
                        let _ = tokio::io::copy(&mut from, &mut write).await;
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut write).await;
                    };
                    tokio::join!(up, down);
                    let _ = child.wait().await;
                });
            }
        });
        let bridge = DockerBridge {
            path: local.to_path_buf(),
            task,
        };
        let out = self
            .run(&["docker", "version", "--format", "{{.Server.Version}}"].map(String::from))
            .await?;
        if !out.ok() {
            return Err(Error::Ssh {
                host: self.host.clone(),
                detail: format!("its Docker does not answer: {}", out.stderr.trim()),
            });
        }
        Ok(bridge)
    }
}

/// A machine's Docker API on a local socket, closed when dropped.
pub struct DockerBridge {
    path: std::path::PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for DockerBridge {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

#[async_trait::async_trait]
impl Runner for SshRunner {
    async fn run(&self, argv: &[String]) -> Result<Output> {
        let mut args = self.base_args();
        // The command is passed escaped: package names come from constants, but a
        // remote command line is never built without escaping.
        args.push(
            argv.iter()
                .map(|a| shell_quote(a))
                .collect::<Vec<_>>()
                .join(" "),
        );

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

        // 255 is ssh's own code: the remote command never ran. Confusing it with an
        // application failure would send you down a false trail.
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

    async fn write_file(&self, path: &str, content: &str) -> Result<()> {
        let mut args = self.base_args();
        // `umask` first: a file created under the remote default is world-readable
        // until something narrows it.
        args.push(format!("umask 077 && cat > {}", shell_quote(path)));

        let mut child = Command::new("ssh")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| Error::Spawn {
                command: format!("writing {path} on {}", self.host),
                source,
            })?;

        if let Some(mut si) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            si.write_all(content.as_bytes())
                .await
                .map_err(|source| Error::Spawn {
                    command: format!("sending the content of {path}"),
                    source,
                })?;
            let _ = si.shutdown().await;
        }

        let out = child
            .wait_with_output()
            .await
            .map_err(|source| Error::Spawn {
                command: format!("writing {path}"),
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

    fn label(&self) -> String {
        match &self.user {
            Some(u) => format!("{u}@{}", self.host),
            None => self.host.clone(),
        }
    }
}

/// Escaping for a remote shell.
fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_=./:@".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_arguments_pass_through_unquoted() {
        assert_eq!(shell_quote("apt-get"), "apt-get");
        assert_eq!(
            shell_quote("--no-install-recommends"),
            "--no-install-recommends"
        );
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
        assert_eq!(shell_quote("the'apostrophe"), r"'the'\''apostrophe'");
    }

    #[test]
    fn ssh_never_prompts() {
        // 🔴 A bootstrap waiting for input on a remote node hangs with no message,
        // until the timeout.
        let args = SshRunner::new("node1").user("root").base_args().join(" ");
        assert!(args.contains("BatchMode=yes"), "{args}");
        assert!(args.contains("ConnectTimeout"), "{args}");
        assert!(args.contains("root@node1"), "{args}");
    }

    #[test]
    fn a_new_host_is_accepted_once_and_a_changed_one_never() {
        let args = SshRunner::new("node1").base_args().join(" ");
        assert!(args.contains("StrictHostKeyChecking=accept-new"), "{args}");
        // Never `no`: that would accept a key that CHANGED, which is the attack.
        assert!(!args.contains("StrictHostKeyChecking=no"), "{args}");
    }

    #[test]
    fn ssh_options_are_carried() {
        let args = SshRunner::new("node1")
            .port(2222)
            .identity("/tmp/key")
            .base_args()
            .join(" ");
        assert!(args.contains("-p 2222"));
        assert!(args.contains("-i /tmp/key"));
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
            .expect("execution");
        assert!(out.ok());
        assert_eq!(out.first_line().as_deref(), Some("bonjour"));
    }

    #[tokio::test]
    async fn a_failing_command_is_not_an_error() {
        // Probing for a missing binary must stay possible without surfacing an Err.
        let out = LocalRunner
            .run(&["sh".to_string(), "-c".to_string(), "exit 3".to_string()])
            .await
            .expect("execution");
        assert!(!out.ok());
        assert_eq!(out.status, 3);
    }

    #[tokio::test]
    async fn a_missing_binary_is_reported_as_an_error() {
        // Here, on the other hand, nothing could be launched at all.
        let r = LocalRunner
            .run(&["this-command-does-not-exist-at-all".to_string()])
            .await;
        assert!(matches!(r, Err(Error::Spawn { .. })));
    }

    #[tokio::test]
    async fn reading_a_missing_file_gives_none() {
        assert!(LocalRunner
            .read_file("/really/does/not/exist")
            .await
            .expect("read")
            .is_none());
    }

    #[tokio::test]
    async fn an_empty_command_does_not_panic() {
        let out = LocalRunner.run(&[]).await.expect("execution");
        assert!(!out.ok());
    }
}
