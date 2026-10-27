//! Running the PostgreSQL client tools in a container.
//!
//! Same reasoning as for restic: `pg_dump` is not guaranteed present on the host, and
//! above all **its version must match the server** — a `pg_dump` 15 refuses to back up
//! a PostgreSQL 17. Going through the official image guarantees the pairing.

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::pgdump::{DumpRunner, RawOutput};
use crate::{Error, Result};

pub struct PgContainerRunner {
    image: String,
    /// Docker network on which the server is reachable.
    network: Option<String>,
}

impl PgContainerRunner {
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            network: None,
        }
    }

    /// Joins a network to reach the server by its service name.
    pub fn network(mut self, net: impl Into<String>) -> Self {
        self.network = Some(net.into());
        self
    }
}

impl Default for PgContainerRunner {
    fn default() -> Self {
        Self::new(crate::images::POSTGRES_CLIENT)
    }
}

/// Running the MariaDB client tools in a container.
///
/// Same reasoning as for PostgreSQL, with one more trap: the binaries were **renamed**
/// in MariaDB 10.5 (`mysqldump` -> `mariadb-dump`). The old names still exist as
/// symlinks, but they emit a deprecation warning on stderr — so noise in output you
/// read to diagnose.
///
/// ⚠️ The image must match the server, as for `pg_dump`: the default is the catalog's
/// own image, held to it by `hlb-catalog`'s tests.
pub struct MariaContainerRunner {
    image: String,
    network: Option<String>,
}

impl MariaContainerRunner {
    pub fn new(image: impl Into<String>) -> Self {
        Self {
            image: image.into(),
            network: None,
        }
    }

    pub fn network(mut self, net: impl Into<String>) -> Self {
        self.network = Some(net.into());
        self
    }
}

impl Default for MariaContainerRunner {
    fn default() -> Self {
        Self::new(crate::images::MARIADB_CLIENT)
    }
}

#[async_trait::async_trait]
impl DumpRunner for MariaContainerRunner {
    async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<RawOutput> {
        // The execution path is strictly the same as for PostgreSQL: only the image
        // changes. Sharing it keeps the two from diverging — notably on passing the
        // content through stdin, which is the subtle part.
        let r = PgContainerRunner::new(self.image.clone());
        let r = match &self.network {
            Some(n) => r.network(n.clone()),
            None => r,
        };
        r.run(args, env).await
    }
}

impl PgContainerRunner {
    /// The `docker run` the client tool is started by; `stdin` when a payload follows.
    fn command(&self, args: &[String], env: &[(String, String)], stdin: bool) -> Command {
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm", "-i"]);

        if let Some(n) = &self.network {
            cmd.arg("--network");
            cmd.arg(n);
        }
        // No point passing the payload as a variable: it travels through stdin.
        crate::docker_env::pass_by_name(&mut cmd, env.iter().filter(|(k, _)| k != "HLB_STDIN_B64"));

        cmd.arg("--entrypoint");
        cmd.arg("sh");
        cmd.arg(&self.image);
        cmd.arg("-c");

        let inner = args
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ");

        if stdin {
            // `base64 -d` rebuilds the binary dump before handing it to pg_restore.
            cmd.arg(format!("base64 -d | {inner}"));
        } else {
            cmd.arg(inner);
        }

        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd
    }
}

#[async_trait::async_trait]
impl DumpRunner for PgContainerRunner {
    async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<RawOutput> {
        // The content to restore arrives encoded so it can cross the environment; we
        // send it back on the container's standard input.
        let stdin_b64 = env
            .iter()
            .find(|(k, _)| k == "HLB_STDIN_B64")
            .map(|(_, v)| v.clone());

        let mut child = self
            .command(args, env, stdin_b64.is_some())
            .spawn()
            .map_err(|e| Error::ResticMissing(format!("docker not found: {e}")))?;

        if let Some(b64) = stdin_b64 {
            if let Some(mut si) = child.stdin.take() {
                si.write_all(b64.as_bytes())
                    .await
                    .map_err(|e| Error::Unexpected(format!("writing stdin: {e}")))?;
                si.shutdown()
                    .await
                    .map_err(|e| Error::Unexpected(format!("closing stdin: {e}")))?;
            }
        } else {
            drop(child.stdin.take());
        }

        let out = child
            .wait_with_output()
            .await
            .map_err(|e| Error::Unexpected(format!("waiting for the container: {e}")))?;

        Ok(RawOutput {
            status: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }
}

/// Escaping for `sh -c`. Database names come from manifests, not from free-form input,
/// but we never build a command line without escaping.
pub(crate) fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_=./:".contains(c))
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
    fn no_password_reaches_the_dump_tools_docker_command_line() {
        let env = [
            ("PGPASSWORD".to_string(), "pg-pass-1".to_string()),
            ("MYSQL_PWD".to_string(), "maria-pass-2".to_string()),
            ("HLB_STDIN_B64".to_string(), "cGF5bG9hZA==".to_string()),
        ];
        let cmd = PgContainerRunner::default().command(&["pg_dump".to_string()], &env, true);
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for (_, value) in &env {
            assert!(!args.iter().any(|a| a.contains(value.as_str())), "{args:?}");
        }
        assert!(
            args.windows(2).any(|w| w == ["-e", "PGPASSWORD"]),
            "{args:?}"
        );
        assert!(!args.iter().any(|a| a == "HLB_STDIN_B64"), "{args:?}");
    }

    #[test]
    fn simple_arguments_are_left_alone() {
        assert_eq!(shell_quote("pg_dump"), "pg_dump");
        assert_eq!(shell_quote("--format=custom"), "--format=custom");
    }

    #[test]
    fn dangerous_arguments_are_quoted() {
        assert_eq!(shell_quote("my database"), "'my database'");
        assert_eq!(shell_quote("a;rm -rf /"), "'a;rm -rf /'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
