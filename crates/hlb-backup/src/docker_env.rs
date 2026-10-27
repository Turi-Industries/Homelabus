//! Handing variables to a `docker run`.
//!
//! 🔴 `-e NAME=value` puts the value on the Docker client's command line, which every
//! account of the node reads in `ps` and `/proc/<pid>/cmdline` for as long as the
//! container runs — a repository password, an S3 secret, a database password. `-e NAME`
//! alone makes the client read the value from its own environment, which only its owner
//! and root can read. This is the one place a `docker run` gets `-e`
//! (`hlb-types/tests/argv.rs` refuses it anywhere else).

use tokio::process::Command;

/// Adds every variable of `env` to `cmd` by name, its value in the client's environment.
pub fn pass_by_name<'a>(cmd: &mut Command, env: impl IntoIterator<Item = &'a (String, String)>) {
    for (k, v) in env {
        cmd.arg("-e");
        cmd.arg(k);
        cmd.env(k, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_goes_to_the_environment_and_only_its_name_to_the_command_line() {
        let mut cmd = Command::new("docker");
        let env = [("RESTIC_PASSWORD".to_string(), "s3cr3t-value".to_string())];
        pass_by_name(&mut cmd, &env);
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["-e", "RESTIC_PASSWORD"]);
        let set = cmd
            .as_std()
            .get_envs()
            .find(|(k, _)| *k == "RESTIC_PASSWORD")
            .and_then(|(_, v)| v)
            .map(|v| v.to_string_lossy().into_owned());
        assert_eq!(set.as_deref(), Some("s3cr3t-value"));
    }
}
