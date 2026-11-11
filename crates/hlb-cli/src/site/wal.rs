//! The vital server's WAL pushed to the site: the receiving end set up on the VPS, the
//! pushing service deployed beside the server at home (`hlb_backup::wal_ship`).
//!
//! The pusher holds a key of its own, never Homelabus's: the site's `authorized_keys`
//! lets it run the receiver and nothing else, so the container it runs in — a service
//! on a house node — can write WAL into one directory of the VPS and do nothing more.

use hlb_backup::wal_ship;
use hlb_bootstrap::Runner;
use hlb_orchestrator::{Orchestrator as _, ServiceSpec, SwarmOrchestrator};
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::VITAL_POSTGRES;

use crate::{parse_ssh_target, upgrade_app, Cli};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The pushing service, on the house.
pub const PUSHER: &str = "hlb-wal-push";

/// The pushing key, in the vault. A stored name.
const KEY_SECRET: &str = "site-wal-push-key";

/// The comment closing the pushing key's line: how it is found again and replaced.
const KEY_COMMENT: &str = " hlb-wal-push";

/// `before` with the pushing key's line replaced by `line`, every other kept as it was.
fn authorized_with(before: &str, line: &str) -> String {
    let mut out: Vec<&str> = before
        .lines()
        .filter(|l| !l.trim_end().ends_with(KEY_COMMENT))
        .collect();
    out.push(line);
    let mut s = out.join("\n");
    s.push('\n');
    s
}

/// Whether the vital server, as installed, archives what the pusher reads.
fn archives(m: &hlb_types::Manifest) -> bool {
    m.spec.args.ends_with(&wal_ship::primary_args())
}

/// The pushing key, made once.
async fn key(state: &State, vault: &Vault) -> Result<hlb_bootstrap::access::KeyPair> {
    if let Some(ct) = state.secret(KEY_SECRET).await? {
        let v: serde_json::Value = serde_json::from_str(&vault.decrypt(&ct)?)?;
        return Ok(hlb_bootstrap::access::KeyPair {
            private: v["private"].as_str().unwrap_or_default().to_string(),
            public: v["public"].as_str().unwrap_or_default().to_string(),
        });
    }
    let kp = hlb_bootstrap::access::generate_keypair("hlb-wal-push").await?;
    let json = serde_json::json!({ "private": kp.private, "public": kp.public });
    state
        .store_secret_if_absent(
            KEY_SECRET,
            &vault.encrypt(&json.to_string())?,
            "the key pushing the vital server's WAL to the site, refused anything else there",
        )
        .await?;
    Box::pin(key(state, vault)).await
}

/// The pusher, as the house runs it: on the vital server's node, its archive mounted,
/// root kept only to read and remove what PostgreSQL wrote there.
fn pusher(
    target: &wal_ship::Target,
    private: &str,
    known_hosts: &str,
    network: &str,
) -> ServiceSpec {
    let mut spec = ServiceSpec::new(PUSHER, hlb_backup::images::RESTIC)
        .network(network)
        .constraint(format!(
            "node.labels.{}==true",
            hlb_types::manifest::data_label(VITAL_POSTGRES)
        ))
        .mount(format!("{VITAL_POSTGRES}-wal"), wal_ship::PUSHER_ARCHIVE)
        .file(wal_ship::PUSHER_KEY, private)
        .file(wal_ship::PUSHER_KNOWN_HOSTS, known_hosts)
        .command(["sh", "-c", &wal_ship::pusher_script(target)]);
    // The archive is postgres's, 0700: root crosses it only with this.
    spec.hardening.cap_add = vec!["DAC_OVERRIDE".into()];
    spec.hardening.tmpfs = vec!["/tmp".into()];
    spec.memory = Some(hlb_types::manifest::Memory {
        reserve: hlb_types::manifest::Bytes(16 << 20),
        limit: hlb_types::manifest::Bytes(64 << 20),
    });
    spec
}

/// The site made to receive, and the pusher deployed. Whether it went.
pub async fn ship(cli: &Cli, state: &State, vault: &Vault, apply: bool) -> Result<bool> {
    let Some(s) = super::load(state, vault).await? else {
        return Ok(true);
    };
    if !apply {
        println!(
            "            its WAL pushed to {} every {} s at most, by {PUSHER} beside it,",
            s.name,
            wal_ship::ARCHIVE_TIMEOUT_S
        );
        println!("            with a key the site lets run its receiver and nothing else");
        return Ok(true);
    }
    println!("\nThe vital server's WAL, pushed to {}:", s.name);
    let installed = state.app_manifest(VITAL_POSTGRES).await?;
    if !archives(&installed) {
        // Installed before it archived: brought to the catalog's manifest first, or
        // the pusher would wait on an archive nothing fills.
        let catalog = crate::sources::catalog_with_sources(cli, state).await?;
        let code = upgrade_app(cli, state, &catalog, VITAL_POSTGRES, None, true).await?;
        if code != std::process::ExitCode::SUCCESS
            || !archives(&state.app_manifest(VITAL_POSTGRES).await?)
        {
            eprintln!("  🔴 {VITAL_POSTGRES} does not archive its WAL: nothing pushed");
            return Ok(false);
        }
    }

    let kp = key(state, vault).await?;
    let (_tmp, ssh) = super::lifeboat::ssh_to(state, vault, &s).await?;
    hlb_bootstrap::provision::install_file(
        &ssh,
        wal_ship::RECEIVER,
        &wal_ship::receiver_script(),
        0o700,
    )
    .await?;
    let home = ssh
        .run(&["sh".into(), "-c".into(), "printf %s \"$HOME\"".into()])
        .await?
        .stdout;
    let before = hlb_bootstrap::access::read_authorized_keys(&ssh, &home).await?;
    let after = authorized_with(&before, &wal_ship::authorized_line(&kp.public));
    if after != before {
        hlb_bootstrap::access::write_authorized_keys(&ssh, &home, &after, &before).await?;
    }
    println!("  ✓ its receiver, the only command the pushing key may run there");

    let host_key = ssh
        .read_file("/etc/ssh/ssh_host_ed25519_key.pub")
        .await?
        .ok_or("the site has no ed25519 host key to pin")?;
    let (host, user, port) = parse_ssh_target(&s.ssh);
    let target = wal_ship::Target {
        user: user.unwrap_or_else(|| "root".into()),
        host,
        port: port.unwrap_or(22),
    };
    let known = wal_ship::known_hosts_line(&target, &host_key);
    let orch = SwarmOrchestrator::connect().await?;
    orch.deploy(&pusher(&target, &kp.private, &known, &cli.platform_network))
        .await?;
    orch.wait_healthy(PUSHER, 120).await?;
    println!("  ✓ {PUSHER} running beside {VITAL_POSTGRES}");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pushing_key_s_line_is_replaced_and_every_other_kept() {
        let before = "ssh-ed25519 AAAA owner\nrestrict,command=\"/x\" ssh-ed25519 OLD hlb-wal-push\nssh-ed25519 BBBB homelabus@cluster\n";
        let after = authorized_with(
            before,
            "restrict,command=\"/x\" ssh-ed25519 NEW hlb-wal-push",
        );
        assert_eq!(
            after,
            "ssh-ed25519 AAAA owner\nssh-ed25519 BBBB homelabus@cluster\nrestrict,command=\"/x\" ssh-ed25519 NEW hlb-wal-push\n"
        );
        assert_eq!(
            authorized_with(&after, after.lines().last().unwrap_or_default()),
            after
        );
    }

    #[test]
    fn the_pusher_runs_beside_the_vital_server_with_one_capability() {
        let t = wal_ship::Target {
            user: "root".into(),
            host: "203.0.113.7".into(),
            port: 22,
        };
        let s = pusher(&t, "PRIVATE", "203.0.113.7 ssh-ed25519 K\n", "hlb_platform");
        assert_eq!(
            s.constraints,
            vec!["node.labels.hlb.data.postgres-vital==true"]
        );
        assert_eq!(
            s.mounts,
            vec![("postgres-vital-wal".to_string(), "/archive".to_string())]
        );
        assert_eq!(s.hardening.cap_add, vec!["DAC_OVERRIDE"]);
        assert!(s.hardening.read_only_rootfs);
    }
}
