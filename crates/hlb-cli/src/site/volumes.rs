//! The vital apps' volumes pushed to the site every minute (`hlb_backup::volume_ship`):
//! the site's account set up, rclone deployed beside each volume at home, its pushes
//! judged by `site status`, laid in place by the promotion and emptied by the return.
//!
//! Each volume holds a key of its own, never Homelabus's: the site lets it write over
//! SFTP into the volume's own directory, and nothing else.

use hlb_backup::{images, volume_ship, wal_ship};
use hlb_bootstrap::Runner;
use hlb_engine::lifeboat::Pushed;
use hlb_orchestrator::{Orchestrator as _, ServiceSpec, SwarmOrchestrator};
use hlb_secrets::Vault;
use hlb_state::State;

use crate::{parse_ssh_target, Cli};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A carried app's volume and its pusher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carried {
    pub app: String,
    pub pushed: Pushed,
}

impl Carried {
    /// Its pusher's service at home, and its account on the site: one name.
    pub fn user(&self) -> Result<String> {
        Ok(volume_ship::user(&self.pushed.volume)?)
    }
}

/// What the apps the lifeboat carries push, and what the nightly copy alone carries
/// with why — the volumes the house recorded as backed up only: a name no deployment
/// created would be mounted empty, and an empty push replaces nothing.
pub async fn carried(
    state: &State,
    vault: &Vault,
) -> Result<(Vec<Carried>, Vec<(String, String)>)> {
    carried_among(state, &super::lifeboat::apps(state, vault).await?).await
}

pub async fn carried_among(
    state: &State,
    apps: &[String],
) -> Result<(Vec<Carried>, Vec<(String, String)>)> {
    let mut out = Vec::new();
    let mut nightly = Vec::new();
    for app in apps {
        let recorded: Vec<String> = state
            .volumes_to_backup(app)
            .await?
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        let (pushed, alone) =
            hlb_engine::lifeboat::pushed_volumes(app, &state.app_manifest(app).await?);
        for p in pushed {
            if recorded.contains(&p.volume) {
                out.push(Carried {
                    app: app.clone(),
                    pushed: p,
                });
            }
        }
        nightly.extend(alone);
    }
    Ok((out, nightly))
}

/// The vault's entry for `volume`'s pushing key. A stored name.
fn key_secret(volume: &str) -> String {
    format!("site-volume-key-{volume}")
}

/// `volume`'s pushing key, made once.
async fn key(state: &State, vault: &Vault, volume: &str) -> Result<hlb_bootstrap::access::KeyPair> {
    let name = key_secret(volume);
    if let Some(ct) = state.secret(&name).await? {
        let v: serde_json::Value = serde_json::from_str(&vault.decrypt(&ct)?)?;
        return Ok(hlb_bootstrap::access::KeyPair {
            private: v["private"].as_str().unwrap_or_default().to_string(),
            public: v["public"].as_str().unwrap_or_default().to_string(),
        });
    }
    let kp = hlb_bootstrap::access::generate_keypair("hlb-volume").await?;
    let json = serde_json::json!({ "private": kp.private, "public": kp.public });
    state
        .store_secret_if_absent(
            &name,
            &vault.encrypt(&json.to_string())?,
            "the key pushing a vital app's volume to the site, its own directory only",
        )
        .await?;
    Box::pin(key(state, vault, volume)).await
}

/// The pusher, as the house runs it: on the volume's node, the volume read-only, as
/// root with nothing but the right to read every file of it — an app's 0700 directory
/// included.
fn pusher(
    c: &Carried,
    user: &str,
    env: Vec<(String, String)>,
    private: &str,
    network: &str,
) -> ServiceSpec {
    let mut spec = ServiceSpec::new(user, images::RCLONE)
        .network(network)
        .constraint(format!(
            "node.labels.{}==true",
            hlb_types::manifest::data_label(&c.pushed.service)
        ))
        .mount_read_only(c.pushed.volume.clone(), volume_ship::MOUNTED_AT)
        .file(volume_ship::KEY, private)
        .env(env);
    spec.command = vec!["sh".into(), "-c".into(), volume_ship::push_script()];
    spec.hardening.cap_add = vec!["DAC_READ_SEARCH".into()];
    spec.hardening.tmpfs = vec![volume_ship::SCRATCH.into()];
    spec.memory = Some(hlb_types::manifest::Memory {
        reserve: hlb_types::manifest::Bytes(16 << 20),
        limit: hlb_types::manifest::Bytes(128 << 20),
    });
    spec
}

/// Every host key the site has, as rclone pins them.
async fn host_keys(ssh: &dyn Runner) -> Result<Vec<String>> {
    let mut files = Vec::new();
    for path in hlb_backup::sftp_account::HOST_KEYS {
        files.push(ssh.read_file(path).await?);
    }
    let keys = volume_ship::host_keys(&files);
    if keys.is_empty() {
        return Err("the site has no SSH host key to pin".into());
    }
    Ok(keys)
}

/// The site's accounts set up and every pusher deployed. Whether all went.
pub async fn ship(cli: &Cli, state: &State, vault: &Vault, apply: bool) -> Result<bool> {
    let Some(s) = super::load(state, vault).await? else {
        return Ok(true);
    };
    let (all, nightly) = carried(state, vault).await?;
    if !apply {
        for c in &all {
            println!(
                "  volume  : {}'s {} pushed to {} every minute, what changed only, by {}",
                c.app,
                c.pushed.volume,
                s.name,
                c.user()?
            );
        }
        if !all.is_empty() {
            println!("            beside it, into a directory of the site its own account reaches");
        }
        for (v, why) in &nightly {
            println!("  volume  : {v} carried by the nightly copy alone: {why}");
        }
        return Ok(true);
    }
    for (v, why) in &nightly {
        println!("  ⚠️  {v} is carried by the nightly copy alone: {why}");
    }
    if all.is_empty() {
        return Ok(true);
    }
    println!("\nThe vital volumes, pushed to {}:", s.name);
    let (_tmp, ssh) = super::lifeboat::ssh_to(state, vault, &s).await?;
    let keys = host_keys(&ssh).await?;
    let (host, _, port) = parse_ssh_target(&s.ssh);
    let target = wal_ship::Target {
        user: String::new(),
        host,
        port: port.unwrap_or(22),
    };
    let house = SwarmOrchestrator::connect().await?;
    let mut ok = true;
    for c in &all {
        match ship_one(cli, state, vault, &ssh, &house, c, &target, &keys).await {
            Ok(user) => println!("  ✓ {user} running beside {}", c.pushed.volume),
            Err(e) => {
                ok = false;
                eprintln!("  🔴 {}: {e}", c.pushed.volume);
            }
        }
    }
    Ok(ok)
}

#[allow(clippy::too_many_arguments)]
async fn ship_one(
    cli: &Cli,
    state: &State,
    vault: &Vault,
    ssh: &dyn Runner,
    house: &SwarmOrchestrator,
    c: &Carried,
    target: &wal_ship::Target,
    keys: &[String],
) -> Result<String> {
    let user = c.user()?;
    let kp = key(state, vault, &c.pushed.volume).await?;
    let out = ssh
        .run(&[
            "sh".into(),
            "-c".into(),
            volume_ship::ACCOUNTS.setup_script(&user, &kp.public),
        ])
        .await?;
    if !out.ok() {
        return Err(format!("its account on the site: {}", out.stderr.trim()).into());
    }
    house
        .deploy(&pusher(
            c,
            &user,
            volume_ship::env(target, &user, keys),
            &kp.private,
            &cli.platform_network,
        ))
        .await?;
    house.wait_healthy(&user, 120).await?;
    Ok(user)
}

/// The promotion's steps, `(service, step)`: each pushed volume of `apps` laid over
/// last night's copy before the service holding it starts on the site.
pub async fn promote_steps(state: &State, apps: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for c in carried_among(state, apps).await?.0 {
        out.push((
            c.pushed.service.clone(),
            volume_ship::promote_step(&c.user()?, &c.pushed.volume, images::RCLONE),
        ));
    }
    Ok(out)
}

/// Each pushed volume, judged by `site status`; false on a fault.
pub async fn status(
    state: &State,
    vault: &Vault,
    hub: &dyn Runner,
    promoted: bool,
    now: u64,
) -> Result<bool> {
    use wal_ship::Mark;
    let (all, _) = carried(state, vault).await?;
    if all.is_empty() {
        return Ok(true);
    }
    if promoted {
        println!("  … volumes — the site serves its own: no push to follow");
        return Ok(true);
    }
    let users = all.iter().map(Carried::user).collect::<Result<Vec<_>>>()?;
    let site = hub
        .run(&[
            "sh".into(),
            "-c".into(),
            volume_ship::site_probe_script(&users),
        ])
        .await?
        .stdout;
    let house = SwarmOrchestrator::connect().await?;
    let mut fine = true;
    for (c, user) in all.iter().zip(&users) {
        let running = matches!(house.status(user).await, Ok(s) if s.running_replicas > 0);
        let said = volume_ship::judge(
            &c.pushed.volume,
            volume_ship::parse_probe(&site, user),
            volume_ship::parse_probe(&site, &format!("{user}.bytes")),
            running,
            now,
        );
        let mark = match said.mark {
            Mark::Fine => "✓",
            Mark::Unknown => "⚠️ ",
            Mark::Fault => {
                fine = false;
                "🔴"
            }
        };
        println!("  {mark} {}", said.line);
    }
    Ok(fine)
}

/// Before the return replaces the house's volumes: each pusher stopped, or it would
/// push a volume being replaced.
pub async fn stop(state: &State, vault: &Vault, house: &SwarmOrchestrator) -> Result<()> {
    for c in carried(state, vault).await?.0 {
        let user = c.user()?;
        if house.status(&user).await.is_ok() {
            house.scale(&user, 0).await?;
        }
    }
    Ok(())
}

/// Once the house holds what the site wrote: the site's pushed trees emptied — they
/// follow a volume that is no longer the house's — and each pusher started again,
/// pushing it whole. What failed is said; the next `site sync` deploys them again.
pub async fn resume(state: &State, vault: &Vault, ssh: &dyn Runner, house: &SwarmOrchestrator) {
    let all = match carried(state, vault).await {
        Ok((all, _)) => all,
        Err(e) => {
            eprintln!("⚠️  the volume pushers could not be listed ({e}): hlb site sync --apply");
            return;
        }
    };
    for c in all {
        let Ok(user) = c.user() else { continue };
        let emptied = ssh
            .run(&[
                "sh".into(),
                "-c".into(),
                format!("find {} -mindepth 1 -delete", volume_ship::site_dir(&user)),
            ])
            .await;
        if !matches!(&emptied, Ok(o) if o.ok()) {
            eprintln!(
                "⚠️  {}'s push on the site was not emptied: hlb site sync --apply",
                c.pushed.volume
            );
            continue;
        }
        if let Err(e) = house.scale(&user, 1).await {
            eprintln!("⚠️  {user} did not start again ({e}): hlb site sync --apply");
        }
    }
}

/// The promotion's steps of one service run in one `case` arm: a second arm of the
/// same name is never reached. Each service's steps joined, in the order given — the
/// volume's files first, then the SQLite its replica puts back over them.
pub fn joined(steps: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (svc, step) in steps {
        match out.iter_mut().find(|(s, _)| *s == svc) {
            Some((_, all)) => all.push_str(&step),
            None => out.push((svc, step)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vw() -> Carried {
        Carried {
            app: "vaultwarden".into(),
            pushed: Pushed {
                volume: "vaultwarden-data".into(),
                service: "vaultwarden".into(),
            },
        }
    }

    #[test]
    fn the_pusher_runs_on_the_volume_s_node_reading_it_and_nothing_more() {
        let s = pusher(
            &vw(),
            "hlb-vol-vaultwarden-data",
            vec![],
            "KEY",
            "hlb_platform",
        );
        assert_eq!(s.name, "hlb-vol-vaultwarden-data");
        assert_eq!(
            s.constraints,
            vec!["node.labels.hlb.data.vaultwarden==true"]
        );
        assert_eq!(s.read_only_volumes, vec!["vaultwarden-data".to_string()]);
        assert_eq!(s.hardening.cap_add, vec!["DAC_READ_SEARCH".to_string()]);
        assert!(s.hardening.read_only_rootfs);
        assert_eq!(s.command[..2], ["sh".to_string(), "-c".to_string()]);
        assert!(s.image.starts_with("rclone/rclone:1."));
    }

    #[test]
    fn one_service_s_steps_share_its_one_arm_files_first() {
        let j = joined(vec![
            ("pocket-id".into(), "files\n".into()),
            ("vaultwarden".into(), "vw\n".into()),
            ("pocket-id".into(), "sqlite\n".into()),
        ]);
        assert_eq!(
            j,
            vec![
                ("pocket-id".to_string(), "files\nsqlite\n".to_string()),
                ("vaultwarden".to_string(), "vw\n".to_string()),
            ]
        );
    }
}
