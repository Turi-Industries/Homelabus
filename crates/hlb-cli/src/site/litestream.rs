//! The vital apps' SQLite pushed to the site as it is written (`hlb_backup::sqlite_ship`):
//! the site's account set up, Litestream deployed beside each app at home, its replica
//! judged by `site status`, put in place by the promotion and emptied by the return.
//!
//! Each app holds a key of its own, never Homelabus's: the site lets it write over SFTP
//! into the app's own directory, and nothing else.

use hlb_backup::{images, sqlite_ship, wal_ship};
use hlb_bootstrap::Runner;
use hlb_orchestrator::{Orchestrator as _, ServiceSpec, SwarmOrchestrator};
use hlb_secrets::Vault;
use hlb_state::State;

use crate::{parse_ssh_target, Cli};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A vital app's volume holding SQLite, as the house records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carried {
    pub app: String,
    pub volume: String,
    /// Where the app mounts it.
    pub mount: String,
}

impl Carried {
    /// Its pusher's service at home, and its account on the site: one name.
    pub fn user(&self) -> Result<String> {
        Ok(sqlite_ship::user(&self.app)?)
    }
}

/// Every backed-up SQLite volume of the apps the lifeboat carries. Which volumes hold
/// SQLite is the state's word — the manifest's flag and what a pass found by header.
pub async fn carried(state: &State, vault: &Vault) -> Result<Vec<Carried>> {
    carried_among(state, &super::lifeboat::apps(state, vault).await?).await
}

/// Every backed-up SQLite volume of `apps`.
pub async fn carried_among(state: &State, apps: &[String]) -> Result<Vec<Carried>> {
    Ok(state
        .sqlite_volumes()
        .await?
        .into_iter()
        .filter(|(app, _, _)| apps.contains(app))
        .map(|(app, volume, mount)| Carried { app, volume, mount })
        .collect())
}

/// The databases `c`'s volume holds and their owner, asked of the app's running service.
pub async fn discover(
    house: &SwarmOrchestrator,
    c: &Carried,
) -> std::result::Result<(String, Vec<String>), String> {
    let out = house
        .exec_in_service(
            &c.app,
            &[
                "sh".into(),
                "-c".into(),
                sqlite_ship::discover_script(&c.mount),
            ],
        )
        .await
        .map_err(|e| format!("{}'s databases could not be read: {e}", c.app))?;
    if !out.ok() {
        return Err(format!(
            "{}'s databases could not be read: {}",
            c.app,
            out.stderr.trim()
        ));
    }
    sqlite_ship::parse_discovered(&out.stdout)
        .map_err(|e| format!("{} ({}): {e}", c.app, c.volume))?
        .ok_or_else(|| format!("{} holds no SQLite database in {}", c.app, c.mount))
}

/// The vault's entry for `app`'s pushing key. A stored name.
fn key_secret(app: &str) -> String {
    format!("site-litestream-key-{app}")
}

/// `app`'s pushing key, made once.
async fn key(state: &State, vault: &Vault, app: &str) -> Result<hlb_bootstrap::access::KeyPair> {
    let name = key_secret(app);
    if let Some(ct) = state.secret(&name).await? {
        let v: serde_json::Value = serde_json::from_str(&vault.decrypt(&ct)?)?;
        return Ok(hlb_bootstrap::access::KeyPair {
            private: v["private"].as_str().unwrap_or_default().to_string(),
            public: v["public"].as_str().unwrap_or_default().to_string(),
        });
    }
    let kp = hlb_bootstrap::access::generate_keypair("hlb-litestream").await?;
    let json = serde_json::json!({ "private": kp.private, "public": kp.public });
    state
        .store_secret_if_absent(
            &name,
            &vault.encrypt(&json.to_string())?,
            "the key pushing a vital app's SQLite to the site, its own directory only",
        )
        .await?;
    Box::pin(key(state, vault, app)).await
}

/// The pusher, as the house runs it: on the app's data node, its volume mounted, as the
/// user owning the databases — what Litestream opens it creates as that user, and the
/// app must still open it.
fn pusher(
    c: &Carried,
    user: &str,
    owner: &str,
    config: &str,
    private: &str,
    network: &str,
) -> ServiceSpec {
    let mut spec = ServiceSpec::new(user, images::LITESTREAM)
        .network(network)
        .constraint(format!(
            "node.labels.{}==true",
            hlb_types::manifest::data_label(&c.app)
        ))
        .mount(c.volume.clone(), sqlite_ship::MOUNTED_AT)
        .file(sqlite_ship::CONFIG, config)
        .file(sqlite_ship::KEY, private);
    spec.args = vec![
        "replicate".into(),
        "-config".into(),
        sqlite_ship::CONFIG.into(),
    ];
    spec.hardening.user = Some(owner.to_string());
    spec.hardening.tmpfs = vec![sqlite_ship::META.into()];
    // 18 MiB idle beside a small database (measured).
    spec.memory = Some(hlb_types::manifest::Memory {
        reserve: hlb_types::manifest::Bytes(16 << 20),
        limit: hlb_types::manifest::Bytes(64 << 20),
    });
    spec
}

/// The host key Litestream is shown by the site, read off it.
pub async fn host_key(ssh: &dyn Runner) -> Result<String> {
    let mut keys = Vec::new();
    for path in sqlite_ship::HOST_KEYS {
        keys.push(ssh.read_file(path).await?);
    }
    Ok(
        sqlite_ship::pinned_host_key(keys[0].as_deref(), keys[1].as_deref(), keys[2].as_deref())
            .ok_or("the site has no SSH host key to pin")?
            .to_string(),
    )
}

/// The site's accounts set up and every pusher deployed. Whether all went.
pub async fn ship(cli: &Cli, state: &State, vault: &Vault, apply: bool) -> Result<bool> {
    let Some(s) = super::load(state, vault).await? else {
        return Ok(true);
    };
    let all = carried(state, vault).await?;
    if all.is_empty() {
        return Ok(true);
    }
    if !apply {
        for c in &all {
            println!(
                "  SQLite  : {}'s ({}) pushed to {} as it is written, by {} beside it,",
                c.app,
                c.volume,
                s.name,
                c.user()?
            );
        }
        println!(
            "            into a directory of the site its own account reaches, over SFTP only"
        );
        return Ok(true);
    }
    println!("\nThe vital SQLite databases, pushed to {}:", s.name);
    let (_tmp, ssh) = super::lifeboat::ssh_to(state, vault, &s).await?;
    let host_key = host_key(&ssh).await?;
    let (host, _, port) = parse_ssh_target(&s.ssh);
    let target = wal_ship::Target {
        user: String::new(),
        host,
        port: port.unwrap_or(22),
    };
    let house = SwarmOrchestrator::connect().await?;
    let mut ok = true;
    for c in &all {
        match ship_one(cli, state, vault, &ssh, &house, c, &target, &host_key).await {
            Ok(dbs) => println!(
                "  ✓ {} running beside {}: {}",
                c.user()?,
                c.app,
                dbs.join(", ")
            ),
            Err(e) => {
                ok = false;
                eprintln!("  🔴 {}: {e}", c.app);
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
    host_key: &str,
) -> Result<Vec<String>> {
    let user = c.user()?;
    let (owner, dbs) = discover(house, c).await?;
    let kp = key(state, vault, &c.app).await?;
    let out = ssh
        .run(&[
            "sh".into(),
            "-c".into(),
            sqlite_ship::site_setup_script(&user, &kp.public),
        ])
        .await?;
    if !out.ok() {
        return Err(format!("its account on the site: {}", out.stderr.trim()).into());
    }
    let config = sqlite_ship::config(&dbs, target, &user, host_key);
    house
        .deploy(&pusher(
            c,
            &user,
            &owner,
            &config,
            &kp.private,
            &cli.platform_network,
        ))
        .await?;
    house.wait_healthy(&user, 120).await?;
    Ok(dbs)
}

/// The promotion's steps, `(service, step)`: each database of `apps` put back from its
/// replica before its app starts on the site. What could not be read is said and left
/// to last night's copy.
pub async fn promote_steps(state: &State, apps: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let house = SwarmOrchestrator::connect().await?;
    for c in carried_among(state, apps).await? {
        match discover(&house, &c).await {
            Ok((_, dbs)) => out.push((
                c.app.clone(),
                sqlite_ship::promote_step(&c.user()?, &c.volume, &dbs, images::LITESTREAM),
            )),
            Err(e) => eprintln!("  ⚠️  {e}: the promotion will start it on last night's copy"),
        }
    }
    Ok(out)
}

/// Each carried database's replica, judged by `site status`; false on a fault.
pub async fn status(
    state: &State,
    vault: &Vault,
    hub: &dyn Runner,
    promoted: bool,
    now: u64,
) -> Result<bool> {
    use wal_ship::Mark;
    let all = carried(state, vault).await?;
    if all.is_empty() {
        return Ok(true);
    }
    if promoted {
        println!("  … SQLite — the site serves its own: no replica to follow");
        return Ok(true);
    }
    let house = SwarmOrchestrator::connect().await?;
    let mut fine = true;
    for c in &all {
        let user = c.user()?;
        let dbs = match discover(&house, c).await {
            Ok((_, dbs)) => dbs,
            Err(e) => {
                println!("  ⚠️  SQLite — {e}");
                continue;
            }
        };
        let at_home = house
            .exec_in_service(
                &user,
                &[
                    "sh".into(),
                    "-c".into(),
                    sqlite_ship::house_probe_script(&dbs),
                ],
            )
            .await;
        let at_home = match at_home {
            Ok(o) if o.ok() => Some(o.stdout),
            _ => {
                fine = false;
                println!(
                    "  🔴 SQLite — {user} does not run at home: {}'s writes stay there \
                     (hlb site sync --apply)",
                    c.app
                );
                None
            }
        };
        let site = hub
            .run(&[
                "sh".into(),
                "-c".into(),
                sqlite_ship::site_probe_script(&user, &dbs),
            ])
            .await?
            .stdout;
        for db in &dbs {
            let said = sqlite_ship::judge(
                db,
                at_home
                    .as_deref()
                    .and_then(|o| sqlite_ship::parse_site_newest(o, db)),
                sqlite_ship::parse_site_newest(&site, db),
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
    }
    Ok(fine)
}

/// Before the return replaces the house's copy: each pusher stopped, or it would push
/// the database being replaced.
pub async fn stop(state: &State, vault: &Vault, house: &SwarmOrchestrator) -> Result<()> {
    for c in carried(state, vault).await? {
        let user = c.user()?;
        if house.status(&user).await.is_ok() {
            house.scale(&user, 0).await?;
        }
    }
    Ok(())
}

/// Once the house holds what the site wrote: the site's replicas emptied — they follow
/// a database that is no longer the house's — and each pusher started again, pushing it
/// whole. What failed is said; the next `site sync` deploys them again.
pub async fn resume(state: &State, vault: &Vault, ssh: &dyn Runner, house: &SwarmOrchestrator) {
    let all = match carried(state, vault).await {
        Ok(all) => all,
        Err(e) => {
            eprintln!("⚠️  the SQLite pushers could not be listed ({e}): hlb site sync --apply");
            return;
        }
    };
    for c in all {
        let Ok(user) = c.user() else { continue };
        let emptied = ssh
            .run(&[
                "sh".into(),
                "-c".into(),
                format!(
                    "find {} -mindepth 1 -delete",
                    sqlite_ship::site_replica(&user)
                ),
            ])
            .await;
        if !matches!(&emptied, Ok(o) if o.ok()) {
            eprintln!(
                "⚠️  {}'s replica on the site was not emptied: hlb site sync --apply",
                c.app
            );
            continue;
        }
        if let Err(e) = house.scale(&user, 1).await {
            eprintln!("⚠️  {user} did not start again ({e}): hlb site sync --apply");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pusher_runs_on_the_app_s_node_as_its_user_with_no_capability() {
        let c = Carried {
            app: "pocket-id".into(),
            volume: "pocket-id-data".into(),
            mount: "/app/data".into(),
        };
        let s = pusher(
            &c,
            "hlb-ls-pocket-id",
            "1000:1000",
            "dbs: []\n",
            "KEY",
            "hlb_platform",
        );
        assert_eq!(s.name, "hlb-ls-pocket-id");
        assert_eq!(s.constraints, vec!["node.labels.hlb.data.pocket-id==true"]);
        assert_eq!(
            s.mounts,
            vec![("pocket-id-data".to_string(), "/data".to_string())]
        );
        assert_eq!(s.hardening.user.as_deref(), Some("1000:1000"));
        assert!(s.hardening.cap_add.is_empty());
        assert!(s.hardening.read_only_rootfs);
        assert_eq!(s.args, vec!["replicate", "-config", "/etc/litestream.yml"]);
        assert!(s.image.starts_with("litestream/litestream:0.5"));
    }
}
