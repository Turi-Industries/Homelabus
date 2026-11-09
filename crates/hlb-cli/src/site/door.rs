//! The front door on the site: its configuration checked by the image that will run it,
//! put in place, then the service created, replaced or reloaded.
//!
//! The configuration is a file in a directory mounted read-only, never a Swarm config:
//! a config is immutable, so every new house node would be a new task, and the door
//! closed for as long as it takes to start. A renamed file and `SIGUSR2` reload it
//! with the connections already open left to finish.

use std::time::Duration;

use hlb_bootstrap::provision;
use hlb_bootstrap::Runner;
use hlb_ingress::front_door::{self, Backend, CONFIG_DIR, IMAGE, MOUNTED_AT, SERVICE};
use hlb_mesh::site::Site;

/// What became of the door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Created,
    /// Its service was made by another revision of this code: removed and made again.
    Replaced,
    Reloaded,
    Unchanged,
}

impl Outcome {
    pub fn says(self) -> &'static str {
        match self {
            Outcome::Created => "opened",
            Outcome::Replaced => "rebuilt to this revision",
            Outcome::Reloaded => "reloaded with the new house nodes",
            Outcome::Unchanged => "already up to date",
        }
    }
}

/// The label carrying the fingerprint of the arguments the service was created with.
/// A stored name: a door made by an older `hlb` reads as another spec, and is rebuilt.
const SPEC_LABEL: &str = "homelabus.front-door.spec";

/// How long a new task may take to run, the image's first pull included.
const START_WITHIN: Duration = Duration::from_secs(90);

fn live() -> String {
    format!("{CONFIG_DIR}/haproxy.cfg")
}

fn staged() -> String {
    format!("{CONFIG_DIR}/haproxy.cfg.new")
}

/// The door's configuration for this site's members.
pub fn config(s: &Site) -> String {
    let backends: Vec<Backend> = s
        .members
        .iter()
        .map(|m| Backend {
            name: m.name.clone(),
            address: m.address,
        })
        .collect();
    front_door::render(&backends)
}

/// The service's arguments after `docker service create`, its label left out.
fn spec() -> Vec<String> {
    let mount = format!("type=bind,src={CONFIG_DIR},dst={MOUNTED_AT},readonly");
    [
        "--name",
        SERVICE,
        // Host mode, or the routing mesh hands HAProxy the ingress network's address
        // and every visitor's PROXY header says the VPS.
        "--publish",
        "mode=host,target=80,published=80",
        "--publish",
        "mode=host,target=443,published=443",
        "--mount",
        &mount,
        "--read-only",
        "--cap-drop",
        "ALL",
        // Two tasks cannot hold one host port: the old one stops first.
        "--update-order",
        "stop-first",
        "--detach",
        "--quiet",
        IMAGE,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn fingerprint() -> String {
    hlb_types::token::sha256_hex(spec().join("\0").as_bytes())[..16].to_string()
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

async fn run(hub: &dyn Runner, what: &str, cmd: Vec<String>) -> Result<String, String> {
    let out = hub.run(&cmd).await.map_err(|e| format!("{what}: {e}"))?;
    if out.ok() {
        Ok(out.stdout)
    } else {
        Err(format!("{what}: {}", out.stderr.trim()))
    }
}

/// Puts the door in place on the site, or brings it up to date.
///
/// 🔴 A configuration the image refuses never replaces the running one: checked staged,
/// by the same binary, before the rename.
pub async fn deploy(hub: &dyn Runner, s: &Site) -> Result<Outcome, String> {
    if s.members.is_empty() {
        return Err("no house node is linked: the door would lead nowhere".into());
    }
    let cfg = config(s);
    let changed = hub
        .read_file(&live())
        .await
        .map_err(|e| e.to_string())?
        .as_deref()
        != Some(cfg.as_str());
    if changed {
        // No secret in it, and HAProxy reads it as its own unprivileged user.
        provision::install_file(hub, &staged(), &cfg, 0o644)
            .await
            .map_err(|e| e.to_string())?;
        run(
            hub,
            "opening its directory to HAProxy's user",
            argv(&["chmod", "755", CONFIG_DIR]),
        )
        .await?;
        let src = format!("type=bind,src={CONFIG_DIR},dst={MOUNTED_AT},readonly");
        let file = format!("{MOUNTED_AT}/haproxy.cfg.new");
        run(
            hub,
            "HAProxy refuses its configuration",
            argv(&[
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--mount",
                &src,
                IMAGE,
                "haproxy",
                "-c",
                "-f",
                &file,
            ]),
        )
        .await?;
        run(
            hub,
            "putting the configuration in place",
            argv(&["mv", "-f", &staged(), &live()]),
        )
        .await?;
    }

    let label = format!("{{{{index .Spec.Labels \"{SPEC_LABEL}\"}}}}");
    let inspected = hub
        .run(&argv(&[
            "docker", "service", "inspect", "--format", &label, SERVICE,
        ]))
        .await
        .map_err(|e| e.to_string())?;
    let want = fingerprint();
    let outcome = if !inspected.ok() {
        Outcome::Created
    } else if inspected.stdout.trim() != want {
        // `service update` cannot drop a flag an older spec had: made again whole.
        run(
            hub,
            "removing the door of an older revision",
            argv(&["docker", "service", "rm", SERVICE]),
        )
        .await?;
        Outcome::Replaced
    } else if changed {
        reload(hub).await?;
        return Ok(Outcome::Reloaded);
    } else {
        return Ok(Outcome::Unchanged);
    };

    let mut create = argv(&["docker", "service", "create", "--label"]);
    create.push(format!("{SPEC_LABEL}={want}"));
    create.extend(spec());
    // A replaced service's ports are released while its task stops: tried again then.
    let tries = if outcome == Outcome::Replaced { 10 } else { 1 };
    for left in (0..tries).rev() {
        match run(hub, "creating the door's service", create.clone()).await {
            Ok(_) => break,
            Err(e) if left == 0 => return Err(e),
            Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
    running(hub).await?;
    Ok(outcome)
}

/// `SIGUSR2` to the master: it starts workers on the new file and lets the old ones
/// finish their connections.
async fn reload(hub: &dyn Runner) -> Result<(), String> {
    let filter = format!("label=com.docker.swarm.service.name={SERVICE}");
    let ids = run(
        hub,
        "finding the door's container",
        argv(&["docker", "ps", "-q", "--filter", &filter]),
    )
    .await?;
    let ids: Vec<&str> = ids.split_whitespace().collect();
    if ids.is_empty() {
        return Err(format!(
            "no task of {SERVICE} runs to reload: `docker service ps {SERVICE}` says why"
        ));
    }
    for id in ids {
        run(
            hub,
            "reloading HAProxy",
            argv(&["docker", "kill", "-s", "USR2", id]),
        )
        .await?;
    }
    Ok(())
}

/// Waits for the door's task to run, and says why it does not — port 80 already taken
/// by a web server the provider installed is the likely one.
async fn running(hub: &dyn Runner) -> Result<(), String> {
    let started = std::time::Instant::now();
    loop {
        let states = run(
            hub,
            "reading the door's task",
            argv(&[
                "docker",
                "service",
                "ps",
                "--no-trunc",
                "--format",
                "{{.CurrentState}}\t{{.Error}}",
                SERVICE,
            ]),
        )
        .await?;
        // Newest first: the task Swarm is on now.
        let newest = states.lines().next().unwrap_or_default();
        if newest.starts_with("Running") {
            return Ok(());
        }
        if started.elapsed() >= START_WITHIN {
            let (state, error) = newest.split_once('\t').unwrap_or((newest, ""));
            return Err(format!(
                "its task does not run ({}){}",
                state.trim(),
                if error.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", error.trim())
                }
            ));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use hlb_bootstrap::runner::{Output, Result as RunResult};
    use hlb_mesh::site::Member;

    /// A VPS: files in a map, every command recorded, answers chosen by prefix.
    #[derive(Default)]
    struct Vps {
        files: Mutex<BTreeMap<String, String>>,
        ran: Mutex<Vec<String>>,
        /// The label the service carries; `None` when there is no service.
        service: Option<String>,
        check_refuses: bool,
    }

    impl Vps {
        fn ran(&self) -> Vec<String> {
            self.ran.lock().expect("lock").clone()
        }
        fn ran_any(&self, prefix: &str) -> bool {
            self.ran().iter().any(|c| c.starts_with(prefix))
        }
    }

    #[async_trait::async_trait]
    impl Runner for Vps {
        async fn run(&self, argv: &[String]) -> RunResult<Output> {
            let line = argv.join(" ");
            self.ran.lock().expect("lock").push(line.clone());
            let (status, stdout) = if line.starts_with("docker service inspect") {
                match &self.service {
                    Some(l) => (0, format!("{l}\n")),
                    None => (1, String::new()),
                }
            } else if line.starts_with("docker run") && self.check_refuses {
                (1, String::new())
            } else if line.starts_with("docker ps") {
                (0, "abc123\n".into())
            } else if line.starts_with("docker service ps") {
                (0, "Running 2 seconds ago\t\n".into())
            } else if line.starts_with("mv -f") {
                let mut f = self.files.lock().expect("lock");
                if let Some(c) = f.remove(&argv[2]) {
                    f.insert(argv[3].clone(), c);
                }
                (0, String::new())
            } else {
                (0, String::new())
            };
            Ok(Output {
                status,
                stdout,
                stderr: if status == 0 {
                    String::new()
                } else {
                    "refused".into()
                },
            })
        }
        async fn read_file(&self, path: &str) -> RunResult<Option<String>> {
            Ok(self.files.lock().expect("lock").get(path).cloned())
        }
        async fn write_file(&self, path: &str, content: &str) -> RunResult<()> {
            self.files
                .lock()
                .expect("lock")
                .insert(path.into(), content.into());
            Ok(())
        }
        fn label(&self) -> String {
            "vps".into()
        }
    }

    /// The rename over the live file, not the one staging it.
    fn put_in_place() -> String {
        format!("mv -f {} {}", staged(), live())
    }

    fn site(members: &[(&str, u8)]) -> Site {
        Site {
            name: "vps".into(),
            endpoint: "203.0.113.7".into(),
            ssh: "root@203.0.113.7:22".into(),
            public_key: "hub=".into(),
            memory_mb: None,
            free_disk_mb: None,
            members: members
                .iter()
                .map(|(n, last)| Member {
                    name: n.to_string(),
                    address: Ipv4Addr::new(10, 43, 0, *last),
                    public_key: format!("{n}="),
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn a_new_door_is_checked_put_in_place_then_created() {
        let vps = Vps::default();
        let s = site(&[("deb1", 2)]);
        assert_eq!(deploy(&vps, &s).await, Ok(Outcome::Created));
        let ran = vps.ran();
        let at = |p: &str| ran.iter().position(|c| c.starts_with(p)).expect(p);
        let into_place = put_in_place();
        assert!(at("docker run --rm") < at(&into_place), "{ran:#?}");
        assert!(at(&into_place) < at("docker service create"), "{ran:#?}");
        let create = &ran[at("docker service create")];
        for want in [
            "mode=host,target=443,published=443",
            "--read-only",
            "--cap-drop ALL",
            IMAGE,
            &format!("{SPEC_LABEL}={}", fingerprint()),
        ] {
            assert!(create.contains(want), "{want} missing: {create}");
        }
        assert_eq!(
            vps.files.lock().expect("lock").get(&live()),
            Some(&config(&s))
        );
    }

    #[tokio::test]
    async fn a_refused_configuration_never_replaces_the_running_one() {
        let vps = Vps {
            service: Some(fingerprint()),
            check_refuses: true,
            ..Vps::default()
        };
        let old = config(&site(&[("deb1", 2)]));
        vps.files.lock().expect("lock").insert(live(), old.clone());
        let r = deploy(&vps, &site(&[("deb1", 2), ("deb2", 3)])).await;
        assert!(r.is_err(), "{r:?}");
        assert!(!vps.ran_any(&put_in_place()), "{:#?}", vps.ran());
        assert!(!vps.ran_any("docker kill"), "{:#?}", vps.ran());
        assert_eq!(vps.files.lock().expect("lock").get(&live()), Some(&old));
    }

    #[tokio::test]
    async fn a_new_house_node_reloads_the_door_without_a_new_task() {
        let vps = Vps {
            service: Some(fingerprint()),
            ..Vps::default()
        };
        vps.files
            .lock()
            .expect("lock")
            .insert(live(), config(&site(&[("deb1", 2)])));
        let r = deploy(&vps, &site(&[("deb1", 2), ("deb2", 3)])).await;
        assert_eq!(r, Ok(Outcome::Reloaded));
        assert!(
            vps.ran_any("docker kill -s USR2 abc123"),
            "{:#?}",
            vps.ran()
        );
        assert!(!vps.ran_any("docker service create"), "{:#?}", vps.ran());
        assert!(!vps.ran_any("docker service rm"), "{:#?}", vps.ran());
    }

    #[tokio::test]
    async fn a_door_up_to_date_is_left_alone() {
        let s = site(&[("deb1", 2)]);
        let vps = Vps {
            service: Some(fingerprint()),
            ..Vps::default()
        };
        vps.files.lock().expect("lock").insert(live(), config(&s));
        assert_eq!(deploy(&vps, &s).await, Ok(Outcome::Unchanged));
        let ran = vps.ran();
        assert_eq!(ran.len(), 1, "only the inspection: {ran:#?}");
    }

    #[tokio::test]
    async fn a_door_of_another_revision_is_made_again() {
        let s = site(&[("deb1", 2)]);
        let vps = Vps {
            service: Some("older".into()),
            ..Vps::default()
        };
        vps.files.lock().expect("lock").insert(live(), config(&s));
        assert_eq!(deploy(&vps, &s).await, Ok(Outcome::Replaced));
        assert!(vps.ran_any("docker service rm hlb-front-door"));
        assert!(vps.ran_any("docker service create"));
    }

    #[tokio::test]
    async fn a_site_with_no_house_node_opens_no_door() {
        let vps = Vps::default();
        assert!(deploy(&vps, &site(&[])).await.is_err());
        assert!(vps.ran().is_empty());
    }
}
