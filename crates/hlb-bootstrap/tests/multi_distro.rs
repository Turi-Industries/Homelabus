//! The "any server distribution" promise, checked.
//!
//! This test is what makes that promise credible. Without it, "it works on any distro"
//! is an assumption.
//!
//! Containers are used rather than VMs: they are enough to validate detection, the
//! choice of package manager and a real installation. What they do not validate -
//! systemd, cgroups, the network - is out of this module's scope anyway.
//!
//! ```sh
//! export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
//! cargo test -p hlb-bootstrap --test multi_distro -- --ignored --test-threads=1 --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_bootstrap::runner::{Output, Result, Runner};
use hlb_bootstrap::{observe, Family};

/// Runs inside a container, as `SshRunner` would on a remote node.
struct DockerRunner {
    container: String,
}

#[async_trait::async_trait]
impl Runner for DockerRunner {
    async fn run(&self, argv: &[String]) -> Result<Output> {
        let mut args = vec!["exec".to_string(), self.container.clone()];
        args.extend(argv.iter().cloned());

        let out = tokio::process::Command::new("docker")
            .args(&args)
            .output()
            .await
            .expect("docker reachable (DOCKER_HOST ?)");

        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }

    async fn read_file(&self, path: &str) -> Result<Option<String>> {
        let o = self.run(&["cat".into(), path.into()]).await?;
        Ok(o.ok().then_some(o.stdout))
    }

    async fn write_file(&self, path: &str, content: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let mut child = tokio::process::Command::new("docker")
            .args(["exec", "-i", &self.container, "sh", "-c"])
            .arg(format!("umask 077 && cat > '{path}'"))
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("docker reachable");
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(content.as_bytes()).await.expect("write");
        drop(stdin);
        assert!(
            child.wait().await.expect("wait").success(),
            "writing {path}"
        );
        Ok(())
    }

    fn label(&self) -> String {
        self.container.clone()
    }
}

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

/// Is the image already present locally?
///
/// A `docker pull` of several hundred megabytes in the middle of a test makes its
/// failure unreadable: better to skip cleanly and say so.
fn image_present(image: &str) -> bool {
    docker(&["image", "inspect", image]).status.success()
}

fn start(name: &str, image: &str) -> DockerRunner {
    let _ = docker(&["rm", "-f", name]);
    let out = docker(&["run", "-d", "--name", name, image, "sleep", "600"]);
    assert!(
        out.status.success(),
        "starting {image}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    DockerRunner {
        container: name.into(),
    }
}

fn stop(name: &str) {
    let _ = docker(&["rm", "-f", name]);
}

/// Every family is detected, with the right package manager.
#[tokio::test]
#[ignore = "needs Docker"]
async fn every_supported_family_is_detected() {
    // The images are assumed already present: a `docker pull` of several hundred
    // megabytes in the middle of a test makes its failure unreadable.
    let cases = [
        ("hlb-d-debian", "debian:12", Family::Debian),
        ("hlb-d-ubuntu", "ubuntu:24.04", Family::Debian),
        ("hlb-d-alpine", "alpine:3", Family::Alpine),
        ("hlb-d-rocky", "rockylinux/rockylinux:9", Family::RedHat),
        ("hlb-d-arch", "archlinux:base", Family::Arch),
    ];

    let mut covered = Vec::new();
    let mut ignored = Vec::new();

    for (name, image, expected) in cases {
        if !image_present(image) {
            ignored.push(image);
            continue;
        }
        let r = start(name, image);
        let obs = observe(&r).await.expect("observation");
        let report = hlb_bootstrap::preflight::run(&obs);

        let d = report
            .distro
            .unwrap_or_else(|| panic!("{image}: distribution not identified"));

        assert_eq!(d.family, expected, "{image} misclassified");
        println!(
            "✓ {image:<28} → {} ({:?})",
            d.pretty_name,
            d.package_manager()
        );
        covered.push(image);
        stop(name);
    }

    if !ignored.is_empty() {
        println!("⚠️  not checked for lack of a local image: {ignored:?}");
        println!("    (no download is triggered: `docker pull` stays in your hands)");
    }

    // A missing image is an environment limitation, not a code defect. But passing as
    // green without having checked anything at all is refused.
    assert!(
        !covered.is_empty(),
        "no distribution image available locally - this test proved nothing"
    );
    println!(
        "{} {} checked: {covered:?}",
        covered.len(),
        if covered.len() == 1 {
            "family"
        } else {
            "families"
        }
    );
}

/// A recent distribution must pass the preflight checks, apart from what does not
/// apply to a container.
#[tokio::test]
#[ignore = "needs Docker"]
async fn preflight_only_blocks_on_real_problems() {
    let r = start("hlb-pf-debian", "debian:12");
    let obs = observe(&r).await.expect("observation");
    let report = hlb_bootstrap::preflight::run(&obs);

    // Inside a container Docker is absent: that is normal, and must NOT block.
    assert!(
        report.can_proceed(),
        "blockers inattendus : {:?}",
        report.blocking().iter().map(|c| c.name).collect::<Vec<_>>()
    );

    // The container runs as root, so privileges pass.
    assert!(obs.is_root);
    // And memory is indeed read from /proc.
    assert!(obs.total_memory_mb.unwrap_or(0) > 0);
    println!(
        "✓ preflight: {} MB of RAM, nothing blocking",
        obs.total_memory_mb.unwrap_or(0)
    );

    stop("hlb-pf-debian");
}

/// 🔴 The test that proves the promise: really installing a package, on three families
/// with different package managers.
#[tokio::test]
#[ignore = "needs Docker"]
async fn a_package_is_actually_installed_on_each_family() {
    let cases = [
        ("hlb-i-debian", "debian:12"),
        ("hlb-i-alpine", "alpine:3"),
        ("hlb-i-rocky", "rockylinux/rockylinux:9"),
    ];

    let mut covered = 0;
    for (name, image) in cases {
        if !image_present(image) {
            println!("⚠️  {image} absent locally - not checked");
            continue;
        }
        let r = start(name, image);
        let obs = observe(&r).await.expect("observation");
        let d = hlb_bootstrap::preflight::run(&obs)
            .distro
            .unwrap_or_else(|| panic!("{image} not identified"));
        let pm = d.package_manager();

        // `ca-certificates` exists on every family and installs quickly.
        if let Some(refresh) = pm.refresh_command() {
            let o = r.run(&refresh).await.expect("refresh");
            assert!(o.ok(), "{image}: refresh failed → {}", o.stderr);
        }

        let o = r
            .run(&pm.install_command(&["ca-certificates"]))
            .await
            .expect("installation");
        assert!(
            o.ok(),
            "{image}: installation failed → {}",
            o.stderr.lines().take(3).collect::<Vec<_>>().join(" | ")
        );

        // And the package is checked to be really present, not just that the command
        // returned 0.
        let q = r
            .run(&pm.query_command("ca-certificates"))
            .await
            .expect("interrogation");
        assert!(q.ok(), "{image}: package absent after installation");

        println!("✓ {image:<28} {:?} installed and confirmed the package", pm);
        covered += 1;
        stop(name);
    }

    assert!(
        covered >= 1,
        "no image available locally - this test proved nothing"
    );
    println!(
        "{covered} package {} checked against a real installation",
        if covered == 1 { "manager" } else { "managers" }
    );
}

/// Installation commands must never wait for input.
#[tokio::test]
#[ignore = "needs Docker"]
async fn installation_never_waits_for_input() {
    // Without `-y`, apt asks a question and would hang here until the test times out.
    let r = start("hlb-noint-debian", "debian:12");
    let d = hlb_bootstrap::preflight::run(&observe(&r).await.expect("obs"))
        .distro
        .expect("distro");

    let refresh = d.package_manager().refresh_command().expect("apt refresh");
    r.run(&refresh).await.expect("refresh");

    // `stdin` is closed by `docker exec` without `-i`: if the command asked a
    // question, it would fail rather than succeed.
    let o = r
        .run(&d.package_manager().install_command(&["curl"]))
        .await
        .expect("installation");

    assert!(o.ok(), "installation interactive ? → {}", o.stderr);
    println!("✓ non-interactive installation confirmed");

    stop("hlb-noint-debian");
}

/// 🔴 The whole provisioning plan, run for real: Docker's repository with its
/// compiled-in key, Docker's packages, the dependencies, unattended updates — then every
/// dependency observed again, by the same probes the plan is built from.
///
/// Debian 12 is the case that matters most: its own `docker.io` is 20.10, below the
/// floor, so the node only works if Docker's repository really is used.
///
/// Services are left out: a container has no init to start them.
#[tokio::test]
#[ignore = "needs Docker and network access"]
async fn the_provisioning_plan_turns_a_bare_image_into_a_node() {
    use hlb_bootstrap::provision::{self, Phase};

    let cases = [
        ("hlb-p-debian", "debian:12"),
        ("hlb-p-ubuntu", "ubuntu:24.04"),
        ("hlb-p-rocky", "rockylinux/rockylinux:9"),
        ("hlb-p-alpine", "alpine:3"),
        ("hlb-p-arch", "archlinux:base"),
    ];

    let mut covered = Vec::new();
    for (name, image) in cases {
        if !image_present(image) {
            println!("⚠️  {image} absent locally - not checked");
            continue;
        }
        let r = start(name, image);
        let obs = observe(&r).await.expect("observation");
        let d = hlb_bootstrap::preflight::run(&obs)
            .distro
            .unwrap_or_else(|| panic!("{image} not identified"));

        let seen = hlb_bootstrap::observe::dependencies(&r, &d)
            .await
            .expect("dependencies");
        let deps = hlb_bootstrap::deps::plan(&d, &seen);
        let facts = hlb_bootstrap::observe::facts(&r, &d).await.expect("facts");
        let mut plan =
            provision::plan(&d, &deps, &facts).unwrap_or_else(|e| panic!("{image}: refused → {e}"));
        plan.steps.retain(|s| s.phase != Phase::Services);

        provision::execute(&r, &plan, |s| println!("  {image}: {}", s.describe()))
            .await
            .unwrap_or_else(|e| panic!("{image}: {e}"));

        let after = hlb_bootstrap::observe::dependencies(&r, &d)
            .await
            .expect("dependencies");
        let still = hlb_bootstrap::deps::plan(&d, &after);
        let missing: Vec<_> = still
            .decisions
            .iter()
            .filter(|x| x.presence.needs_install())
            .map(|x| x.dependency.name)
            .collect();
        assert!(missing.is_empty(), "{image}: still missing {missing:?}");

        let version = after
            .iter()
            .find(|(n, _)| *n == "docker")
            .and_then(|(_, v)| v.clone())
            .expect("docker observed");
        assert!(
            hlb_bootstrap::deps::version_at_least(&version, hlb_bootstrap::deps::DOCKER_FLOOR),
            "{image}: Docker {version} is below the floor"
        );

        // A second plan has nothing left to install: the probes see what was installed.
        let facts = hlb_bootstrap::observe::facts(&r, &d).await.expect("facts");
        let again = provision::plan(&d, &still, &facts).expect("a plan");
        assert!(
            again
                .steps
                .iter()
                .all(|s| s.phase == Phase::Services || s.phase == Phase::Configuration),
            "{image}: a second run would install again: {:?}",
            again.steps.iter().map(|s| s.describe()).collect::<Vec<_>>()
        );

        println!("✓ {image:<28} provisioned, Docker {version}");
        covered.push(image);
        stop(name);
    }

    assert!(
        !covered.is_empty(),
        "no image available locally - this test proved nothing"
    );
}

/// The mesh under OpenRC, for real: Alpine has no `wg-quick@` unit, so it gets a
/// service of its own — brought up once, then synchronised in place on a second run.
#[tokio::test]
#[ignore = "needs Docker, privileges, and the host's WireGuard module"]
async fn the_mesh_comes_up_under_openrc() {
    use hlb_bootstrap::provision::{self, Init, Provision};

    let name = "hlb-mesh-alpine";
    let _ = docker(&["rm", "-f", name]);
    let out = docker(&[
        "run",
        "-d",
        "--name",
        name,
        "--privileged",
        "alpine:3",
        "sleep",
        "600",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let r = DockerRunner {
        container: name.into(),
    };
    let setup = r
        .run(&[
            "sh".into(),
            "-c".into(),
            "apk add -q --no-cache openrc wireguard-tools nftables iproute2 >/dev/null \
             && mkdir -p /run/openrc && touch /run/openrc/softlevel && wg genkey"
                .into(),
        ])
        .await
        .expect("setup");
    assert!(setup.ok(), "{}", setup.stderr);
    let key = setup.stdout.trim().to_string();

    let config = format!("[Interface]\nPrivateKey = {key}\nAddress = 10.42.0.2/24\nListenPort = 51820\nPostUp = nft -f /etc/wireguard/hlb0.nft\n");
    let firewall = "table inet hlb_swarm\ndelete table inet hlb_swarm\ntable inet hlb_swarm {\n\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n\t\tiifname \"hlb0\" accept\n\t\tudp dport 4789 drop\n\t}\n}\n";
    let tunnel = hlb_bootstrap::mesh::Tunnel {
        label: "the mesh",
        unit: "hlb-mesh",
        interface: "hlb0",
        config_path: "/etc/wireguard/hlb0.conf",
        firewall_path: "/etc/wireguard/hlb0.nft",
    };
    let steps =
        hlb_bootstrap::mesh::steps(Init::OpenRc, &tunnel, &config, firewall).expect("openrc steps");
    let plan = Provision {
        steps,
        notes: Vec::new(),
    };

    for pass in ["bring-up", "sync in place"] {
        provision::execute(&r, &plan, |s| println!("  {pass}: {}", s.describe()))
            .await
            .unwrap_or_else(|e| panic!("{pass}: {e}"));
        let link = r
            .run(&[
                "ip".into(),
                "-br".into(),
                "addr".into(),
                "show".into(),
                "hlb0".into(),
            ])
            .await
            .expect("ip");
        assert!(link.stdout.contains("10.42.0.2"), "{pass}: {}", link.stdout);
    }
    let rules = r
        .run(&[
            "nft".into(),
            "list".into(),
            "table".into(),
            "inet".into(),
            "hlb_swarm".into(),
        ])
        .await
        .expect("nft");
    assert!(rules.stdout.contains("4789"), "{}", rules.stdout);
    let boot = r
        .run(&["rc-update".into(), "show".into(), "default".into()])
        .await
        .expect("rc-update");
    assert!(boot.stdout.contains("hlb-mesh"), "{}", boot.stdout);
    println!("✓ hlb0 up under OpenRC, firewall loaded, started at boot");
    stop(name);
}
