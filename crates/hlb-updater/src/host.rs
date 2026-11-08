//! What a machine itself runs — its system's packages, the kernel among them — against
//! the flaws known today, with the images' rule: an alert only when a fix exists and the
//! flaw is exploited or likely to be.
//!
//! Three jobs, none installed on the host: one reads its `/etc/os-release`, one runs Syft
//! on its package database ALONE, mounted read-only — never `/`, which holds the vault
//! and every app's data —, and Grype reads the list of packages Syft printed, on the node
//! keeping its database. `debsecan` was the first idea: Debian only, and it knows neither
//! KEV nor EPSS, the two things the alert is decided on.
//!
//! 🔴 A distribution Grype holds no advisories for reads CLEAN, not unread: measured
//! 2026-11-08 on old images, openSUSE Leap 15.5 gave 0 fixable flaws and Arch 5 (from
//! sources that are not its own), where Debian 12.8 gave 97 and Rocky 9.3 517. Only the
//! distributions in [`READ_BY_GRYPE`] are read; any other is said NOT READ, never clean.

use hlb_bootstrap::{Distro, PackageManager};
use hlb_orchestrator::swarm::DOCKER_CLI_IMAGE;
use hlb_orchestrator::{JobOutcome, NodeInfo, ServiceSpec};

use crate::grype::{grype_reading, report, tail, Finding, Grype, SYFT_IMAGE};

/// The `ID`s whose advisories Grype reads, each measured 2026-11-08 against an old image
/// of it (fixable flaws found: Debian 12.8 97, Ubuntu 24.04 9, Rocky 9.3 517, AlmaLinux
/// 9.3 503, Alpine 3.20.0 71) — and RHEL, whose advisories Rocky and Alma are read by.
/// A derivative is not its parent: Mint's packages are named `linuxmint`, which nothing
/// in Grype's database matches.
pub const READ_BY_GRYPE: [&str; 6] = ["debian", "ubuntu", "rhel", "rocky", "almalinux", "alpine"];

/// Where the host's `/etc/os-release` is read in the first job. A bind follows a link:
/// the file is usually one, into `/usr/lib`.
const OS_RELEASE: &str = "/hlb/os-release";

/// The host's files, under Syft's directory.
const ROOT: &str = "/host";
const SYFT_TEMPLATE_PATH: &str = "/hlb/purls.tmpl";
const PURLS_PATH: &str = "/hlb/host.purls";

const PURLS: &str = "hlb-purls";
const DISTRO: &str = "hlb-distro";
const PACKAGES: &str = "hlb-packages";

/// Ten packages a line, then the distribution and the count: the job's log is its only
/// output and is read up to 2,000 lines, so one a line would cut a desktop's list — the
/// count tells a cut list from a short one. Syft's template reads its JSON's own keys.
const SYFT_TEMPLATE: &str = concat!(
    "{{- range $i, $a := .artifacts -}}\n",
    "{{- if eq (mod $i 10) 0}}{{if $i}}\n{{end}}hlb-purls{{end}}\t{{$a.purl}}\n",
    "{{- end}}\n",
    // A key the release file lacks prints `<no value>`: `with` prints nothing.
    "hlb-distro\t{{.distro.id}}\t{{with .distro.versionID}}{{.}}{{end}}\n",
    "hlb-packages\t{{len .artifacts}}\n",
);

/// A list Swarm can hand the Grype job: its files ride on secrets, 500 KB at most. A
/// Debian server's thousand packages are about 110 KB.
const PURLS_MAX: usize = 400_000;

/// The package database Syft reads for `d`, or why the machine cannot be read.
pub fn database(d: &Distro) -> Result<&'static str, String> {
    if !READ_BY_GRYPE.contains(&d.id.as_str()) {
        return Err(format!(
            "Grype holds no advisories for {}: its packages would read clean",
            d.pretty_name
        ));
    }
    match d.package_manager() {
        PackageManager::Apt => Ok("/var/lib/dpkg"),
        // A link into `/usr/lib/sysimage/rpm` on the newest: the bind follows it.
        PackageManager::Dnf | PackageManager::Zypper => Ok("/var/lib/rpm"),
        PackageManager::Apk => Ok("/lib/apk/db"),
        PackageManager::Pacman => Err(format!(
            "Grype holds no advisories for {}: its packages would read clean",
            d.pretty_name
        )),
    }
}

fn short(node: &NodeInfo) -> &str {
    node.id.get(..12).unwrap_or(&node.id)
}

/// Prints `node`'s `/etc/os-release`.
pub fn os_job(node: &NodeInfo) -> ServiceSpec {
    ServiceSpec::new(format!("hlb-os-{}", short(node)), DOCKER_CLI_IMAGE)
        .job()
        .constraint(format!("node.id=={}", node.id))
        .bind("/etc/os-release", OS_RELEASE, true)
        .command(["cat".to_string(), OS_RELEASE.to_string()])
}

/// Lists the packages in `node`'s database at `db`. No network: it reads two paths.
pub fn syft_job(node: &NodeInfo, db: &str) -> ServiceSpec {
    let mut job = ServiceSpec::new(format!("hlb-syft-{}", short(node)), SYFT_IMAGE)
        .job()
        .constraint(format!("node.id=={}", node.id))
        // Syft names the distribution from this file, where it finds it in the tree.
        .bind("/etc/os-release", format!("{ROOT}/etc/os-release"), true)
        .bind(db, format!("{ROOT}{db}"), true)
        .file(SYFT_TEMPLATE_PATH, SYFT_TEMPLATE)
        .command([
            "/syft".to_string(),
            "scan".to_string(),
            format!("dir:{ROOT}"),
            "-o".to_string(),
            "template".to_string(),
            "-t".to_string(),
            SYFT_TEMPLATE_PATH.to_string(),
            "-q".to_string(),
        ]);
    // Syft writes its cache under the home directory.
    job.hardening.read_only_rootfs = false;
    job
}

/// Grype's reading of `purls`, on `at` — the node keeping its database.
pub fn grype_job(
    node: &NodeInfo,
    purls: &[String],
    network: &str,
    at: Option<&str>,
) -> ServiceSpec {
    let mut job = ServiceSpec::new(
        format!("hlb-grype-host-{}", short(node)),
        crate::grype::GRYPE_IMAGE,
    )
    .job()
    .network(network)
    .file(PURLS_PATH, purls.join("\n") + "\n");
    if let Some(at) = at {
        job = job.constraint(format!("node.id=={at}"));
    }
    job.hardening.read_only_rootfs = false;
    grype_reading(job, &format!("purl:{PURLS_PATH}"))
}

/// A machine's packages, as Syft listed them.
#[derive(Debug, Clone, PartialEq)]
pub struct Packages {
    /// `debian 12`, as Syft named the distribution.
    pub distro: String,
    pub purls: Vec<String>,
}

/// Reads the Syft job's log. `Err` says why it is not a list.
pub fn parse(lines: &[String]) -> Result<Packages, String> {
    let mut purls = Vec::new();
    let mut distro = None;
    let mut count = None;
    for line in lines {
        let fields: Vec<&str> = line.trim_end_matches(['\r', '\n']).split('\t').collect();
        match fields.as_slice() {
            [PURLS, rest @ ..] => purls.extend(rest.iter().map(|p| p.to_string())),
            [DISTRO, id, version] => distro = Some(format!("{id} {version}").trim().to_string()),
            [PACKAGES, n] => count = n.trim().parse::<usize>().ok(),
            _ => {}
        }
    }
    let Some(n) = count else {
        return Err(format!(
            "Syft did not say how many packages it found: {}",
            tail(lines)
        ));
    };
    if n != purls.len() {
        return Err(format!(
            "the list was cut: {} of {n} packages read",
            purls.len()
        ));
    }
    // 🔴 No package is a database not read — the wrong path, or one empty — never a
    // machine with nothing to fix.
    if n == 0 {
        return Err("Syft found no package: the database was not where it was looked for".into());
    }
    // Syft names a package by a purl only on a distribution it knows: one without is
    // a package Grype would never judge.
    let bare = purls.iter().filter(|p| !p.starts_with("pkg:")).count();
    if bare > 0 {
        return Err(format!(
            "{bare} of {n} packages have no package URL: Grype would not judge them"
        ));
    }
    match distro.filter(|d| !d.is_empty()) {
        // Without a distribution Grype matches nothing a distribution fixes.
        None => Err("Syft did not name the distribution".into()),
        Some(distro) => Ok(Packages { distro, purls }),
    }
}

/// What a machine was read as.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    /// `Debian GNU/Linux 12 (bookworm)`, or the hostname alone when even that is not known.
    pub system: String,
    pub found: Result<Vec<Finding>, String>,
}

fn output(o: &JobOutcome, what: &str) -> Result<Vec<String>, String> {
    if o.succeeded {
        Ok(o.output.clone())
    } else {
        Err(format!("{what} failed: {}", tail(&o.output)))
    }
}

impl Grype<'_> {
    /// The flaws a fix exists for in what `node` itself runs.
    pub async fn host_findings(&self, node: &NodeInfo) -> Reading {
        let mut system = node.hostname.clone();
        let found = async {
            let os = output(&self.run(&os_job(node)).await?, "reading /etc/os-release")?;
            let distro = Distro::parse(&os.join("\n"))
                .ok_or_else(|| format!("/etc/os-release names no known system: {}", tail(&os)))?;
            system = distro.pretty_name.clone();
            let db = database(&distro)?;
            let listed = output(&self.run(&syft_job(node, db)).await?, "Syft")?;
            let packages = parse(&listed)?;
            if packages.purls.iter().map(|p| p.len() + 1).sum::<usize>() > PURLS_MAX {
                return Err(format!(
                    "{} packages: more than a job can be handed",
                    packages.purls.len()
                ));
            }
            let at = self.orchestrator.local_node().await.ok().flatten();
            report(
                &self
                    .run(&grype_job(
                        node,
                        &packages.purls,
                        self.network,
                        at.as_deref(),
                    ))
                    .await?,
            )
        }
        .await;
        Reading { system, found }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn distro(os_release: &str) -> Distro {
        Distro::parse(os_release).expect("a distribution")
    }

    #[test]
    fn only_a_distribution_grype_reads_is_read() {
        let debian = distro("ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n");
        assert_eq!(database(&debian), Ok("/var/lib/dpkg"));
        let rocky = distro("ID=rocky\nID_LIKE=\"rhel centos fedora\"\nPRETTY_NAME=Rocky\n");
        assert_eq!(database(&rocky), Ok("/var/lib/rpm"));
        let alpine = distro("ID=alpine\nPRETTY_NAME=Alpine\n");
        assert_eq!(database(&alpine), Ok("/lib/apk/db"));
        // 🔴 Each would read clean: a family Homelabus drives is not one Grype reads.
        for unread in [
            "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nPRETTY_NAME=Mint\n",
            "ID=arch\nPRETTY_NAME=Arch\n",
            "ID=opensuse-leap\nPRETTY_NAME=Leap\n",
            "ID=fedora\nPRETTY_NAME=Fedora\n",
        ] {
            let d = distro(unread);
            let why = database(&d).expect_err(unread);
            assert!(why.contains("would read clean"), "{why}");
        }
    }

    fn lines(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_package_list_is_read_whole_or_not_at_all() {
        let whole = lines(&[
            "hlb-purls\tpkg:deb/debian/apt@2.6.1?distro=debian-12\tpkg:deb/debian/bash@5.2",
            "hlb-purls\tpkg:deb/debian/zlib1g@1.2.13?distro=debian-12",
            "hlb-distro\tdebian\t12",
            "hlb-packages\t3",
        ]);
        let p = parse(&whole).expect("a list");
        assert_eq!(p.distro, "debian 12");
        assert_eq!(p.purls.len(), 3);

        let cut = &whole[1..];
        assert!(parse(cut).expect_err("cut").contains("1 of 3"));
        assert!(parse(&whole[..3]).is_err(), "no count");
        let none = lines(&["hlb-distro\tdebian\t12", "hlb-packages\t0"]);
        assert!(parse(&none).expect_err("empty").contains("no package"));
        let unnamed = lines(&[
            "hlb-purls\tpkg:deb/x@1",
            "hlb-distro\t\t",
            "hlb-packages\t1",
        ]);
        assert!(parse(&unnamed).is_err(), "no distribution matches nothing");
        let bare = lines(&[
            "hlb-purls\t\tpkg:deb/x@1",
            "hlb-distro\tx\t1",
            "hlb-packages\t2",
        ]);
        assert!(parse(&bare)
            .expect_err("bare")
            .contains("1 of 2 packages have no package URL"));
    }

    fn node() -> NodeInfo {
        NodeInfo {
            id: "abcdefabcdef0123".into(),
            hostname: "deb1".into(),
            role: hlb_orchestrator::NodeRole::Worker,
            status: "ready".into(),
            availability: "active".into(),
            tier: None,
            protection: None,
            disk_tangs: Vec::new(),
            is_leader: false,
            memory_mb: None,
            failure_domain: None,
            data: Vec::new(),
            ingress: false,
            addr: None,
        }
    }

    #[test]
    fn a_machine_is_read_on_itself_and_judged_where_the_database_is() {
        let n = node();
        let os = os_job(&n);
        assert!(os
            .constraints
            .contains(&"node.id==abcdefabcdef0123".to_string()));
        assert!(os.binds.iter().all(|b| b.read_only));

        let syft = syft_job(&n, "/var/lib/dpkg");
        assert_eq!(syft.image, SYFT_IMAGE);
        assert!(syft.networks.is_empty(), "it reads two paths, nothing else");
        // 🔴 Never `/`: the vault and every app's data live under it.
        let sources: Vec<&str> = syft.binds.iter().map(|b| b.source.as_str()).collect();
        assert_eq!(sources, ["/etc/os-release", "/var/lib/dpkg"]);
        assert!(syft.binds.iter().all(|b| b.read_only));

        let purls = ["pkg:deb/debian/apt@2.6.1?distro=debian-12".to_string()];
        let g = grype_job(&n, &purls, "hlb_platform", Some("manager"));
        assert!(g.constraints.contains(&"node.id==manager".to_string()));
        assert!(g.command.contains(&format!("purl:{PURLS_PATH}")));
        assert!(g.command.contains(&"--only-fixed".to_string()));
        assert!(g
            .files
            .iter()
            .any(|(p, c)| p == PURLS_PATH && c.contains("apt@2.6.1")));
    }
}
