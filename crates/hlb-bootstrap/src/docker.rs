//! Where Docker comes from, and how it is configured.
//!
//! ## Docker's own repository, where it publishes one
//!
//! A distribution's package lags: Debian 12 ships `docker.io` 20.10, below the floor
//! Swarm needs here — so "install the distribution's Docker" fails on the most common
//! server distribution there is. Docker publishes signed repositories for Debian, Ubuntu,
//! Fedora, RHEL and its rebuilds; those are used. Elsewhere (Alpine, Arch, openSUSE,
//! Amazon Linux) the distribution's own package is current enough and is the one its
//! maintainers support.
//!
//! The convenience script (`get.docker.com`) is never used: Docker documents it as unfit
//! for production, and it runs whatever the server returns that day as root.
//!
//! ## 🔴 The signing keys are compiled in
//!
//! Downloading the key at install time trusts whatever answers on that day: anyone able
//! to tamper with the download hands the node a key of their choosing, and every package
//! after it. The keys below were fetched from `download.docker.com` on 2026-10-11 and
//! checked against the fingerprints Docker publishes:
//!
//! | File | Fingerprint |
//! |---|---|
//! | `keys/docker-deb.asc` | `9DC8 5822 9FC7 DD38 854A  E2D8 8D81 803C 0EBF CD88` |
//! | `keys/docker-rpm.asc` | `060A 61C5 1B55 8A7F 742B  77AA C52F EB6B 621E 9F35` |
//!
//! ## Rootless Docker is not an option here
//!
//! Rootless mode does not support overlay networks, and Swarm's service networking is
//! built on them: a rootless node can join nothing. Containers still run unprivileged —
//! `cap_drop: [ALL]`, `no_new_privileges` and a read-only root are the defaults every
//! manifest starts from.

use crate::distro::{Distro, Family};

/// Docker's key for its APT repositories.
pub const DEB_KEY: &str = include_str!("../keys/docker-deb.asc");

/// Docker's key for its RPM repositories.
pub const RPM_KEY: &str = include_str!("../keys/docker-rpm.asc");

/// The packages Docker's repositories install. Not `docker-buildx-plugin` nor
/// `docker-compose-plugin`: a node builds nothing and composes nothing.
pub const OFFICIAL_PACKAGES: &[&str] = &["docker-ce", "docker-ce-cli", "containerd.io"];

/// Packages that conflict with Docker's own, as Docker lists them. `apt` refuses to
/// install over them halfway through, after the repository is already in place.
pub const APT_CONFLICTS: &[&str] = &[
    "docker.io",
    "docker-doc",
    "docker-compose",
    "podman-docker",
    "containerd",
    "runc",
];

/// Same, on the RPM side.
pub const DNF_CONFLICTS: &[&str] = &[
    "docker",
    "docker-client",
    "docker-common",
    "docker-engine",
    "podman-docker",
    "moby-engine",
];

/// Where `daemon.json` lives.
pub const DAEMON_JSON: &str = "/etc/docker/daemon.json";

/// Where Docker comes from on a given distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Docker's APT repository. `os` is the path segment on `download.docker.com`.
    Apt { os: &'static str, suite: String },
    /// Docker's RPM repository.
    Dnf { os: &'static str },
    /// The distribution's own package.
    Distribution { package: &'static str },
}

impl Source {
    /// The packages to install.
    pub fn packages(&self) -> Vec<&'static str> {
        match self {
            Self::Apt { .. } => OFFICIAL_PACKAGES.to_vec(),
            // 🔴 `iptables-nft` named, not left to dnf: with EPEL enabled (restic lives
            // there) dnf satisfied Docker's `iptables` with EPEL's `iptables-legacy`,
            // and the daemon then failed to start on "can't initialize iptables table
            // `nat'" — seen on Rocky 9.
            Self::Dnf { .. } => {
                let mut p = vec!["iptables-nft"];
                p.extend(OFFICIAL_PACKAGES);
                p
            }
            Self::Distribution { package } => vec![package],
        }
    }

    /// The installed packages that would stop the installation, among those observed.
    pub fn conflicts(&self) -> &'static [&'static str] {
        match self {
            Self::Apt { .. } => APT_CONFLICTS,
            Self::Dnf { .. } => DNF_CONFLICTS,
            Self::Distribution { .. } => &[],
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Apt { os, suite } => {
                format!("Docker's APT repository ({os} {suite}), key compiled in")
            }
            Self::Dnf { os } => format!("Docker's RPM repository ({os}), key compiled in"),
            Self::Distribution { package } => format!("the distribution's \"{package}\""),
        }
    }

    /// The repository definition and key to put in place, as `(path, content)`.
    pub fn repository_files(&self) -> Vec<(String, String)> {
        match self {
            Self::Apt { os, suite } => vec![
                ("/etc/apt/keyrings/docker.asc".into(), DEB_KEY.into()),
                (
                    "/etc/apt/sources.list.d/docker.sources".into(),
                    // deb822, with the key scoped to this repository alone:
                    // `apt-key` trusted a key for EVERY repository on the machine.
                    format!(
                        "Types: deb\n\
                         URIs: https://download.docker.com/linux/{os}\n\
                         Suites: {suite}\n\
                         Components: stable\n\
                         Signed-By: /etc/apt/keyrings/docker.asc\n"
                    ),
                ),
            ],
            Self::Dnf { os } => vec![
                (
                    "/etc/pki/rpm-gpg/RPM-GPG-KEY-docker-ce".into(),
                    RPM_KEY.into(),
                ),
                (
                    "/etc/yum.repos.d/docker-ce.repo".into(),
                    format!(
                        "[docker-ce-stable]\n\
                         name=Docker CE Stable - $basearch\n\
                         baseurl=https://download.docker.com/linux/{os}/$releasever/$basearch/stable\n\
                         enabled=1\n\
                         gpgcheck=1\n\
                         repo_gpgcheck=0\n\
                         gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-docker-ce\n"
                    ),
                ),
            ],
            Self::Distribution { .. } => Vec::new(),
        }
    }
}

/// Decides where Docker comes from.
///
/// An Ubuntu derivative is matched through `UBUNTU_CODENAME`: Mint's own codename
/// (`wilma`) names no suite in Docker's repository, and `apt-get update` would fail on a
/// 404 naming a URL nobody chose.
pub fn source(distro: &Distro) -> Source {
    match distro.family {
        Family::Debian => {
            if distro.id == "ubuntu" || distro.ubuntu_codename.is_some() {
                let suite = distro
                    .ubuntu_codename
                    .clone()
                    .or_else(|| distro.codename.clone());
                if let Some(suite) = suite {
                    return Source::Apt {
                        os: "ubuntu",
                        suite,
                    };
                }
            } else if distro.id == "debian" || distro.id == "raspbian" {
                // `raspbian` is the 32-bit Raspberry Pi OS, which Docker publishes
                // apart; the 64-bit one reports itself as `debian`.
                let os = if distro.id == "raspbian" {
                    "raspbian"
                } else {
                    "debian"
                };
                if let Some(suite) = distro.codename.clone() {
                    return Source::Apt { os, suite };
                }
            }
            // Devuan and other derivatives: their codenames are not Debian's, and
            // guessing one would pin the node to the wrong release.
            Source::Distribution {
                package: "docker.io",
            }
        }
        Family::RedHat => match distro.id.as_str() {
            "fedora" => Source::Dnf { os: "fedora" },
            "rhel" => Source::Dnf { os: "rhel" },
            "centos" | "rocky" | "almalinux" | "ol" => Source::Dnf { os: "centos" },
            // Amazon Linux's `$releasever` matches none of Docker's directories.
            _ => Source::Distribution { package: "docker" },
        },
        Family::Alpine | Family::Arch | Family::Suse => Source::Distribution { package: "docker" },
    }
}

/// The `daemon.json` written on a node where Homelabus installed Docker.
///
/// Only what a Swarm node needs and the defaults get wrong:
///
/// - **Log rotation.** The default `json-file` driver never rotates: one chatty
///   container fills `/var/lib/docker`, and a full disk stops every service on the node
///   at once. 3 × 10 MB per container.
/// - **`live-restore` stays off** — by omission. Swarm refuses to run with it, and a
///   node configured with it fails `docker swarm join` with a message that names the
///   option but not who set it.
/// - **🔴 No userland proxy.** Caddy's ports are published in host mode on an IPv4-only
///   bridge: an IPv6 client was carried by `docker-proxy`, and reached Caddy from the
///   bridge's GATEWAY — a private address, so a private route answered the internet
///   and CrowdSec saw one address for every IPv6 client. Without it the kernel's DNAT
///   keeps the client's own address, and IPv6 reaches no IPv4-only container at all.
pub const DAEMON_CONFIG: &str = r#"{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "userland-proxy": false
}
"#;

/// Does this `daemon.json` leave Docker's userland proxy on — its default? Then an
/// IPv6 client of a published port reaches the container as the bridge's gateway, a
/// private address ([`DAEMON_CONFIG`]). An unreadable file is judged elsewhere.
pub fn userland_proxy_on(content: Option<&str>) -> bool {
    let Some(v) = content
        .filter(|c| !c.trim().is_empty())
        .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
    else {
        return content.is_none_or(|c| c.trim().is_empty());
    };
    v.get("userland-proxy").and_then(|b| b.as_bool()) != Some(false)
}

/// What an EXISTING `daemon.json` means for a node about to join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonConfig {
    /// No file: Docker's defaults apply.
    Absent,
    /// Present and compatible.
    Fine,
    /// Logs are never rotated.
    UnboundedLogs,
    /// 🔴 `live-restore` is on: Swarm will refuse it.
    LiveRestore,
    /// The file does not parse: Docker itself will not start.
    Unreadable(String),
}

/// Judges a `daemon.json` found on the machine. It is never rewritten: it belongs to
/// whoever configured that Docker, and they may have reasons.
pub fn judge_daemon_config(content: Option<&str>) -> DaemonConfig {
    let Some(content) = content else {
        return DaemonConfig::Absent;
    };
    if content.trim().is_empty() {
        return DaemonConfig::Absent;
    }
    let v: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(e) => return DaemonConfig::Unreadable(e.to_string()),
    };

    if v.get("live-restore").and_then(|b| b.as_bool()) == Some(true) {
        return DaemonConfig::LiveRestore;
    }

    // Only `json-file`, the default, grows without bound. `local` and `journald`
    // rotate on their own; a remote driver keeps nothing on the disk.
    let driver = v
        .get("log-driver")
        .and_then(|d| d.as_str())
        .unwrap_or("json-file");
    let rotated = v.get("log-opts").and_then(|o| o.get("max-size")).is_some();
    if driver == "json-file" && !rotated {
        return DaemonConfig::UnboundedLogs;
    }
    DaemonConfig::Fine
}

#[cfg(test)]
mod tests {
    use super::*;

    fn distro(os_release: &str) -> Distro {
        Distro::parse(os_release).expect("parsable")
    }

    #[test]
    fn debian_gets_dockers_repository_on_its_own_codename() {
        let d = distro("ID=debian\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Debian 12\"\n");
        assert_eq!(
            source(&d),
            Source::Apt {
                os: "debian",
                suite: "bookworm".into()
            }
        );
    }

    #[test]
    fn an_ubuntu_derivative_uses_the_ubuntu_codename_not_its_own() {
        // Mint 22 is `wilma`; Docker publishes `noble`.
        let d = distro(
            "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\nVERSION_CODENAME=wilma\n\
             UBUNTU_CODENAME=noble\nPRETTY_NAME=\"Linux Mint 22\"\n",
        );
        assert_eq!(
            source(&d),
            Source::Apt {
                os: "ubuntu",
                suite: "noble".into()
            }
        );
    }

    #[test]
    fn a_debian_derivative_with_its_own_codenames_falls_back_to_its_own_package() {
        let d = distro("ID=devuan\nID_LIKE=debian\nVERSION_CODENAME=daedalus\nPRETTY_NAME=x\n");
        assert_eq!(
            source(&d),
            Source::Distribution {
                package: "docker.io"
            }
        );
    }

    #[test]
    fn a_debian_without_a_codename_is_not_guessed() {
        let d = distro("ID=debian\nPRETTY_NAME=\"Debian\"\n");
        assert!(matches!(source(&d), Source::Distribution { .. }));
    }

    #[test]
    fn rhel_rebuilds_use_the_centos_repository() {
        for id in ["rocky", "almalinux", "centos"] {
            let d = distro(&format!(
                "ID={id}\nID_LIKE=\"rhel fedora\"\nPRETTY_NAME=x\n"
            ));
            assert_eq!(source(&d), Source::Dnf { os: "centos" }, "{id}");
        }
        let d = distro("ID=fedora\nPRETTY_NAME=x\n");
        assert_eq!(source(&d), Source::Dnf { os: "fedora" });
    }

    #[test]
    fn rolling_and_minimal_distributions_use_their_own_package() {
        for id in ["alpine", "arch", "opensuse-tumbleweed"] {
            let d = distro(&format!("ID={id}\nPRETTY_NAME=x\n"));
            assert_eq!(
                source(&d),
                Source::Distribution { package: "docker" },
                "{id}"
            );
        }
    }

    #[test]
    fn the_rpm_side_names_its_iptables_rather_than_letting_epel_choose() {
        let d = distro("ID=rocky\nPRETTY_NAME=x\n");
        assert_eq!(source(&d).packages()[0], "iptables-nft");
    }

    #[test]
    fn the_official_repository_never_installs_a_package_called_docker() {
        let d = distro("ID=debian\nVERSION_CODENAME=trixie\nPRETTY_NAME=x\n");
        let pkgs = source(&d).packages();
        assert!(pkgs.contains(&"docker-ce"));
        assert!(!pkgs.contains(&"docker"));
    }

    #[test]
    fn the_repository_is_signed_by_the_compiled_in_key_and_nothing_else() {
        let d = distro("ID=ubuntu\nVERSION_CODENAME=noble\nPRETTY_NAME=x\n");
        let files = source(&d).repository_files();
        let (_, sources) = files
            .iter()
            .find(|(p, _)| p.ends_with(".sources"))
            .expect("a sources file");
        assert!(sources.contains("Signed-By: /etc/apt/keyrings/docker.asc"));
        assert!(sources.contains("URIs: https://download.docker.com/linux/ubuntu"));
        assert!(sources.contains("Suites: noble"));
        let (_, key) = files
            .iter()
            .find(|(p, _)| p.ends_with("docker.asc"))
            .expect("the key");
        assert_eq!(key, DEB_KEY);

        let d = distro("ID=rocky\nPRETTY_NAME=x\n");
        let files = source(&d).repository_files();
        let (_, repo) = files
            .iter()
            .find(|(p, _)| p.ends_with(".repo"))
            .expect("a repo file");
        assert!(repo.contains("gpgcheck=1"));
        assert!(repo.contains("gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-docker-ce"));
    }

    #[test]
    fn the_compiled_in_keys_are_public_keys() {
        // A truncated or swapped file would fail at `apt-get update` on the node, with
        // a NO_PUBKEY that does not say the binary carried the wrong bytes.
        for key in [DEB_KEY, RPM_KEY] {
            assert!(key.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
            assert!(key
                .trim_end()
                .ends_with("-----END PGP PUBLIC KEY BLOCK-----"));
        }
    }

    #[test]
    fn our_daemon_config_rotates_logs_and_leaves_live_restore_off() {
        assert_eq!(judge_daemon_config(Some(DAEMON_CONFIG)), DaemonConfig::Fine);
    }

    #[test]
    fn our_daemon_config_turns_the_userland_proxy_off() {
        let v: serde_json::Value = serde_json::from_str(DAEMON_CONFIG).expect("JSON");
        assert_eq!(v["userland-proxy"], false, "{DAEMON_CONFIG}");
        assert!(!userland_proxy_on(Some(DAEMON_CONFIG)));
        // Docker's default is on: no file, or a file not saying, leaves it on.
        assert!(userland_proxy_on(None));
        assert!(userland_proxy_on(Some(r#"{"log-driver": "local"}"#)));
        assert!(userland_proxy_on(Some(r#"{"userland-proxy": true}"#)));
        assert!(
            !userland_proxy_on(Some("{ nope")),
            "judged as unreadable instead"
        );
    }

    #[test]
    fn live_restore_is_caught_before_swarm_refuses_it() {
        let c = r#"{"live-restore": true, "log-opts": {"max-size": "5m"}}"#;
        assert_eq!(judge_daemon_config(Some(c)), DaemonConfig::LiveRestore);
    }

    #[test]
    fn the_default_driver_without_a_size_is_unbounded() {
        assert_eq!(
            judge_daemon_config(Some(r#"{"debug": false}"#)),
            DaemonConfig::UnboundedLogs
        );
        assert_eq!(
            judge_daemon_config(Some(r#"{"log-driver": "local"}"#)),
            DaemonConfig::Fine
        );
    }

    #[test]
    fn a_missing_or_broken_file_is_named_as_such() {
        assert_eq!(judge_daemon_config(None), DaemonConfig::Absent);
        assert_eq!(judge_daemon_config(Some("  \n")), DaemonConfig::Absent);
        assert!(matches!(
            judge_daemon_config(Some("{ nope")),
            DaemonConfig::Unreadable(_)
        ));
    }
}
