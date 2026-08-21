//! Observation d'une machine, locale ou distante (§2ter.4).
//!
//! Séparé du jugement : ce module ne fait que **constater**, [`crate::preflight`]
//! décide. Cette frontière permet de tester le raisonnement complet sur des
//! observations fabriquées, sans provisionner de VM.
//!
//! Aucune commande ici ne modifie quoi que ce soit. C'est ce qui rend `hlb node
//! check` sûr à lancer sur une machine de production.

use crate::runner::{Result, Runner};

/// Interroge la machine et rassemble tout ce dont le précheck a besoin.
pub async fn observe(runner: &dyn Runner) -> Result<crate::preflight::Observation> {
    let os_release = runner
        .read_file("/etc/os-release")
        .await?
        .unwrap_or_default();

    Ok(crate::preflight::Observation {
        os_release,
        docker_version: docker_version(runner).await?,
        docker_is_snap: docker_is_snap(runner).await?,
        podman_present: binary_exists(runner, "podman").await?,
        total_memory_mb: total_memory_mb(runner).await?,
        free_disk_mb: free_disk_mb(runner, "/var/lib").await?,
        clock_synced: clock_synced(runner).await?,
        is_root: is_root(runner).await?,
        cgroups_v2: cgroups_v2(runner).await?,
    })
}

async fn binary_exists(runner: &dyn Runner, name: &str) -> Result<bool> {
    // `command -v` est POSIX ; `which` ne l'est pas et manque sur les images minimales.
    let out = runner
        .run(&["sh".into(), "-c".into(), format!("command -v {name}")])
        .await?;
    Ok(out.ok())
}

async fn docker_version(runner: &dyn Runner) -> Result<Option<String>> {
    let out = runner
        .run(&[
            "docker".into(),
            "version".into(),
            "--format".into(),
            "{{.Server.Version}}".into(),
        ])
        .await;

    // Le binaire peut être absent (Err) ou le daemon injoignable (status != 0).
    // Dans les deux cas, on ne peut pas affirmer qu'un Docker utilisable est là.
    match out {
        Ok(o) if o.ok() => Ok(o.first_line()),
        _ => Ok(None),
    }
}

/// Docker installé via snap ? Son confinement casse certains montages de volumes.
async fn docker_is_snap(runner: &dyn Runner) -> Result<bool> {
    let out = runner
        .run(&["sh".into(), "-c".into(), "command -v docker".into()])
        .await?;
    Ok(out.stdout.contains("/snap/"))
}

async fn total_memory_mb(runner: &dyn Runner) -> Result<Option<u64>> {
    let Some(meminfo) = runner.read_file("/proc/meminfo").await? else {
        return Ok(None);
    };
    Ok(parse_meminfo_total_mb(&meminfo))
}

/// `MemTotal:       16311456 kB`
pub fn parse_meminfo_total_mb(meminfo: &str) -> Option<u64> {
    meminfo
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .map(|kb| kb / 1024)
}

async fn free_disk_mb(runner: &dyn Runner, path: &str) -> Result<Option<u64>> {
    // `-P` force le format POSIX : sans lui, un nom de périphérique long passe à la
    // ligne et décale toutes les colonnes.
    let out = runner
        .run(&["df".into(), "-Pm".into(), path.into()])
        .await?;
    if !out.ok() {
        return Ok(None);
    }
    Ok(parse_df_available_mb(&out.stdout))
}

pub fn parse_df_available_mb(df: &str) -> Option<u64> {
    df.lines()
        .nth(1)?
        .split_whitespace()
        .nth(3)?
        .parse::<u64>()
        .ok()
}

async fn clock_synced(runner: &dyn Runner) -> Result<Option<bool>> {
    // `timedatectl` sur systemd, `chronyc` ailleurs. Aucun des deux n'est garanti.
    let out = runner.run(&["timedatectl".into(), "show".into()]).await;
    if let Ok(o) = out {
        if o.ok() {
            if let Some(v) = parse_timedatectl_synced(&o.stdout) {
                return Ok(Some(v));
            }
        }
    }

    let out = runner.run(&["chronyc".into(), "tracking".into()]).await;
    if let Ok(o) = out {
        if o.ok() {
            // `Leap status : Normal` signale une horloge saine.
            return Ok(Some(o.stdout.contains("Normal")));
        }
    }
    Ok(None)
}

pub fn parse_timedatectl_synced(out: &str) -> Option<bool> {
    out.lines()
        .find_map(|l| l.strip_prefix("NTPSynchronized="))
        .map(|v| v.trim() == "yes")
}

async fn is_root(runner: &dyn Runner) -> Result<bool> {
    let out = runner.run(&["id".into(), "-u".into()]).await?;
    Ok(out.first_line().as_deref() == Some("0"))
}

async fn cgroups_v2(runner: &dyn Runner) -> Result<Option<bool>> {
    // En v2, ce fichier existe à la racine du montage cgroup unifié.
    let out = runner
        .run(&[
            "sh".into(),
            "-c".into(),
            "test -f /sys/fs/cgroup/cgroup.controllers".into(),
        ])
        .await?;
    Ok(Some(out.ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_is_read_from_meminfo() {
        let m = "MemTotal:       16311456 kB\nMemFree:         1234 kB\n";
        assert_eq!(parse_meminfo_total_mb(m), Some(15929));
    }

    #[test]
    fn a_malformed_meminfo_gives_none() {
        assert_eq!(parse_meminfo_total_mb(""), None);
        assert_eq!(parse_meminfo_total_mb("MemTotal: abc kB"), None);
        assert_eq!(parse_meminfo_total_mb("MemFree: 100 kB"), None);
    }

    #[test]
    fn disk_space_is_read_from_df() {
        let df = "Filesystem 1M-blocks Used Available Capacity Mounted on\n\
                  /dev/sda1      102400 20480     76800      21% /\n";
        assert_eq!(parse_df_available_mb(df), Some(76800));
    }

    #[test]
    fn a_df_without_data_gives_none() {
        assert_eq!(
            parse_df_available_mb("Filesystem 1M-blocks Used Available\n"),
            None
        );
        assert_eq!(parse_df_available_mb(""), None);
    }

    #[test]
    fn clock_sync_is_read_from_timedatectl() {
        let out = "Timezone=Europe/Paris\nNTPSynchronized=yes\nCanNTP=yes\n";
        assert_eq!(parse_timedatectl_synced(out), Some(true));

        let out = "Timezone=UTC\nNTPSynchronized=no\n";
        assert_eq!(parse_timedatectl_synced(out), Some(false));
    }

    #[test]
    fn a_timedatectl_without_the_field_gives_none() {
        // Une version ancienne peut ne pas exposer ce champ : ne rien conclure vaut
        // mieux que de supposer que l'horloge est bonne.
        assert_eq!(parse_timedatectl_synced("Timezone=UTC\n"), None);
    }

    #[tokio::test]
    async fn observing_the_local_machine_does_not_panic() {
        // Ce test tourne sur macOS comme sur Linux : /proc n'existe pas partout, et
        // l'observation doit dégrader proprement plutôt qu'échouer.
        let obs = observe(&crate::LocalRunner).await.expect("observation");
        // Sur macOS l'os-release est absent, donc vide : c'est un constat valide.
        assert!(obs.os_release.is_empty() || obs.os_release.contains("ID"));
    }

    #[tokio::test]
    async fn a_missing_binary_never_claims_presence() {
        // 🔴 Docker absent doit donner None, jamais une version fantaisiste.
        struct Vide;
        #[async_trait::async_trait]
        impl Runner for Vide {
            async fn run(&self, _: &[String]) -> Result<crate::runner::Output> {
                Ok(crate::runner::Output {
                    status: 127,
                    stdout: String::new(),
                    stderr: "command not found".into(),
                })
            }
            async fn read_file(&self, _: &str) -> Result<Option<String>> {
                Ok(None)
            }
            fn label(&self) -> String {
                "vide".into()
            }
        }

        let obs = observe(&Vide).await.expect("observation");
        assert!(obs.docker_version.is_none());
        assert!(!obs.podman_present);
        assert!(!obs.is_root);
        assert!(obs.total_memory_mb.is_none());
    }
}
