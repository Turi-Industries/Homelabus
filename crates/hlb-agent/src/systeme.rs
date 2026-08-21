//! What the node knows about itself: load, memory, network, versions.
//!
//! ## 🔴 `Option` everywhere, and never a zero
//!
//! Any measurement can be missing: an absent `/proc` (macOS during development), an
//! unreadable file, a first reading with no previous one to compare against. In **all**
//! those cases the value is `None`, never `0.0`.
//!
//! Same rule as elsewhere in the project: an absent metric beats a zero. A CPU at "0 %"
//! reads as "idle machine", the exact opposite of "I do not know". On a dashboard, that
//! is the difference between an empty cell you go and check and a green light that
//! reassures you wrongly.
//!
//! ## Why `/proc` and not Docker
//!
//! The agent **never** talks to Docker. Giving it the socket would turn every node into
//! a door onto the daemon, with the privileges that implies. Per-container statistics
//! come from cadvisor, deployed as a catalog app and scraped by VictoriaMetrics - not
//! from our agent.

use serde::{Deserialize, Serialize};

/// The system's load average.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Charge {
    pub une_min: f64,
    pub cinq_min: f64,
    pub quinze_min: f64,
}

impl Charge {
    /// The load divided by the core count.
    ///
    /// 🔴 This is **the only comparable figure** between machines. A load of 4 is
    /// dramatic on one core and comfortable on sixteen; showing the raw value side by
    /// side for heterogeneous nodes - which is what a homelab is - means nothing.
    pub fn par_coeur(&self, coeurs: u32) -> Option<f64> {
        (coeurs > 0).then(|| self.une_min / f64::from(coeurs))
    }
}

/// A network interface's counters.
///
/// ⚠️ Counters **cumulative since boot**, not a rate. The rate is computed as a
/// difference between two readings, and that is the consumer's job: the agent does not
/// know when it will next be polled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub nom: String,
    pub rx_octets: u64,
    pub tx_octets: u64,
}

/// The system's identity.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Systeme {
    #[serde(default)]
    pub noyau: Option<String>,
    #[serde(default)]
    pub distro: Option<String>,
    /// How long the machine has been running.
    ///
    /// Useful for a precise reason: a node that just rebooted explains a lot, and
    /// checking that does not always come to mind.
    #[serde(default)]
    pub uptime_s: Option<u64>,
}

/// The CPU's state at the moment of reading.
///
/// `/proc/stat`'s counters are cumulative: the usage rate is a **difference** between
/// two readings. This structure carries the raw reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuReading {
    pub total: u64,
    pub inactif: u64,
}

impl CpuReading {
    /// The usage rate between two readings, in `[0, 1]`.
    ///
    /// 🔴 Returns `None` when the computation makes no sense - no previous reading,
    /// counters that went backwards (a reboot), no elapsed time. A `0.0` in those cases
    /// would make a machine we know nothing about look idle.
    pub fn occupation(&self, previous: &CpuReading) -> Option<f64> {
        let dt = self.total.checked_sub(previous.total)?;
        let di = self.inactif.checked_sub(previous.inactif)?;
        if dt == 0 {
            return None;
        }
        Some(((dt - di.min(dt)) as f64 / dt as f64).clamp(0.0, 1.0))
    }
}

/// Lit `/proc/loadavg`.
pub fn charge() -> Option<Charge> {
    let s = std::fs::read_to_string("/proc/loadavg").ok()?;
    let mut m = s.split_whitespace();
    Some(Charge {
        une_min: m.next()?.parse().ok()?,
        cinq_min: m.next()?.parse().ok()?,
        quinze_min: m.next()?.parse().ok()?,
    })
}

/// The number of cores the kernel sees.
pub fn coeurs() -> Option<u32> {
    std::thread::available_parallelism()
        .ok()
        .map(|n| n.get() as u32)
}

/// Reads the aggregated `cpu` line from `/proc/stat`.
pub fn read_cpu() -> Option<CpuReading> {
    let s = std::fs::read_to_string("/proc/stat").ok()?;
    parse_cpu(&s)
}

/// Extracts the reading from the first `cpu ` line (aggregated, with the space).
///
/// ⚠️ "cpu" **with the space**: without it we would match `cpu0`, the first core, and
/// report one core's load as the machine's.
pub fn parse_cpu(proc_stat: &str) -> Option<CpuReading> {
    let ligne = proc_stat.lines().find(|l| l.starts_with("cpu "))?;
    let champs: Vec<u64> = ligne
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    if champs.len() < 4 {
        return None;
    }
    // /proc/stat order: user, nice, system, idle, iowait, irq, softirq, steal...
    // `iowait` counts as idle: the CPU is waiting on a disk there, it is not busy.
    let inactif = champs[3] + champs.get(4).copied().unwrap_or(0);
    Some(CpuReading {
        total: champs.iter().sum(),
        inactif,
    })
}

/// Lit `/proc/net/dev`.
pub fn interfaces() -> Vec<Interface> {
    std::fs::read_to_string("/proc/net/dev")
        .map(|s| parser_interfaces(&s))
        .unwrap_or_default()
}

/// Extracts the interfaces from `/proc/net/dev`.
///
/// ⚠️ `lo` is excluded: loopback traffic inflates the figures without saying anything
/// about the real network - on a Swarm node it is most of the volume.
pub fn parser_interfaces(proc_net_dev: &str) -> Vec<Interface> {
    proc_net_dev
        .lines()
        .skip(2) // Two header lines.
        .filter_map(|l| {
            let (nom, reste) = l.split_once(':')?;
            let nom = nom.trim();
            if nom == "lo" || nom.is_empty() {
                return None;
            }
            let champs: Vec<u64> = reste
                .split_whitespace()
                .filter_map(|v| v.parse().ok())
                .collect();
            // Colonnes : rx_bytes … (8 champs) … tx_bytes …
            Some(Interface {
                nom: nom.to_string(),
                rx_octets: *champs.first()?,
                tx_octets: *champs.get(8)?,
            })
        })
        .collect()
}

/// Lit l'uptime en secondes.
pub fn uptime_s() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/uptime").ok()?;
    s.split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|v| v as u64)
}

/// Le noyau et la distribution.
pub fn systeme() -> Systeme {
    Systeme {
        noyau: std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        distro: std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| pretty_name(&s)),
        uptime_s: uptime_s(),
    }
}

/// Extrait `PRETTY_NAME` de `/etc/os-release`.
pub fn pretty_name(os_release: &str) -> Option<String> {
    os_release.lines().find_map(|l| {
        l.strip_prefix("PRETTY_NAME=")
            .map(|v| v.trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    })
}

/// Swap memory, in megabytes.
pub fn swap_mb() -> (Option<u64>, Option<u64>) {
    let Ok(s) = std::fs::read_to_string("/proc/meminfo") else {
        return (None, None);
    };
    let ko = |cle: &str| -> Option<u64> {
        s.lines()
            .find(|l| l.starts_with(cle))?
            .split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()
    };
    let total = ko("SwapTotal:").map(|v| v / 1024);
    let libre = ko("SwapFree:").map(|v| v / 1024);
    // Used is computed; exposing it directly stops every consumer redoing the
    // subtraction and getting the sign wrong half the time.
    let utilise = match (total, libre) {
        (Some(t), Some(l)) => Some(t.saturating_sub(l)),
        _ => None,
    };
    (total, utilise)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_usage_needs_two_readings() {
        // 🔴 The very first reading has nothing to compare against. Returning 0 % would
        // make a node we know nothing about look idle.
        let a = CpuReading {
            total: 1000,
            inactif: 800,
        };
        let b = CpuReading {
            total: 1100,
            inactif: 850,
        };
        // 100 ticks elapsed, 50 idle → 50 % busy.
        assert_eq!(b.occupation(&a), Some(0.5));
    }

    #[test]
    fn a_reboot_does_not_produce_an_absurd_figure() {
        // After a reboot the counters restart from zero: the subtraction would
        // overflow, and a `wrapping_sub` would give a nonsensical rate.
        let before = CpuReading {
            total: 1_000_000,
            inactif: 900_000,
        };
        let after = CpuReading {
            total: 500,
            inactif: 400,
        };
        assert_eq!(after.occupation(&before), None);
    }

    #[test]
    fn two_identical_readings_yield_nothing_rather_than_idle() {
        // No elapsed time: we know nothing. "0 %" would say "idle".
        let a = CpuReading {
            total: 1000,
            inactif: 800,
        };
        assert_eq!(a.occupation(&a), None);
    }

    #[test]
    fn the_aggregate_cpu_line_is_read_not_the_first_core() {
        // ⚠️ "cpu" WITH the space: without it we match `cpu0` and report one core's
        // load as the machine's.
        let proc_stat = "cpu  100 20 30 800 50 0 0 0 0 0\n\
                         cpu0 10 2 3 80 5 0 0 0 0 0\n\
                         cpu1 90 18 27 720 45 0 0 0 0 0\n\
                         intr 12345\n";
        let r = parse_cpu(proc_stat).expect("reading");
        assert_eq!(r.total, 1000, "the aggregated line, not cpu0");
        assert_eq!(r.inactif, 850, "idle + iowait");
    }

    #[test]
    fn iowait_counts_as_idle() {
        // The CPU is waiting on a disk there: it is not busy. Counting it as work
        // would make a machine waiting on its NAS look saturated.
        let without = parse_cpu("cpu  100 0 0 900 0 0 0 0\n").expect("reading");
        let with = parse_cpu("cpu  100 0 0 400 500 0 0 0\n").expect("reading");
        assert_eq!(without.inactif, with.inactif);
    }

    #[test]
    fn a_missing_proc_file_yields_nothing_rather_than_zero() {
        assert_eq!(parse_cpu(""), None);
        assert_eq!(parse_cpu("intr 12345\n"), None);
        assert_eq!(parse_cpu("cpu  1 2\n"), None, "champs insuffisants");
    }

    #[test]
    fn loopback_traffic_is_excluded() {
        // 🔴 On a Swarm node, `lo` is most of the volume: including it would make the
        // network figure useless.
        let dev = "Inter-|   Receive                    |  Transmit\n\
                   face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets\n\
                   \x20 lo: 999999 100 0 0 0 0 0 0 999999 100 0 0 0 0 0 0\n\
                   \x20eth0: 1234 10 0 0 0 0 0 0 5678 20 0 0 0 0 0 0\n";
        let v = parser_interfaces(dev);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].nom, "eth0");
        assert_eq!(v[0].rx_octets, 1234);
        assert_eq!(v[0].tx_octets, 5678);
    }

    #[test]
    fn load_is_comparable_only_once_divided_by_cores() {
        // 🔴 A load of 4 is dramatic on one core and comfortable on sixteen. A homelab
        // is made of heterogeneous machines: the raw value side by side means
        // nothing.
        let c = Charge {
            une_min: 4.0,
            cinq_min: 3.0,
            quinze_min: 2.0,
        };
        assert_eq!(c.par_coeur(1), Some(4.0));
        assert_eq!(c.par_coeur(16), Some(0.25));
        assert_eq!(c.par_coeur(0), None, "no division by zero");
    }

    #[test]
    fn the_distribution_name_is_read_without_its_quotes() {
        let os = "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\n";
        assert_eq!(
            pretty_name(os).as_deref(),
            Some("Debian GNU/Linux 12 (bookworm)")
        );
        assert_eq!(pretty_name("ID=debian\n"), None);
        assert_eq!(pretty_name("PRETTY_NAME=\"\"\n"), None, "vide vaut absent");
    }
}
