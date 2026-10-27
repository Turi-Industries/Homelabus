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
pub struct LoadAverage {
    pub one_min: f64,
    pub five_min: f64,
    pub fifteen_min: f64,
}

impl LoadAverage {
    /// The load divided by the core count.
    ///
    /// 🔴 This is **the only comparable figure** between machines. A load of 4 is
    /// dramatic on one core and comfortable on sixteen; showing the raw value side by
    /// side for heterogeneous nodes - which is what a homelab is - means nothing.
    pub fn per_core(&self, cores: u32) -> Option<f64> {
        (cores > 0).then(|| self.one_min / f64::from(cores))
    }
}

/// A network interface's counters.
///
/// ⚠️ Counters **cumulative since boot**, not a rate. The rate is computed as a
/// difference between two readings, and that is the consumer's job: the agent does not
/// know when it will next be polled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// The system's identity.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct System {
    #[serde(default)]
    pub kernel: Option<String>,
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
    pub idle: u64,
}

impl CpuReading {
    /// The usage rate between two readings, in `[0, 1]`.
    ///
    /// 🔴 Returns `None` when the computation makes no sense - no previous reading,
    /// counters that went backwards (a reboot), no elapsed time. A `0.0` in those cases
    /// would make a machine we know nothing about look idle.
    pub fn busy(&self, previous: &CpuReading) -> Option<f64> {
        let dt = self.total.checked_sub(previous.total)?;
        let di = self.idle.checked_sub(previous.idle)?;
        if dt == 0 {
            return None;
        }
        Some(((dt - di.min(dt)) as f64 / dt as f64).clamp(0.0, 1.0))
    }
}

/// Lit `/proc/loadavg`.
pub fn load() -> Option<LoadAverage> {
    let s = std::fs::read_to_string("/proc/loadavg").ok()?;
    let mut m = s.split_whitespace();
    Some(LoadAverage {
        one_min: m.next()?.parse().ok()?,
        five_min: m.next()?.parse().ok()?,
        fifteen_min: m.next()?.parse().ok()?,
    })
}

/// The number of cores the kernel sees.
pub fn cores() -> Option<u32> {
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
    let line = proc_stat.lines().find(|l| l.starts_with("cpu "))?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    if fields.len() < 4 {
        return None;
    }
    // /proc/stat order: user, nice, system, idle, iowait, irq, softirq, steal...
    // `iowait` counts as idle: the CPU is waiting on a disk there, it is not busy.
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);
    Some(CpuReading {
        total: fields.iter().sum(),
        idle,
    })
}

/// Reads the host's network interfaces.
///
/// ⚠️ In a container `/proc/net/dev` is the CONTAINER's namespace: one `eth0` on the
/// overlay. With the host's root mounted, PID 1's view is the host's.
pub fn interfaces(host_root: Option<&str>) -> Vec<Interface> {
    let path = match host_root {
        Some(r) => format!("{r}/proc/1/net/dev"),
        None => "/proc/net/dev".to_string(),
    };
    std::fs::read_to_string(path)
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
            let (name, remaining) = l.split_once(':')?;
            let name = name.trim();
            if name == "lo" || name.is_empty() {
                return None;
            }
            let fields: Vec<u64> = remaining
                .split_whitespace()
                .filter_map(|v| v.parse().ok())
                .collect();
            // Colonnes : rx_bytes … (8 fields) … tx_bytes …
            Some(Interface {
                name: name.to_string(),
                rx_bytes: *fields.first()?,
                tx_bytes: *fields.get(8)?,
            })
        })
        .collect()
}

/// Reads the uptime, in seconds.
pub fn uptime_s() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/uptime").ok()?;
    s.split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|v| v as u64)
}

/// The kernel and the distribution — the host's, under `host_root`: the container's own
/// `/etc/os-release` names the agent's image.
pub fn system(host_root: Option<&str>) -> System {
    System {
        kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        distro: std::fs::read_to_string(format!("{}/etc/os-release", host_root.unwrap_or("")))
            .ok()
            .and_then(|s| pretty_name(&s)),
        uptime_s: uptime_s(),
    }
}

/// Does the host wait for a reboot? The same two signals `hlb node upgrade` reads, through
/// the host's root: Debian's flag, or a newer kernel installed than the one running.
///
/// ⚠️ `run/`, not `var/run/`: on the host `/var/run` is a symlink to `/run`, absolute,
/// and under a mounted root it would point at the CONTAINER's `/run`.
pub fn reboot_required(host_root: Option<&str>) -> Option<bool> {
    let root = host_root.unwrap_or("");
    let mut probe = String::new();
    if std::path::Path::new(&format!("{root}/run/reboot-required")).exists() {
        probe.push_str("yes\n");
    }
    if let Ok(k) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        probe.push_str(&format!("running={}\n", k.trim()));
    }
    if let Ok(entries) = std::fs::read_dir(format!("{root}/lib/modules")) {
        for e in entries.flatten() {
            probe.push_str(&format!("installed={}\n", e.file_name().to_string_lossy()));
        }
    }
    hlb_bootstrap::updates::reboot_required(&probe)
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
    let ko = |key: &str| -> Option<u64> {
        s.lines()
            .find(|l| l.starts_with(key))?
            .split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()
    };
    let total = ko("SwapTotal:").map(|v| v / 1024);
    let free = ko("SwapFree:").map(|v| v / 1024);
    // Used is computed; exposing it directly stops every consumer redoing the
    // subtraction and getting the sign wrong half the time.
    let used = match (total, free) {
        (Some(t), Some(l)) => Some(t.saturating_sub(l)),
        _ => None,
    };
    (total, used)
}

#[cfg(test)]
mod tests {

    #[test]
    fn debians_flag_under_the_host_root_means_a_pending_reboot() {
        let root = tempfile::tempdir().expect("tmp");
        std::fs::create_dir_all(root.path().join("run")).expect("run");
        std::fs::write(root.path().join("run/reboot-required"), "").expect("flag");
        let r = root.path().to_string_lossy().to_string();
        assert_eq!(reboot_required(Some(&r)), Some(true));
    }

    #[test]
    fn a_host_root_that_shows_nothing_says_unknown_not_fine() {
        let root = tempfile::tempdir().expect("tmp");
        let r = root.path().to_string_lossy().to_string();
        // No flag, no /lib/modules: nothing to compare the running kernel with.
        assert_eq!(reboot_required(Some(&r)), None);
    }

    use super::*;

    #[test]
    fn cpu_usage_needs_two_readings() {
        // 🔴 The very first reading has nothing to compare against. Returning 0 % would
        // make a node we know nothing about look idle.
        let a = CpuReading {
            total: 1000,
            idle: 800,
        };
        let b = CpuReading {
            total: 1100,
            idle: 850,
        };
        // 100 ticks elapsed, 50 idle → 50 % busy.
        assert_eq!(b.busy(&a), Some(0.5));
    }

    #[test]
    fn a_reboot_does_not_produce_an_absurd_figure() {
        // After a reboot the counters restart from zero: the subtraction would
        // overflow, and a `wrapping_sub` would give a nonsensical rate.
        let before = CpuReading {
            total: 1_000_000,
            idle: 900_000,
        };
        let after = CpuReading {
            total: 500,
            idle: 400,
        };
        assert_eq!(after.busy(&before), None);
    }

    #[test]
    fn two_identical_readings_yield_nothing_rather_than_idle() {
        // No elapsed time: we know nothing. "0 %" would say "idle".
        let a = CpuReading {
            total: 1000,
            idle: 800,
        };
        assert_eq!(a.busy(&a), None);
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
        assert_eq!(r.idle, 850, "idle + iowait");
    }

    #[test]
    fn iowait_counts_as_idle() {
        // The CPU is waiting on a disk there: it is not busy. Counting it as work
        // would make a machine waiting on its NAS look saturated.
        let without = parse_cpu("cpu  100 0 0 900 0 0 0 0\n").expect("reading");
        let with = parse_cpu("cpu  100 0 0 400 500 0 0 0\n").expect("reading");
        assert_eq!(without.idle, with.idle);
    }

    #[test]
    fn a_missing_proc_file_yields_nothing_rather_than_zero() {
        assert_eq!(parse_cpu(""), None);
        assert_eq!(parse_cpu("intr 12345\n"), None);
        assert_eq!(parse_cpu("cpu  1 2\n"), None, "not enough fields");
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
        assert_eq!(v[0].name, "eth0");
        assert_eq!(v[0].rx_bytes, 1234);
        assert_eq!(v[0].tx_bytes, 5678);
    }

    #[test]
    fn load_is_comparable_only_once_divided_by_cores() {
        // 🔴 A load of 4 is dramatic on one core and comfortable on sixteen. A homelab
        // is made of heterogeneous machines: the raw value side by side means
        // nothing.
        let c = LoadAverage {
            one_min: 4.0,
            five_min: 3.0,
            fifteen_min: 2.0,
        };
        assert_eq!(c.per_core(1), Some(4.0));
        assert_eq!(c.per_core(16), Some(0.25));
        assert_eq!(c.per_core(0), None, "no division by zero");
    }

    #[test]
    fn the_distribution_name_is_read_without_its_quotes() {
        let os = "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\n";
        assert_eq!(
            pretty_name(os).as_deref(),
            Some("Debian GNU/Linux 12 (bookworm)")
        );
        assert_eq!(pretty_name("ID=debian\n"), None);
        assert_eq!(
            pretty_name("PRETTY_NAME=\"\"\n"),
            None,
            "empty means absent"
        );
    }
}
