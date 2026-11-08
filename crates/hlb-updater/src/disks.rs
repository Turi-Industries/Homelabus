//! Each machine's disks, as SMART says them, and its ZFS pools, as `zpool status` does —
//! read daily, nothing repaired and nothing scheduled. A pool's scrub is the
//! distribution's own timer (Debian's `zfsutils-linux` runs one the second Sunday of the
//! month): what is read here is whether it ran.
//!
//! The host is reached as the reboot probe reaches it (`reboot::host_job`): `smartctl`
//! needs the raw device, which only the host's namespaces open.

use chrono::{FixedOffset, NaiveDateTime, TimeZone};
use hlb_orchestrator::{JobOutcome, NodeInfo, ServiceSpec};
use hlb_state::{Disk, ZPool};
use serde_json::Value;

/// How long the job is waited for: a pull of the CLI image on a slow line included.
pub const JOB_TIMEOUT_S: u64 = crate::reboot::JOB_TIMEOUT_S;

/// How old a pool's last scrub may be. Debian scrubs the second Sunday of each month, so
/// two scrubs can be 37 days apart (the 8th, then the 14th of the next month), and the
/// scrub itself takes hours: five weeks would cry wolf every few months.
pub const SCRUB_DAYS: i64 = 42;

const SCAN: &str = "@@scan";
const DISK: &str = "@@disk ";
const POOLS: &str = "@@pools";
const POOL: &str = "@@pool ";
/// The last line: a log cut at the job's ceiling has none, and is no reading.
const END: &str = "@@end";

/// Exec form all the way, as the reboot's: one argument to the host's `sh`.
///
/// One compact JSON line per disk (`--json=c`): pretty-printed, an ATA disk's attributes
/// run to hundreds of lines, and a job's log is read back to 2,000. `-i -H -A` and not
/// `-a`, whose logs say nothing read here. `LC_ALL=C`: the scrub's date is parsed.
fn script() -> String {
    [
        "echo \"virt=$(systemd-detect-virt 2>/dev/null)\"; echo \"tz=$(date +%z)\";",
        "if command -v smartctl >/dev/null 2>&1; then",
        &format!("  echo {SCAN}; smartctl --scan-open 2>&1;"),
        "  smartctl --scan-open 2>/dev/null | while read -r dev flag kind rest; do",
        &format!(
            "    case \"$dev\" in /dev/*) echo \"{DISK}$dev\"; \
             smartctl -i -H -A --json=c -d \"$kind\" \"$dev\" 2>/dev/null; echo;; esac;"
        ),
        "  done;",
        "else echo smartctl=absent; fi;",
        "if command -v zpool >/dev/null 2>&1; then",
        &format!("  echo {POOLS}; zpool list -H -p -o name,health,free 2>&1;"),
        "  for p in $(zpool list -H -o name 2>/dev/null); do",
        &format!(
            "    echo \"{POOL}$p\"; LC_ALL=C zpool status \"$p\" 2>&1 \
             | sed -n -e 's/^ *scan: /scan: /p' -e 's/^ *errors: /errors: /p';"
        ),
        "  done;",
        "fi;",
        &format!("echo {END}"),
    ]
    .join("\n")
}

/// The job reading `node`'s disks and pools.
pub fn job(node: &NodeInfo) -> ServiceSpec {
    crate::reboot::host_job(node, "disks", false, &script())
}

/// What one reading found.
#[derive(Debug, Default, PartialEq)]
pub struct Reading {
    pub disks: Vec<Disk>,
    pub pools: Vec<ZPool>,
}

/// Reads the job.
///
/// A virtual machine's disks answer no SMART — they are files on its host — so finding
/// none there, or no `smartctl`, is no fault; on a physical machine either is disks
/// nobody reads.
pub fn read(out: &JobOutcome) -> Result<Reading, String> {
    if !out.succeeded {
        return Err(format!(
            "the job failed: {}",
            crate::grype::tail(&out.output)
        ));
    }
    let lines: Vec<&str> = out.output.iter().map(|l| l.trim_end()).collect();
    if !lines.contains(&END) {
        return Err("the disks' reading was cut short".into());
    }
    let value = |key: &str| {
        lines
            .iter()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(str::trim)
    };
    let physical = matches!(value("virt"), Some("none") | Some("") | None);
    let tz = value("tz").and_then(|z| FixedOffset::east_opt(offset_seconds(z)?));

    let mut reading = Reading::default();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line == SCAN {
            // A disk the scan names and could not open is written `# /dev/sdb …`: kept,
            // with its reason, never dropped from the list.
            while let Some(l) = lines.get(i + 1).filter(|l| !l.starts_with("@@")) {
                if let Some(rest) = l.strip_prefix("# /dev/") {
                    let device = format!("/dev/{}", rest.split_whitespace().next().unwrap_or(""));
                    let why = rest.rsplit(", ").next().unwrap_or(rest).trim();
                    reading.disks.push(Disk {
                        device,
                        error: Some(why.to_string()),
                        ..Disk::default()
                    });
                }
                i += 1;
            }
        } else if let Some(device) = line.strip_prefix(DISK) {
            let json = lines.get(i + 1).copied().unwrap_or("");
            reading.disks.push(disk(device, json));
            i += 1;
        } else if line == POOLS {
            let start = i + 1;
            while lines.get(i + 1).is_some_and(|l| !l.starts_with("@@")) {
                i += 1;
            }
            let listed = lines[start..i + 1].join("\n");
            reading.pools = hlb_bootstrap::zfs::parse_pools(&listed)
                .into_iter()
                .map(|p| ZPool {
                    name: p.name,
                    health: p.health,
                    ..ZPool::default()
                })
                .collect();
        } else if let Some(name) = line.strip_prefix(POOL) {
            while let Some(l) = lines.get(i + 1).filter(|l| !l.starts_with("@@")) {
                if let Some(pool) = reading.pools.iter_mut().find(|p| p.name == name) {
                    if let Some(scan) = l.strip_prefix("scan: ") {
                        pool.scan = scan.trim().to_string();
                        (pool.scrubbed_at, pool.scrubbing) = scrub(scan, tz);
                    } else if let Some(errors) = l.strip_prefix("errors: ") {
                        pool.data_errors = errors.trim() != "No known data errors";
                    }
                }
                i += 1;
            }
        }
        i += 1;
    }
    if value("smartctl") == Some("absent") {
        if physical {
            return Err(
                "smartmontools is not installed: the disks are read by nothing \
                        (`apt install smartmontools`)"
                    .into(),
            );
        }
    } else if physical && reading.disks.is_empty() {
        return Err(
            "smartctl found no disk: they may sit behind a controller it cannot \
                    see through"
                .into(),
        );
    }
    Ok(reading)
}

/// One disk's `smartctl -i -H -A --json=c`.
fn disk(device: &str, json: &str) -> Disk {
    let mut d = Disk {
        device: device.to_string(),
        ..Disk::default()
    };
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        d.error = Some("smartctl's answer could not be read".into());
        return d;
    };
    let text = |p: &str| v.pointer(p).and_then(Value::as_str).map(str::to_string);
    let number = |p: &str| v.pointer(p).and_then(Value::as_u64);
    // Bit 1 of smartctl's exit status: the device could not be opened.
    if number("/smartctl/exit_status").is_some_and(|s| s & 0b10 != 0) {
        let why = v
            .pointer("/smartctl/messages/0/string")
            .and_then(Value::as_str)
            .unwrap_or("smartctl could not open it");
        d.error = Some(why.to_string());
        return d;
    }
    d.model = text("/model_name");
    d.serial = text("/serial_number");
    let available = v
        .pointer("/smart_support/available")
        .and_then(Value::as_bool);
    d.passed = match available {
        Some(false) => None,
        _ => v.pointer("/smart_status/passed").and_then(Value::as_bool),
    };
    if let Some(table) = v
        .pointer("/ata_smart_attributes/table")
        .and_then(Value::as_array)
    {
        let raw = |id: u64| {
            table
                .iter()
                .find(|a| a.get("id").and_then(Value::as_u64) == Some(id))
                .and_then(|a| a.pointer("/raw/value")?.as_u64())
        };
        d.reallocated = raw(5);
        d.pending = raw(197);
        d.uncorrectable = raw(198);
    }
    if let Some(n) = number("/scsi_grown_defect_list") {
        d.reallocated = Some(n);
    }
    d.media_errors = number("/nvme_smart_health_information_log/media_errors");
    d.critical_warning = number("/nvme_smart_health_information_log/critical_warning");
    d
}

/// `+0100` as seconds east of UTC.
fn offset_seconds(z: &str) -> Option<i32> {
    let (sign, digits) = match z.as_bytes().first()? {
        b'+' => (1, &z[1..]),
        b'-' => (-1, &z[1..]),
        _ => return None,
    };
    if digits.len() != 4 {
        return None;
    }
    let h: i32 = digits[..2].parse().ok()?;
    let m: i32 = digits[2..].parse().ok()?;
    Some(sign * (h * 3600 + m * 60))
}

/// When the last scrub ended, and whether one runs, from the `scan:` line.
///
/// ZFS writes the date as `ctime` does, in the machine's local time
/// (`scrub repaired 0B in 00:00:01 with 0 errors on Sun Nov  8 00:24:02 2026`). Read with
/// today's offset: a change of summer time since is an hour, against weeks.
fn scrub(scan: &str, tz: Option<FixedOffset>) -> (Option<i64>, bool) {
    let scan = scan.trim();
    if scan.starts_with("scrub in progress") {
        return (None, true);
    }
    let Some(done) = scan.strip_prefix("scrub repaired") else {
        return (None, false);
    };
    let Some((_, date)) = done.rsplit_once(" on ") else {
        return (None, false);
    };
    let date = date.split_whitespace().collect::<Vec<_>>().join(" ");
    let at = NaiveDateTime::parse_from_str(&date, "%a %b %d %H:%M:%S %Y")
        .ok()
        .and_then(|t| tz?.from_local_datetime(&t).earliest())
        .map(|t| t.timestamp());
    (at, false)
}

/// Carries what only a comparison tells: when each disk's error counters last grew.
/// A disk is followed by its serial — `/dev/sdX` is assigned at boot — and one seen for
/// the first time has grown from nothing it was compared to.
pub fn carry(before: &[Disk], now: Vec<Disk>, at: i64) -> Vec<Disk> {
    now.into_iter()
        .map(|mut d| {
            let same = before.iter().find(|b| match (&b.serial, &d.serial) {
                (Some(x), Some(y)) => x == y,
                (None, None) => b.device == d.device,
                _ => false,
            });
            if let Some(b) = same {
                let grew = d
                    .counters()
                    .iter()
                    .zip(b.counters())
                    .any(|(n, o)| matches!((n, o), (Some(n), Some(o)) if *n > o));
                d.grew_at = if grew { Some(at) } else { b.grew_at };
            }
            d
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(lines: &[&str]) -> JobOutcome {
        JobOutcome {
            succeeded: true,
            output: lines
                .iter()
                .flat_map(|l| l.lines())
                .map(String::from)
                .collect(),
        }
    }

    /// An ATA disk with eight sectors reallocated, in smartctl 7's JSON (written from its
    /// format: no spinning disk was at hand to measure).
    const ATA: &str = r#"{"smartctl":{"exit_status":0},"device":{"name":"/dev/sda","type":"sat"},"model_name":"WDC WD40EFRX-68N32N0","serial_number":"WD-1","smart_support":{"available":true,"enabled":true},"smart_status":{"passed":true},"ata_smart_attributes":{"revision":16,"table":[{"id":5,"name":"Reallocated_Sector_Ct","value":200,"worst":200,"thresh":140,"when_failed":"","raw":{"value":8,"string":"8"}},{"id":9,"name":"Power_On_Hours","value":50,"worst":50,"thresh":0,"when_failed":"","raw":{"value":36000,"string":"36000"}},{"id":197,"name":"Current_Pending_Sector","value":200,"worst":200,"thresh":0,"when_failed":"","raw":{"value":2,"string":"2"}},{"id":198,"name":"Offline_Uncorrectable","value":200,"worst":200,"thresh":0,"when_failed":"","raw":{"value":0,"string":"0"}}]}}"#;

    #[test]
    fn this_desktop_s_real_answer_reads_four_healthy_nvme_disks() {
        // The job's script run on a desktop (smartmontools 7.5, four NVMe), 2026-11-08,
        // its serials replaced.
        let real = outcome(&[include_str!("../tests/data/smartctl-job-desktop.txt")]);
        let r = read(&real).expect("read");
        assert_eq!(r.disks.len(), 4);
        let first = &r.disks[0];
        assert_eq!(first.device, "/dev/nvme0");
        assert_eq!(first.model.as_deref(), Some("KINGSTON SNV2S1000G"));
        assert_eq!(first.serial.as_deref(), Some("SERIAL1"));
        assert_eq!(
            (first.passed, first.media_errors, first.critical_warning),
            (Some(true), Some(0), Some(0))
        );
        assert!(r.disks.iter().all(|d| !d.failing() && d.error.is_none()));
        assert!(r.pools.is_empty());
    }

    #[test]
    fn an_ata_disk_s_counters_are_its_raw_values() {
        let d = disk("/dev/sda", ATA);
        assert_eq!(
            (d.reallocated, d.pending, d.uncorrectable, d.passed),
            (Some(8), Some(2), Some(0), Some(true))
        );
        let failing = ATA.replace(r#""passed":true"#, r#""passed":false"#);
        assert!(disk("/dev/sda", &failing).failing());
    }

    #[test]
    fn a_disk_that_would_not_open_is_kept_with_its_reason() {
        let r = read(&outcome(&[
            "virt=none",
            "tz=+0100",
            SCAN,
            "/dev/sda -d sat # /dev/sda [SAT], ATA device",
            "# /dev/sdb -d scsi # /dev/sdb, SCSI device, open failed: No such device",
            "@@disk /dev/sda",
            ATA,
            "@@disk /dev/sdc",
            r#"{"smartctl":{"exit_status":2,"messages":[{"string":"Read Device Identity failed","severity":"error"}]}}"#,
            END,
        ]))
        .expect("read");
        let errors: Vec<(&str, Option<&str>)> = r
            .disks
            .iter()
            .map(|d| (d.device.as_str(), d.error.as_deref()))
            .collect();
        assert_eq!(
            errors,
            [
                ("/dev/sdb", Some("open failed: No such device")),
                ("/dev/sda", None),
                ("/dev/sdc", Some("Read Device Identity failed")),
            ]
        );
    }

    #[test]
    fn a_virtual_machine_has_no_disk_to_read_and_a_physical_one_does() {
        let vm = |virt: &str, smartctl: &str| {
            outcome(&[&format!("virt={virt}"), "tz=+0000", smartctl, END])
        };
        assert_eq!(read(&vm("kvm", "smartctl=absent")), Ok(Reading::default()));
        assert_eq!(read(&vm("kvm", SCAN)), Ok(Reading::default()));
        assert!(read(&vm("none", "smartctl=absent"))
            .expect_err("unread")
            .contains("not installed"));
        assert!(read(&vm("none", SCAN))
            .expect_err("unread")
            .contains("found no disk"));
    }

    #[test]
    fn a_pool_s_health_scrub_and_errors_are_read() {
        let r = read(&outcome(&[
            "virt=kvm",
            "tz=+0100",
            POOLS,
            "tank\tONLINE\t3841982464",
            "backup\tDEGRADED\t120000",
            "fresh\tONLINE\t1000",
            "@@pool tank",
            "scan: scrub repaired 0B in 00:00:01 with 0 errors on Sun Nov  8 00:24:02 2026",
            "errors: No known data errors",
            "@@pool backup",
            "scan: scrub in progress since Sun Nov  8 00:24:02 2026",
            "errors: 3 data errors, use '-v' for a list",
            "@@pool fresh",
            "scan: none requested",
            "errors: No known data errors",
            END,
        ]))
        .expect("read");
        let [tank, backup, fresh] = &r.pools[..] else {
            panic!("three pools: {:?}", r.pools);
        };
        // 00:24:02 at +01:00 is 23:24:02 UTC the day before.
        assert_eq!(tank.scrubbed_at, Some(1_794_093_842));
        assert!(!tank.unhealthy() && !tank.scrubbing);
        assert!(backup.unhealthy() && backup.scrubbing && backup.data_errors);
        assert_eq!((fresh.scrubbed_at, fresh.scrubbing), (None, false));
        assert_eq!(fresh.scan, "none requested");
    }

    #[test]
    fn an_answer_cut_short_or_failed_is_no_reading() {
        assert!(read(&outcome(&["virt=none", SCAN, "@@disk /dev/sda", ATA])).is_err());
        let failed = JobOutcome {
            succeeded: false,
            output: vec!["no such image".into()],
        };
        assert!(read(&failed).expect_err("failed").contains("no such image"));
    }

    #[test]
    fn a_counter_that_grows_is_dated_and_the_date_is_kept_until_it_grows_again() {
        let sda = disk("/dev/sda", ATA);
        assert_eq!(carry(&[], vec![sda.clone()], 10)[0].grew_at, None);
        let same = carry(std::slice::from_ref(&sda), vec![sda.clone()], 10);
        assert_eq!(same[0].grew_at, None);

        // The next boot named it sdb, and two more sectors moved.
        let grown = Disk {
            device: "/dev/sdb".into(),
            reallocated: Some(10),
            ..sda.clone()
        };
        let after = carry(std::slice::from_ref(&sda), vec![grown.clone()], 20);
        assert_eq!(after[0].grew_at, Some(20));
        let kept = carry(&after, vec![grown], 30);
        assert_eq!(kept[0].grew_at, Some(20));

        // Another disk under the old name is not the old disk.
        let other = Disk {
            serial: Some("WD-2".into()),
            reallocated: Some(50),
            ..sda.clone()
        };
        assert_eq!(carry(&[sda], vec![other], 40)[0].grew_at, None);
    }

    #[test]
    fn reading_writes_nothing_to_a_disk_or_a_pool() {
        let s = script();
        for verb in [
            " -t ",
            "--test",
            " -s ",
            "zpool scrub",
            "zpool clear",
            " -X",
        ] {
            assert!(!s.contains(verb), "{verb}");
        }
    }
}
