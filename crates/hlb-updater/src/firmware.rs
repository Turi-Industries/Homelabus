//! What each machine's firmware could move to, as fwupd says it — read daily, never
//! applied. A firmware update is a person's, at the machine: a capsule changes what the
//! next boot measures, and a disk the TPM opens then waits for the emergency kit's key.
//!
//! The host is reached as the reboot probe reaches it (`reboot::host_job`): a job in the
//! host's namespaces, no SSH. fwupd is asked with every `--no-*`, so reading downloads
//! nothing, enables no remote and sends no report.

use hlb_orchestrator::{JobOutcome, NodeInfo, ServiceSpec};
use hlb_state::FirmwareUpdate;
use serde_json::Value;

/// How old LVFS's metadata may be before "nothing to update" means "nothing known":
/// fwupd's own refresh timer runs daily, so a month is a timer that stopped.
pub const METADATA_DAYS: i64 = hlb_bootstrap::protection::DBX_METADATA_DAYS;

/// How long the job is waited for: a pull of the CLI image on a slow line included.
pub const JOB_TIMEOUT_S: u64 = crate::reboot::JOB_TIMEOUT_S;

const REMOTES: &str = "@@remotes";
const UPDATES: &str = "@@updates";
/// The last line: a log cut at the job's ceiling has none, and is no reading.
const END: &str = "@@end";

/// Exec form all the way, as the reboot's: one argument to the host's `sh`.
fn script() -> String {
    format!(
        "if ! command -v fwupdmgr >/dev/null 2>&1; then \
           echo \"virt=$(systemd-detect-virt 2>/dev/null)\"; echo fwupd=absent; echo {END}; exit 0; \
         fi; \
         echo \"now=$(date +%s)\"; \
         echo {REMOTES}; fwupdmgr get-remotes --json 2>/dev/null; \
         echo {UPDATES}; fwupdmgr get-updates --no-metadata-check --no-remote-check \
           --no-unreported-check --json 2>/dev/null; \
         echo {END}"
    )
}

/// The job asking `node`'s fwupd what its firmware could move to.
pub fn job(node: &NodeInfo) -> ServiceSpec {
    crate::reboot::host_job(node, "firmware", false, &script())
}

/// Reads the job: the updates fwupd offers, or why they are not known.
///
/// 🔴 `get-updates` answers `{"Devices": []}`, exit 0, over metadata never downloaded:
/// "nothing to update" is believed only beside LVFS's metadata, fresh. And a virtual
/// machine without fwupd has no firmware of its own to read — the hypervisor's is its
/// host's — where a physical one without it is firmware nobody reads.
pub fn read(out: &JobOutcome) -> Result<Vec<FirmwareUpdate>, String> {
    if !out.succeeded {
        return Err(format!(
            "the job failed: {}",
            crate::grype::tail(&out.output)
        ));
    }
    let lines: Vec<&str> = out.output.iter().map(|l| l.trim_end()).collect();
    if !lines.contains(&END) {
        return Err("fwupd's answer was cut short".into());
    }
    let value = |key: &str| {
        lines
            .iter()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(str::trim)
    };
    if value("fwupd") == Some("absent") {
        return match value("virt") {
            Some(v) if !v.is_empty() && v != "none" => Ok(Vec::new()),
            _ => Err("fwupd is not installed: the firmware is read by nothing \
                      (`apt install fwupd`)"
                .into()),
        };
    }
    let section = |from: &str, to: &str| -> Option<Value> {
        let start = lines.iter().position(|l| *l == from)? + 1;
        let end = start + lines[start..].iter().position(|l| *l == to)?;
        serde_json::from_str(&lines[start..end].join("\n")).ok()
    };
    let updates = parse_updates(section(UPDATES, END))?;
    if !updates.is_empty() {
        return Ok(updates);
    }
    let now = value("now").and_then(|n| n.parse::<i64>().ok());
    metadata_fresh(section(REMOTES, UPDATES), now)?;
    Ok(updates)
}

/// Each device `get-updates` lists, at the newest release it offers. `Err` where the
/// answer has no `Devices` list: not the same as an empty one.
fn parse_updates(v: Option<Value>) -> Result<Vec<FirmwareUpdate>, String> {
    let devices = v
        .as_ref()
        .and_then(|v| v.get("Devices")?.as_array().cloned())
        .ok_or("fwupd's updates could not be read")?;
    let mut out: Vec<FirmwareUpdate> = devices
        .iter()
        .filter_map(|d| {
            let text = |v: &Value, k: &str| v.get(k)?.as_str().map(str::to_string);
            // Listed oldest first (measured: the dbx's 20260402 before its 20260707).
            let newest = d
                .get("Releases")?
                .as_array()?
                .iter()
                .filter(|r| text(r, "Version").is_some())
                .max_by(|a, b| {
                    version_key(&text(a, "Version").unwrap_or_default())
                        .cmp(&version_key(&text(b, "Version").unwrap_or_default()))
                })?;
            Some(FirmwareUpdate {
                device: text(d, "Name").unwrap_or_else(|| "a device".into()),
                version: text(d, "Version").unwrap_or_default(),
                latest: text(newest, "Version")?,
                urgency: text(newest, "Urgency").filter(|u| u != "unknown"),
            })
        })
        .collect();
    out.sort_by(|a, b| a.device.cmp(&b.device));
    Ok(out)
}

/// `1.10` after `1.9`, and `20260707` after `20260402`: each dotted part a number where
/// it is one.
fn version_key(v: &str) -> Vec<(u64, String)> {
    v.split('.')
        .map(|p| (p.parse().unwrap_or(0), p.to_string()))
        .collect()
}

/// Whether LVFS's metadata is there, and recent enough to believe an empty list.
fn metadata_fresh(remotes: Option<Value>, now: Option<i64>) -> Result<(), String> {
    let lvfs = remotes
        .as_ref()
        .and_then(|r| r.get("Remotes")?.as_array())
        .and_then(|r| {
            r.iter()
                .find(|r| r.get("Id").and_then(Value::as_str) == Some("lvfs"))
        })
        .ok_or("fwupd has no LVFS remote: nothing says what is newer")?;
    if lvfs.get("Enabled").and_then(Value::as_bool) != Some(true) {
        return Err("fwupd's LVFS remote is disabled: nothing says what is newer".into());
    }
    let mtime = lvfs
        .get("Mtime")
        .and_then(Value::as_i64)
        .filter(|m| *m > 0)
        .ok_or("LVFS's metadata was never downloaded (`fwupdmgr refresh`)")?;
    let now = now.ok_or("the machine's clock could not be read")?;
    let days = (now - mtime) / 86_400;
    if days > METADATA_DAYS {
        return Err(format!(
            "LVFS's metadata is {days} days old: fwupd's refresh timer stopped \
             (`systemctl enable --now fwupd-refresh.timer`)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REMOTES_FRESH: &str =
        r#"{"Remotes": [{"Id": "lvfs", "Enabled": true, "Mtime": 1793300000}]}"#;
    const NOW: &str = "now=1793400000";

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

    fn answered(remotes: &str, updates: &str) -> JobOutcome {
        outcome(&[NOW, REMOTES, remotes, UPDATES, updates, END])
    }

    #[test]
    fn each_device_is_offered_its_newest_release() {
        let updates = read(&answered(
            REMOTES_FRESH,
            include_str!("../../hlb-bootstrap/tests/data/fwupd-updates-dbx.json"),
        ))
        .expect("read");
        assert_eq!(
            updates,
            vec![FirmwareUpdate {
                device: "UEFI dbx".into(),
                version: "20250902".into(),
                latest: "20260707".into(),
                urgency: None,
            }]
        );
        assert!(version_key("1.10") > version_key("1.9"));
    }

    #[test]
    fn nothing_to_update_is_believed_only_beside_fresh_metadata() {
        let none = include_str!("../../hlb-bootstrap/tests/data/fwupd-updates-none.json");
        assert_eq!(read(&answered(REMOTES_FRESH, none)), Ok(Vec::new()));
        // 🔴 This desktop's real answer: an empty list over metadata never downloaded.
        let never = read(&answered(
            include_str!("../../hlb-bootstrap/tests/data/fwupd-remotes.json"),
            none,
        ))
        .expect_err("unknown");
        assert!(never.contains("never downloaded"), "{never}");
        let old = r#"{"Remotes": [{"Id": "lvfs", "Enabled": true, "Mtime": 1780000000}]}"#;
        let stale = read(&answered(old, none)).expect_err("stale");
        assert!(stale.contains("155 days old"), "{stale}");
    }

    #[test]
    fn this_desktop_s_real_answer_reads_as_unknown() {
        // The job's script run on a desktop (fwupd 2.1.9), 2026-11-08: four remotes, LVFS's
        // metadata never downloaded, no device listed.
        let real = outcome(&[include_str!("../tests/data/fwupd-job-desktop.txt")]);
        let why = read(&real).expect_err("unknown");
        assert!(why.contains("never downloaded"), "{why}");
    }

    #[test]
    fn an_answer_cut_short_or_unreadable_is_no_reading() {
        let cut = outcome(&[NOW, REMOTES, REMOTES_FRESH, UPDATES, r#"{"Devices": ["#]);
        assert!(read(&cut).is_err());
        assert!(read(&answered(REMOTES_FRESH, "")).is_err());
        let failed = JobOutcome {
            succeeded: false,
            output: vec!["no such image".into()],
        };
        assert!(read(&failed).expect_err("failed").contains("no such image"));
    }

    #[test]
    fn a_physical_machine_without_fwupd_is_unread_and_a_virtual_one_has_none() {
        let absent = |virt: &str| outcome(&[&format!("virt={virt}"), "fwupd=absent", END]);
        assert_eq!(read(&absent("kvm")), Ok(Vec::new()));
        assert!(read(&absent("none"))
            .expect_err("unread")
            .contains("not installed"));
        // systemd-detect-virt missing says nothing: not proof of a virtual machine.
        assert!(read(&absent("")).is_err());
    }

    #[test]
    fn reading_asks_fwupd_to_download_nothing() {
        let s = script();
        for flag in [
            "--no-metadata-check",
            "--no-remote-check",
            "--no-unreported-check",
        ] {
            assert!(s.contains(flag), "{flag}");
        }
        for verb in ["refresh", " update ", "install"] {
            assert!(!s.contains(verb), "{verb}");
        }
    }
}
