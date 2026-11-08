//! Every machine's disks and ZFS pools, as the privileged side's daily pass read them:
//! the inbox's lines. That pass says aloud what turned; this side reads the state, and
//! what stays wrong stays here until it is not.

use hlb_api::issues::{Cause, Finding};
use hlb_api::Attention;
use hlb_state::State;
use hlb_updater::disks::SCRUB_DAYS;

use crate::flaws::STALE_AFTER_S;

/// How long a counter that grew stays in the inbox: past it, a disk that stopped
/// degrading is left to its notification, and one that goes on is dated anew.
pub const GREW_SHOWN_S: i64 = 14 * 86_400;

/// A disk failing or wearing, a machine's disks not read, a pool unhealthy or unscrubbed.
pub async fn findings(state: &State, now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    for n in state.node_disks().await.unwrap_or_default() {
        let host = n.hostname.clone();
        let wearing = n
            .disks
            .iter()
            .any(|d| d.failing() || d.grew_at.is_some_and(|g| now - g <= GREW_SHOWN_S));
        if wearing {
            out.push((Cause::DiskFailing, Attention::Critical, Some(host.clone())));
        }
        // 🔴 Read is not healthy: a reading that failed, aged, or a disk that would not
        // open is a disk nobody looked at.
        let stale = n.read_at.is_none_or(|r| now - r > STALE_AFTER_S);
        if stale || n.disks.iter().any(|d| d.error.is_some()) {
            out.push((Cause::DiskUnknown, Attention::Notice, Some(host.clone())));
        }
        for p in &n.pools {
            let subject = Some(format!("{host}/{}", p.name));
            if p.unhealthy() {
                out.push((Cause::PoolUnhealthy, Attention::Critical, subject.clone()));
            }
            let old = p.scrubbed_at.is_none_or(|s| now - s > SCRUB_DAYS * 86_400);
            if old && !p.scrubbing {
                out.push((Cause::PoolNotScrubbed, Attention::Notice, subject));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_state::{Disk, ZPool};

    const DAY: i64 = 86_400;

    fn sda() -> Disk {
        Disk {
            device: "/dev/sda".into(),
            serial: Some("WD-1".into()),
            passed: Some(true),
            reallocated: Some(8),
            ..Disk::default()
        }
    }

    fn tank(scrubbed_at: Option<i64>) -> ZPool {
        ZPool {
            name: "tank".into(),
            health: "ONLINE".into(),
            scrubbed_at,
            ..ZPool::default()
        }
    }

    fn line(cause: Cause, attention: Attention, subject: &str) -> Finding {
        (cause, attention, Some(subject.into()))
    }

    #[tokio::test]
    async fn a_healthy_machine_is_silent_and_a_counter_that_grew_is_shown_two_weeks() {
        let s = State::in_memory().await.expect("state");
        let now = 100 * DAY;
        s.record_disks("deb2", now, Ok((&[sda()], &[tank(Some(now - DAY))])))
            .await
            .expect("read");
        // Eight reallocated sectors a disk came with, steady: nothing to say.
        assert!(findings(&s, now).await.is_empty());

        let grew = Disk {
            grew_at: Some(now),
            ..sda()
        };
        s.record_disks("deb2", now, Ok((&[grew], &[tank(Some(now - DAY))])))
            .await
            .expect("read");
        let wearing = line(Cause::DiskFailing, Attention::Critical, "deb2");
        assert_eq!(findings(&s, now).await, vec![wearing]);
        assert!(findings(&s, now + GREW_SHOWN_S + 1)
            .await
            .iter()
            .all(|f| f.0 != Cause::DiskFailing));
    }

    #[tokio::test]
    async fn a_failing_disk_stays_until_it_is_gone() {
        let s = State::in_memory().await.expect("state");
        let failing = Disk {
            passed: Some(false),
            ..sda()
        };
        s.record_disks("deb2", 0, Ok((&[failing], &[])))
            .await
            .expect("read");
        assert_eq!(
            findings(&s, 1).await,
            vec![line(Cause::DiskFailing, Attention::Critical, "deb2")]
        );
    }

    #[tokio::test]
    async fn disks_not_read_or_not_opened_are_unknown_never_healthy() {
        let s = State::in_memory().await.expect("state");
        let unknown = line(Cause::DiskUnknown, Attention::Notice, "deb1");
        s.record_disks("deb1", 0, Err("smartmontools is not installed"))
            .await
            .expect("failed");
        assert_eq!(findings(&s, 0).await, vec![unknown.clone()]);

        let closed = Disk {
            device: "/dev/sdb".into(),
            error: Some("open failed: No such device".into()),
            ..Disk::default()
        };
        s.record_disks("deb1", 0, Ok((&[sda(), closed], &[])))
            .await
            .expect("read");
        assert_eq!(findings(&s, 0).await, vec![unknown.clone()]);

        s.record_disks("deb1", 0, Ok((&[sda()], &[])))
            .await
            .expect("read");
        assert!(findings(&s, 0).await.is_empty());
        // Two days without a reading: what was read is no longer known.
        assert_eq!(findings(&s, STALE_AFTER_S + 1).await, vec![unknown]);
    }

    #[tokio::test]
    async fn a_pool_degraded_or_unscrubbed_is_in_the_inbox() {
        let s = State::in_memory().await.expect("state");
        let now = 100 * DAY;
        let degraded = ZPool {
            health: "DEGRADED".into(),
            ..tank(Some(now - DAY))
        };
        let never = ZPool {
            name: "backup".into(),
            ..tank(None)
        };
        let running = ZPool {
            name: "fresh".into(),
            scrubbing: true,
            ..tank(None)
        };
        s.record_disks("deb2", now, Ok((&[], &[degraded, never, running])))
            .await
            .expect("read");
        assert_eq!(
            findings(&s, now).await,
            vec![
                line(Cause::PoolUnhealthy, Attention::Critical, "deb2/tank"),
                line(Cause::PoolNotScrubbed, Attention::Notice, "deb2/backup"),
            ]
        );
        // Debian's monthly scrub can be 37 days apart: not a reason to say anything.
        s.record_disks("deb2", now, Ok((&[], &[tank(Some(now - 37 * DAY))])))
            .await
            .expect("read");
        assert!(findings(&s, now).await.is_empty());
        let later = now + 6 * DAY;
        s.record_disks("deb2", later, Ok((&[], &[tank(Some(now - 37 * DAY))])))
            .await
            .expect("read");
        assert_eq!(
            findings(&s, later).await,
            vec![line(Cause::PoolNotScrubbed, Attention::Notice, "deb2/tank")]
        );
    }
}
