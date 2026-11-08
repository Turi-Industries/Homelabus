//! The node the privileged side reboots on its own, and the house's rule for it.
//!
//! One row at most, kept here rather than in the daemon's memory: the daemon may run on
//! the very node it reboots, and comes back from that reboot with nothing else to tell it
//! that the node was left drained.

use sqlx::Row;

use crate::{Result, State};

/// Where a reboot stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootPhase {
    /// Drained, its services leaving before the command is sent.
    Draining,
    /// The command was sent; waiting for the node to come back.
    Rebooting,
    /// Given up: nothing is rebooted on its own again until `hlb node upgrade` succeeds
    /// on this node — what stopped it may stop the next one the same way.
    Stopped,
}

impl RebootPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Draining => "draining",
            Self::Rebooting => "rebooting",
            Self::Stopped => "stopped",
        }
    }

    /// 🔴 A phase this binary does not know reads as stopped: it blocks the next reboot
    /// and reaches the inbox, where "in progress" would wait on it for ever.
    fn parse(s: &str) -> Self {
        match s {
            "draining" => Self::Draining,
            "rebooting" => Self::Rebooting,
            _ => Self::Stopped,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeReboot {
    /// Swarm's id: a hostname can be given again to another machine.
    pub node_id: String,
    pub hostname: String,
    pub phase: RebootPhase,
    /// Whether the daemon drained it — and so must put it back, and only then.
    pub drained: bool,
    pub started_at: i64,
    /// When the phase began: what each wait is counted from.
    pub phase_at: i64,
    /// Why it stopped, or what the last step said.
    pub detail: Option<String>,
}

/// When the house lets its machines reboot on their own, and at what cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebootPolicy {
    /// `daily 03:00-05:00`, in the house's zone; `None`: never on its own.
    pub window: Option<String>,
    /// 🔴 Whether a node whose reboot stops apps — the only node, a manager the others
    /// are no majority without, one keeping data — is rebooted all the same, inside the
    /// window. Off unless the owner said so: each house weighs a night's downtime
    /// against a kernel waiting.
    pub accept_downtime: bool,
}

/// The window a house that never said is given.
pub const DEFAULT_REBOOT_WINDOW: &str = "daily 03:00-05:00";

const WINDOW_KEY: &str = "reboot-window";
const DOWNTIME_KEY: &str = "reboot-downtime";
/// Stored for "never", which no window parses as.
const NEVER: &str = "never";

impl State {
    /// The node being rebooted, or given up on.
    pub async fn node_reboot(&self) -> Result<Option<NodeReboot>> {
        let row = sqlx::query(
            "SELECT node_id, hostname, phase, drained, started_at, phase_at, detail
             FROM node_reboots WHERE one = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| {
            let phase: String = r.try_get("phase")?;
            Ok(NodeReboot {
                node_id: r.try_get("node_id")?,
                hostname: r.try_get("hostname")?,
                phase: RebootPhase::parse(&phase),
                drained: r.try_get::<i64, _>("drained")? != 0,
                started_at: r.try_get("started_at")?,
                phase_at: r.try_get("phase_at")?,
                detail: r.try_get("detail")?,
            })
        })
        .transpose()
    }

    /// Takes the one place for a reboot: `false` when a node already holds it, whatever
    /// its phase — one node at a time, and a stopped one blocks the rest.
    pub async fn begin_node_reboot(
        &self,
        node_id: &str,
        hostname: &str,
        phase: RebootPhase,
        drained: bool,
        at: i64,
    ) -> Result<bool> {
        let done = sqlx::query(
            "INSERT OR IGNORE INTO node_reboots
                 (one, node_id, hostname, phase, drained, started_at, phase_at)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?5)",
        )
        .bind(node_id)
        .bind(hostname)
        .bind(phase.as_str())
        .bind(drained)
        .bind(at)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Moves the reboot of `node_id` on; nothing when another node holds the place.
    pub async fn set_node_reboot_phase(
        &self,
        node_id: &str,
        phase: RebootPhase,
        at: i64,
        detail: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE node_reboots SET phase = ?2, phase_at = ?3, detail = ?4
             WHERE one = 1 AND node_id = ?1",
        )
        .bind(node_id)
        .bind(phase.as_str())
        .bind(at)
        .bind(detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Ends the reboot of `node_id`, done or taken over by a person: `true` if there
    /// was one.
    pub async fn clear_node_reboot(&self, node_id: &str) -> Result<bool> {
        let done = sqlx::query("DELETE FROM node_reboots WHERE one = 1 AND node_id = ?1")
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }

    /// The house's rule; [`DEFAULT_REBOOT_WINDOW`] and no downtime until it is set.
    pub async fn reboot_policy(&self) -> Result<RebootPolicy> {
        let window = self.setting(WINDOW_KEY).await?;
        let downtime = self.setting(DOWNTIME_KEY).await?;
        Ok(RebootPolicy {
            window: match window.as_deref() {
                None => Some(DEFAULT_REBOOT_WINDOW.to_string()),
                Some(NEVER) => None,
                Some(w) => Some(w.to_string()),
            },
            accept_downtime: downtime.as_deref() == Some("accept"),
        })
    }

    /// Records the rule. The window is the caller's to have parsed.
    pub async fn set_reboot_policy(&self, p: &RebootPolicy) -> Result<()> {
        self.put_setting(WINDOW_KEY, Some(p.window.as_deref().unwrap_or(NEVER)))
            .await?;
        let downtime = if p.accept_downtime {
            "accept"
        } else {
            "refuse"
        };
        self.put_setting(DOWNTIME_KEY, Some(downtime)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn one_node_holds_the_place_until_it_is_cleared() {
        let s = State::in_memory().await.expect("state");
        assert_eq!(s.node_reboot().await.expect("read"), None);
        assert!(s
            .begin_node_reboot("n1", "deb2", RebootPhase::Draining, true, 100)
            .await
            .expect("begin"));
        // 🔴 One at a time: a second node waits, whatever the first one's phase.
        assert!(!s
            .begin_node_reboot("n2", "deb3", RebootPhase::Rebooting, false, 200)
            .await
            .expect("refused"));

        s.set_node_reboot_phase("n2", RebootPhase::Stopped, 300, Some("not mine"))
            .await
            .expect("other");
        s.set_node_reboot_phase("n1", RebootPhase::Stopped, 300, Some("did not move"))
            .await
            .expect("stop");
        let r = s.node_reboot().await.expect("read").expect("held");
        assert_eq!(
            (
                r.hostname.as_str(),
                r.phase,
                r.drained,
                r.started_at,
                r.phase_at
            ),
            ("deb2", RebootPhase::Stopped, true, 100, 300)
        );
        assert_eq!(r.detail.as_deref(), Some("did not move"));

        assert!(!s.clear_node_reboot("n2").await.expect("other"));
        assert!(s.clear_node_reboot("n1").await.expect("clear"));
        assert_eq!(s.node_reboot().await.expect("read"), None);
    }

    #[test]
    fn a_phase_this_binary_does_not_know_blocks_rather_than_waits() {
        for p in [
            RebootPhase::Draining,
            RebootPhase::Rebooting,
            RebootPhase::Stopped,
        ] {
            assert_eq!(RebootPhase::parse(p.as_str()), p);
        }
        assert_eq!(RebootPhase::parse("paused"), RebootPhase::Stopped);
    }

    #[tokio::test]
    async fn a_house_that_never_said_reboots_at_night_and_never_at_the_cost_of_its_apps() {
        let s = State::in_memory().await.expect("state");
        let p = s.reboot_policy().await.expect("read");
        assert_eq!(p.window.as_deref(), Some(DEFAULT_REBOOT_WINDOW));
        assert!(!p.accept_downtime);

        let never = RebootPolicy {
            window: None,
            accept_downtime: true,
        };
        s.set_reboot_policy(&never).await.expect("set");
        assert_eq!(s.reboot_policy().await.expect("read"), never);
        let sunday = RebootPolicy {
            window: Some("sun 02:00-04:00".into()),
            accept_downtime: false,
        };
        s.set_reboot_policy(&sunday).await.expect("set");
        assert_eq!(s.reboot_policy().await.expect("read"), sunday);
    }
}
