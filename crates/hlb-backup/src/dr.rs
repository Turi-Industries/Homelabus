//! Disaster recovery: moving PostgreSQL onto a small node.
//!
//! ## The scenario
//!
//! `big-01` is dead — motherboard, disk, flood. It is the only `heavy` node, so
//! PostgreSQL has nowhere to go: the `node.labels.tier==heavy` placement constraint no
//! longer matches anything, and Swarm leaves the service pending indefinitely, without
//! an error.
//!
//! Degraded mode means accepting a **smaller** PostgreSQL on a `light` node: less
//! memory, fewer connections, slower — but running.
//!
//! Target: **RTO ≈ 20 min**, degraded but functional service.
//!
//! ## 🔴 What this procedure does NOT do
//!
//! It **does not run on its own**, and that is deliberate.
//!
//! An automatic switchover on failure detection is the best way to lose data: a node
//! unreachable for two minutes (a reboot, a network cable) does not mean it is dead. A
//! promotion triggered while the old primary is still alive gives **two PostgreSQL
//! writing** — a "split-brain". The two datasets diverge, and reconciling them
//! afterwards means choosing which transactions to lose.
//!
//! So this module computes a plan, says what will be degraded, and waits for a human
//! decision.
//!
//! ## 🔴 The reduced profile is not a preference, it is a constraint
//!
//! PostgreSQL starts with `shared_buffers` defaulting to 128 MB, but the official image
//! often lets it climb higher depending on the configuration. On a 4 GB node already
//! running other services, a PostgreSQL configured for 32 GB gets killed by the OOM
//! killer — sometimes immediately, sometimes three days later under load. That is worse
//! than a clean refusal: the service looks like it came back.

use crate::Result;

/// The resource profile of a PostgreSQL instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// A `heavy` node: normal operation.
    Normal,
    /// A `light` node as a fallback: what fits in 4 GB shared.
    Minimal,
}

impl Profile {
    /// Chooses the profile from the host node's memory.
    ///
    /// Where the `heavy` tier starts: `hlb_types::swarm::HEAVY_TIER_MIN_MB`, held to it by
    /// `the_drill_s_profile_turns_where_the_heavy_tier_starts`.
    pub fn for_memory(mb: u64) -> Self {
        if mb >= 7168 {
            Self::Normal
        } else {
            Self::Minimal
        }
    }

    /// The corresponding `postgresql.conf` settings.
    ///
    /// ⚠️ A low `max_connections` **requires** a PgBouncer in front: without one, an app
    /// opening its usual pool of 20 connections exhausts the 50 available by the third
    /// app, and the ones after fail on "too many clients".
    pub fn settings(&self) -> Vec<(&'static str, &'static str)> {
        match self {
            Self::Normal => vec![
                ("shared_buffers", "2GB"),
                ("work_mem", "32MB"),
                ("maintenance_work_mem", "512MB"),
                ("max_connections", "200"),
                ("effective_cache_size", "6GB"),
            ],
            Self::Minimal => vec![
                // 🔴 512 MB and no more: the node has 4 GB and runs other things.
                ("shared_buffers", "512MB"),
                ("work_mem", "8MB"),
                ("maintenance_work_mem", "128MB"),
                // ⚠️ Requires PgBouncer in front, or the 3rd app gets no connection and
                // fails on "too many clients".
                ("max_connections", "50"),
                ("effective_cache_size", "1GB"),
            ],
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Minimal => "reduced (degraded mode)",
        }
    }

    /// What the user loses when degraded.
    pub fn tradeoffs(&self) -> Vec<&'static str> {
        match self {
            Self::Normal => Vec::new(),
            Self::Minimal => vec![
                "analytical queries markedly slower (work_mem divided by 4)",
                "50 connections instead of 200 — PgBouncer becomes MANDATORY",
                "reindexing and VACUUM slower (maintenance_work_mem reduced)",
                "no margin: a second heavy app on this node will bring it down",
            ],
        }
    }
}

/// Why a promotion cannot take place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocked {
    /// 🔴 The old primary still answers.
    PrimaryStillAlive { node: String },
    /// No base backup: there is nothing to restore.
    NoBaseBackup,
    /// The host node has not enough memory, even degraded.
    NotEnoughMemory {
        node: String,
        mb: u64,
        needed_mb: u64,
    },
    /// The host node is not reachable.
    TargetUnreachable { node: String },
}

impl Blocked {
    pub fn describe(&self) -> String {
        match self {
            Self::PrimaryStillAlive { node } => format!(
                "🔴 {node} still answers. Promoting now would give TWO PostgreSQL \
                 writing, and the two datasets would diverge. Stop the old primary for \
                 good first: docker node update --availability drain {node}"
            ),
            Self::NoBaseBackup => "🔴 no base backup: there is nothing to restore. WAL \
                 journals alone do not rebuild a database."
                .to_string(),
            Self::NotEnoughMemory {
                node,
                mb,
                needed_mb,
            } => format!(
                "🔴 {node} only has {mb} MB, at least {needed_mb} are needed even on \
                 the reduced profile. A PostgreSQL that starts then gets killed by the \
                 OOM is worse than a clean refusal: the service looks like it came back."
            ),
            Self::TargetUnreachable { node } => {
                format!("🔴 {node} does not answer — we do not fail over into the unknown.")
            }
        }
    }
}

/// Minimum memory for a PostgreSQL, even reduced.
///
/// Below that, `shared_buffers=512MB` plus the connections plus the system do not fit,
/// and the OOM killer steps in under the first real load.
pub const MIN_MEMORY_MB: u64 = 2048;

/// What a promotion would do.
#[derive(Debug, Clone)]
pub struct Plan {
    pub target_node: String,
    pub profile: Profile,
    /// Base backup to restore.
    pub base_backup: String,
    /// The instant up to which the journals allow replay.
    pub recover_to: i64,
    /// Apps that will come back up.
    pub apps_resumed: Vec<String>,
    /// 🔴 Apps put on hold: they do not fit in the reduced profile.
    pub apps_paused: Vec<String>,
}

impl Plan {
    pub fn describe(&self) -> String {
        let mut s = format!(
            "Promoting PostgreSQL on {} with the {} profile\n",
            self.target_node,
            self.profile.describe()
        );
        s.push_str(&format!(
            "  base     : {} (replay up to {})\n",
            self.base_backup,
            crate::pitr::iso8601(self.recover_to)
        ));
        s.push_str(&format!("  resumed  : {}\n", list(&self.apps_resumed)));
        s.push_str(&format!("  on hold  : {}\n", list(&self.apps_paused)));
        s
    }
}

fn list(v: &[String]) -> String {
    if v.is_empty() {
        "none".to_string()
    } else {
        v.join(", ")
    }
}

/// A node that is a candidate to host.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub node: String,
    pub memory_mb: u64,
    pub reachable: bool,
}

/// Computes the promotion plan, or says why it is impossible.
///
/// `primary_alive` comes from a real observation of the cluster, not from an assumption:
/// it is the safeguard against split-brain.
#[allow(clippy::result_large_err)]
pub fn plan_promotion(
    target: &Candidate,
    primary: Option<&str>,
    primary_alive: bool,
    bases: &[crate::pitr::BaseBackup],
    wal_coverage: Option<i64>,
    apps: &[(String, bool)],
) -> std::result::Result<Plan, Blocked> {
    // 🔴 In this order: split-brain is checked BEFORE everything else. Discovering the
    // old primary is alive after restoring a database would be too late.
    if primary_alive {
        return Err(Blocked::PrimaryStillAlive {
            node: primary.unwrap_or("the old primary").to_string(),
        });
    }
    if !target.reachable {
        return Err(Blocked::TargetUnreachable {
            node: target.node.clone(),
        });
    }
    if target.memory_mb < MIN_MEMORY_MB {
        return Err(Blocked::NotEnoughMemory {
            node: target.node.clone(),
            mb: target.memory_mb,
            needed_mb: MIN_MEMORY_MB,
        });
    }

    let last = bases
        .iter()
        .max_by_key(|b| b.finished_at)
        .ok_or(Blocked::NoBaseBackup)?;

    // The WAL coverage can reach further than the last base; otherwise we stop at the
    // base itself. We never announce more than we have.
    let recover_to = wal_coverage
        .filter(|c| *c >= last.finished_at)
        .unwrap_or(last.finished_at);

    let profile = Profile::for_memory(target.memory_mb);

    // On the reduced profile, apps declared hungry stay on hold: bringing them back
    // would exhaust the 50 connections and take the others down with them.
    let (paused, resumed): (Vec<_>, Vec<_>) = apps
        .iter()
        .partition(|(_, heavy)| *heavy && profile == Profile::Minimal);

    Ok(Plan {
        target_node: target.node.clone(),
        profile,
        base_backup: last.id.clone(),
        recover_to,
        apps_resumed: resumed.into_iter().map(|(n, _)| n.clone()).collect(),
        apps_paused: paused.into_iter().map(|(n, _)| n.clone()).collect(),
    })
}

/// The settings to write, ready to apply.
pub fn render_settings(p: Profile) -> Result<String> {
    let mut s = String::from("# Generated by Homelabus — PostgreSQL resource profile.\n");
    if p == Profile::Minimal {
        s.push_str(
            "# 🔴 DEGRADED MODE. These values fit a \"light\" node that is already\n\
             # running other things. Raising them will get PostgreSQL killed by the OOM\n\
             # killer — sometimes right away, sometimes three days later.\n\
             #\n\
             # ⚠️ max_connections=50 REQUIRES a PgBouncer in front: without one, the\n\
             # third app gets no connection and fails on \"too many clients\".\n",
        );
    }
    for (k, v) in p.settings() {
        s.push_str(&format!("{k} = {v}\n"));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pitr::BaseBackup;

    const J0: i64 = 1_786_881_600;

    fn bases() -> Vec<BaseBackup> {
        vec![
            BaseBackup {
                id: "base-1".into(),
                finished_at: J0,
            },
            BaseBackup {
                id: "base-2".into(),
                finished_at: J0 + 3600,
            },
        ]
    }

    fn small() -> Candidate {
        Candidate {
            node: "small-01".into(),
            memory_mb: 4096,
            reachable: true,
        }
    }

    fn apps() -> Vec<(String, bool)> {
        vec![
            ("vaultwarden".into(), false),
            ("gitea".into(), true),
            ("vikunja".into(), false),
        ]
    }

    #[test]
    fn a_live_primary_blocks_everything() {
        // 🔴 THE safeguard. Two PostgreSQL writing means two datasets diverging — and
        // reconciling afterwards means choosing which transactions to lose.
        let e =
            plan_promotion(&small(), Some("big-01"), true, &bases(), None, &apps()).unwrap_err();

        assert_eq!(
            e,
            Blocked::PrimaryStillAlive {
                node: "big-01".into()
            }
        );
        assert!(e.describe().contains("TWO PostgreSQL"), "{}", e.describe());
        // The message must say WHAT TO DO, not only observe.
        assert!(e.describe().contains("drain"), "{}", e.describe());
    }

    #[test]
    fn the_split_brain_check_comes_first() {
        // Even with no base backup and an unreachable node, it is split-brain that must
        // be reported: discovering the old primary is alive AFTER restoring would be too
        // late.
        let unreachable = Candidate {
            reachable: false,
            ..small()
        };
        let e = plan_promotion(&unreachable, Some("big-01"), true, &[], None, &[]).unwrap_err();
        assert!(matches!(e, Blocked::PrimaryStillAlive { .. }), "{e:?}");
    }

    #[test]
    fn a_node_too_small_is_refused_rather_than_killed_later() {
        // 🔴 A PostgreSQL that starts then gets killed by the OOM is worse than a
        // refusal: the service looks like it came back.
        let minuscule = Candidate {
            memory_mb: 1024,
            ..small()
        };
        let e = plan_promotion(&minuscule, None, false, &bases(), None, &apps()).unwrap_err();

        assert!(matches!(e, Blocked::NotEnoughMemory { .. }), "{e:?}");
        assert!(e.describe().contains("OOM"), "{}", e.describe());
    }

    #[test]
    fn wal_alone_promotes_nothing() {
        let e = plan_promotion(&small(), None, false, &[], Some(J0), &apps()).unwrap_err();
        assert_eq!(e, Blocked::NoBaseBackup);
    }

    #[test]
    fn a_small_node_gets_the_reduced_profile() {
        let p = plan_promotion(&small(), None, false, &bases(), None, &apps()).expect("plan");
        assert_eq!(p.profile, Profile::Minimal);
        assert_eq!(p.base_backup, "base-2", "the MOST RECENT base");
    }

    #[test]
    fn a_big_node_keeps_the_normal_profile() {
        let big = Candidate {
            node: "big-02".into(),
            memory_mb: 32768,
            reachable: true,
        };
        let p = plan_promotion(&big, None, false, &bases(), None, &apps()).expect("plan");
        assert_eq!(p.profile, Profile::Normal);
        // Nothing is put on hold: the node carries the load.
        assert!(p.apps_paused.is_empty(), "{:?}", p.apps_paused);
    }

    #[test]
    fn heavy_apps_stay_paused_in_degraded_mode() {
        // 🔴 Bringing them back would exhaust the 50 connections and take the others
        // down with them — a degraded mode that degrades everything is pointless.
        let p = plan_promotion(&small(), None, false, &bases(), None, &apps()).expect("plan");
        assert_eq!(p.apps_paused, vec!["gitea"]);
        assert_eq!(p.apps_resumed, vec!["vaultwarden", "vikunja"]);
    }

    #[test]
    fn the_recovery_point_never_claims_more_than_the_wal_covers() {
        // Without WAL coverage we stop at the base: announcing more would promise a
        // replay we cannot perform.
        let p = plan_promotion(&small(), None, false, &bases(), None, &apps()).expect("plan");
        assert_eq!(p.recover_to, J0 + 3600);

        // With journals reaching further, we take advantage of them.
        let p = plan_promotion(&small(), None, false, &bases(), Some(J0 + 7200), &apps())
            .expect("plan");
        assert_eq!(p.recover_to, J0 + 7200);

        // Coverage EARLIER than the base is ignored: it is of no use.
        let p =
            plan_promotion(&small(), None, false, &bases(), Some(J0 - 100), &apps()).expect("plan");
        assert_eq!(p.recover_to, J0 + 3600);
    }

    #[test]
    fn the_reduced_profile_fits_a_small_node() {
        let s = Profile::Minimal.settings();
        let sb = s
            .iter()
            .find(|(k, _)| *k == "shared_buffers")
            .expect("shared_buffers");
        assert_eq!(sb.1, "512MB");

        let mc = s
            .iter()
            .find(|(k, _)| *k == "max_connections")
            .expect("max_connections");
        assert_eq!(mc.1, "50");
    }

    #[test]
    fn the_degraded_settings_warn_about_pgbouncer() {
        // ⚠️ Without PgBouncer the 3rd app gets no connection and fails on "too many
        // clients" — a failure that does not look like a shortage of RAM.
        let s = render_settings(Profile::Minimal).expect("rendered");
        assert!(s.contains("PgBouncer"), "{s}");
        assert!(s.contains("DEGRADED MODE"), "{s}");
        assert!(s.contains("OOM"), "{s}");
    }

    #[test]
    fn the_normal_settings_carry_no_warning() {
        let s = render_settings(Profile::Normal).expect("rendered");
        assert!(!s.contains("DEGRADED"), "{s}");
        assert!(s.contains("shared_buffers = 2GB"), "{s}");
    }

    #[test]
    fn the_tradeoffs_are_spelled_out() {
        // The user must know what they lose BEFORE confirming, not discover it after.
        let t = Profile::Minimal.tradeoffs();
        assert!(!t.is_empty());
        assert!(t.iter().any(|x| x.contains("PgBouncer")), "{t:?}");
        assert!(Profile::Normal.tradeoffs().is_empty());
    }

    #[test]
    fn the_profile_threshold_matches_the_tier_rule() {
        // What an 8 GB machine reports is "heavy".
        assert_eq!(Profile::for_memory(8192), Profile::Normal);
        assert_eq!(Profile::for_memory(7168), Profile::Normal);
        assert_eq!(Profile::for_memory(7167), Profile::Minimal);
        assert_eq!(Profile::for_memory(4096), Profile::Minimal);
    }
}
