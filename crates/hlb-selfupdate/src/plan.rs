//! The update sequence, and its rollback.
//!
//! ## 🔴 The golden rule
//!
//! > The controller **never** updates itself in a single step.
//! > It prepares, validates, switches, and keeps the ability to go back.
//!
//! ## Why the order is this one and not another
//!
//! ```text
//! 1. State backup              ← without it, a failure at 4 is final
//! 2. Compatibility             ← before touching anything at all
//! 3. Agents, one node at a time ← a broken agent does not break the others
//! 4. Controller                ← last: it is what drives steps 1-3
//! 5. Post-switch verification  ← otherwise nobody knows whether it worked
//! ```
//!
//! **The controller last**, because it is what executes the preceding steps. Replacing
//! itself first would be sawing off the branch: if the new version does not start,
//! nothing is left to update the agents or to go back.
//!
//! **One agent at a time**, because an unreachable agent does not stop the cluster
//! working (services run under Swarm, not under Homelabus), whereas ten broken agents
//! at once blind the supervision completely.
//!
//! ## 🔴 What makes a rollback possible - or impossible
//!
//! The binary is easy to replace. **The database schema is not.** If version N+1
//! migrates the database and you go back to binary N, it reads a schema it does not
//! understand. That is the state there is no way out of.
//!
//! Hence two non-negotiable requirements, checked by [`Preflight`]:
//!
//! - every migration has its inverse (`down`), or the update is **refused**;
//! - the state is exported before the migration, not after.

use crate::version::{compatible, Compatibility, Jump, Version};

/// A node of the fleet, with its agent's version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentNode {
    pub node: String,
    /// `None` = agent injoignable.
    pub version: Option<Version>,
}

/// What prevents starting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker {
    /// 🔴 A migration cannot be undone.
    IrreversibleMigration { name: String },
    /// Versions incompatibles.
    Incompatible { detail: String },
    /// 🔴 Some agents do not answer: no updating blind.
    UnreachableAgents { nodes: Vec<String> },
    /// No state backup: a failure would be final.
    NoStateBackup,
    /// Nothing to do.
    AlreadyCurrent,
}

impl Blocker {
    pub fn describe(&self) -> String {
        match self {
            Self::IrreversibleMigration { name } => format!(
                "🔴 migration \"{name}\" has no inverse. If the new version fails, \
                 the previous binary will read a schema it does not understand - and \
                 there will be no way back. Write the `down` first."
            ),
            Self::Incompatible { detail } => detail.clone(),
            Self::UnreachableAgents { nodes } => format!(
                "🔴 {} unreachable {}: {}. A fleet you cannot see does not get \
                 updated - silent nodes would stay on version N with no way to know \
                 whether they work.",
                nodes.len(),
                if nodes.len() == 1 { "agent" } else { "agents" },
                nodes.join(", ")
            ),
            Self::NoStateBackup => "🔴 no state backup: a failure during migration \
                 would be final. Run `hlb backup run --force` first."
                .to_string(),
            Self::AlreadyCurrent => "already up to date".to_string(),
        }
    }

    /// Is this a safety refusal, or simply "nothing to do"?
    pub fn is_refusal(&self) -> bool {
        !matches!(self, Self::AlreadyCurrent)
    }
}

/// A schema migration and its inverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    pub name: String,
    /// 🔴 `false` means no `down`. Blocks the update.
    pub reversible: bool,
}

/// Everything known before deciding.
#[derive(Debug, Clone)]
pub struct Preflight {
    pub from: Version,
    pub to: Version,
    pub agents: Vec<AgentNode>,
    pub migrations: Vec<Migration>,
    /// Has the state been backed up recently?
    pub state_backed_up: bool,
}

/// The sequence to execute.
#[derive(Debug, Clone)]
pub struct UpdatePlan {
    pub from: Version,
    pub to: Version,
    pub jump: Jump,
    /// Nodes to update, in order.
    ///
    /// ⚠️ Sorted by name: an update taking nodes in a varying order would make an
    /// incident irreproducible.
    pub agents: Vec<String>,
    pub migrations: Vec<Migration>,
}

impl UpdatePlan {
    pub fn describe(&self) -> String {
        let mut s = format!(
            "Update {} → {} ({})\n",
            self.from,
            self.to,
            self.jump.describe()
        );
        s.push_str(&format!(
            "  1. state backup\n  2. {} {}, one at a time: {}\n",
            self.agents.len(),
            if self.agents.len() == 1 {
                "agent"
            } else {
                "agents"
            },
            if self.agents.is_empty() {
                "none".to_string()
            } else {
                self.agents.join(", ")
            }
        ));
        s.push_str(&format!(
            "  3. controller LAST ({} reversible {})\n",
            self.migrations.len(),
            if self.migrations.len() == 1 {
                "migration"
            } else {
                "migrations"
            }
        ));
        s.push_str("  4. a dry-run reconciliation to check\n");
        s
    }
}

/// Decides whether the update can start, and how.
///
/// 🔴 The order of the checks matters: what makes a ROLLBACK impossible is checked
/// before what makes the update pointless. Discovering a migration is irreversible
/// after migrating would be precisely too late.
pub fn plan(p: &Preflight) -> Result<UpdatePlan, Blocker> {
    // 1. What forecloses the rollback, first.
    if let Some(m) = p.migrations.iter().find(|m| !m.reversible) {
        return Err(Blocker::IrreversibleMigration {
            name: m.name.clone(),
        });
    }

    // 2. Then what makes the operation pointless or dangerous.
    let jump = Jump::between(p.from, p.to);
    if jump == Jump::None {
        return Err(Blocker::AlreadyCurrent);
    }
    if jump == Jump::Downgrade {
        return Err(Blocker::Incompatible {
            detail: format!(
                "🔴 {} is EARLIER than {} - this is not an update. To go back, use \
                 `hlb self rollback`, which restores the schema as well.",
                p.to, p.from
            ),
        });
    }

    if !p.state_backed_up {
        return Err(Blocker::NoStateBackup);
    }

    // 3. The silent agents: a fleet you cannot see does not get updated.
    let muets: Vec<String> = p
        .agents
        .iter()
        .filter(|a| a.version.is_none())
        .map(|a| a.node.clone())
        .collect();
    if !muets.is_empty() {
        return Err(Blocker::UnreachableAgents { nodes: muets });
    }

    // 4. Chaque agent doit pouvoir parler au controller cible.
    for a in &p.agents {
        let Some(v) = a.version else { continue };
        if let Compatibility::Incompatible { reason } = compatible(v, p.to) {
            return Err(Blocker::Incompatible {
                detail: format!("{} : {reason}", a.node),
            });
        }
    }

    let mut agents: Vec<String> = p.agents.iter().map(|a| a.node.clone()).collect();
    // A stable order: an incident must be reproducible.
    agents.sort();

    Ok(UpdatePlan {
        from: p.from,
        to: p.to,
        jump,
        agents,
        migrations: p.migrations.clone(),
    })
}

/// What is kept so that going back is possible.
///
/// ⚠️ The previous binary is **kept on disk**, not re-downloaded: the day you need a
/// rollback is usually a day when something is wrong - and the network can be part of
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rollback {
    pub previous_version: Version,
    pub previous_binary: std::path::PathBuf,
    /// The state export taken before the migration.
    pub state_export: std::path::PathBuf,
    /// Migrations to undo, **in reverse order** of their application.
    pub undo: Vec<Migration>,
}

impl Rollback {
    /// The migrations to undo, in the right order.
    ///
    /// 🔴 Reverse order is mandatory: a migration adding a column referenced by the
    /// next must be undone **after** it. Undoing them in application order would fail
    /// on a constraint, halfway, leaving a schema that is neither the old nor the
    /// new.
    pub fn undo_order(&self) -> Vec<&Migration> {
        self.undo.iter().rev().collect()
    }

    pub fn describe(&self) -> String {
        format!(
            "Back to {}:\n  binary : {}\n  state  : {}\n  {} migrations to undo",
            self.previous_version,
            self.previous_binary.display(),
            self.state_export.display(),
            self.undo.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migration(nom: &str, reversible: bool) -> Migration {
        Migration {
            name: nom.into(),
            reversible,
        }
    }

    fn preflight() -> Preflight {
        Preflight {
            from: Version::new(0, 1, 0),
            to: Version::new(0, 2, 0),
            agents: vec![
                AgentNode {
                    node: "node2".into(),
                    version: Some(Version::new(0, 1, 0)),
                },
                AgentNode {
                    node: "node1".into(),
                    version: Some(Version::new(0, 1, 0)),
                },
            ],
            migrations: vec![migration("0007_truc", true)],
            state_backed_up: true,
        }
    }

    #[test]
    fn an_irreversible_migration_blocks_everything() {
        // 🔴 THE check that matters. Without a `down`, a failure of version N+1 leaves
        // the database in a state binary N does not understand - and there is no way
        // out.
        let mut p = preflight();
        p.migrations.push(migration("0008_sans_retour", false));

        let e = plan(&p).unwrap_err();
        assert_eq!(
            e,
            Blocker::IrreversibleMigration {
                name: "0008_sans_retour".into()
            }
        );
        assert!(e.describe().contains("no way back"), "{}", e.describe());
    }

    #[test]
    fn reversibility_is_checked_before_anything_else() {
        // Discovering a migration is irreversible AFTER migrating would be too late.
        // Even with an identical version and no agents, this check must speak first.
        let p = Preflight {
            to: Version::new(0, 1, 0),
            agents: vec![],
            migrations: vec![migration("x", false)],
            state_backed_up: false,
            ..preflight()
        };
        assert!(matches!(
            plan(&p).unwrap_err(),
            Blocker::IrreversibleMigration { .. }
        ));
    }

    #[test]
    fn updating_without_a_state_backup_is_refused() {
        // A failure during migration would be final.
        let p = Preflight {
            state_backed_up: false,
            ..preflight()
        };
        let e = plan(&p).unwrap_err();
        assert_eq!(e, Blocker::NoStateBackup);
        assert!(
            e.describe().contains("backup run"),
            "l'erreur doit dire quoi faire"
        );
    }

    #[test]
    fn a_mute_agent_stops_the_update() {
        // 🔴 A fleet you cannot see does not get updated: silent nodes would stay on
        // version N with no way to know whether they work.
        let mut p = preflight();
        p.agents.push(AgentNode {
            node: "node3".into(),
            version: None,
        });

        let e = plan(&p).unwrap_err();
        assert_eq!(
            e,
            Blocker::UnreachableAgents {
                nodes: vec!["node3".into()]
            }
        );
        assert!(e.describe().contains("fleet you cannot see"));
    }

    #[test]
    fn a_downgrade_is_redirected_to_rollback() {
        // 🔴 Passing it off as an update would leave the database on schema N+1 under
        // an N binary - the state there is no way out of.
        let p = Preflight {
            from: Version::new(0, 3, 0),
            to: Version::new(0, 2, 0),
            ..preflight()
        };
        let e = plan(&p).unwrap_err();
        assert!(
            e.describe().contains("hlb self rollback"),
            "{}",
            e.describe()
        );
    }

    #[test]
    fn being_current_is_not_a_refusal() {
        // "Nothing to do" must not look like "you were blocked": a failing exit code
        // would suggest a problem inside an update script.
        let p = Preflight {
            to: Version::new(0, 1, 0),
            ..preflight()
        };
        let e = plan(&p).unwrap_err();
        assert_eq!(e, Blocker::AlreadyCurrent);
        assert!(!e.is_refusal());
    }

    #[test]
    fn a_major_mismatch_names_the_node() {
        // On a ten-machine fleet, knowing WHICH one blocks saves inspecting them one
        // by one.
        let mut p = preflight();
        p.to = Version::new(1, 0, 0);
        let e = plan(&p).unwrap_err();
        assert!(e.describe().contains("node"), "{}", e.describe());
    }

    #[test]
    fn agents_are_updated_in_a_stable_order() {
        // ⚠️ A varying order would make an incident irreproducible: "it broke on the
        // third node" means nothing if the third changes.
        let p = plan(&preflight()).expect("plan");
        assert_eq!(p.agents, vec!["node1", "node2"]);
    }

    #[test]
    fn the_plan_puts_the_controller_last() {
        // 🔴 The controller executes the preceding steps. Replacing itself first would
        // be sawing off the branch: if the new version does not start, nothing is left
        // to update the agents or to go back.
        let d = plan(&preflight()).expect("plan").describe();
        let i_agents = d.find("agents").expect("agents");
        let i_ctrl = d.find("controller").expect("controller");
        assert!(
            i_agents < i_ctrl,
            "the agents must come before the controller:\n{d}"
        );
        assert!(d.contains("LAST"), "{d}");
    }

    #[test]
    fn migrations_are_undone_in_reverse_order() {
        // 🔴 A migration adding a column referenced by the next must be undone AFTER
        // it. Application order would fail halfway, leaving a schema that is neither
        // the old nor the new.
        let r = Rollback {
            previous_version: Version::new(0, 1, 0),
            previous_binary: "/opt/hlb/hlb-0.1.0".into(),
            state_export: "/var/lib/hlb/avant-0.2.0.sql".into(),
            undo: vec![
                migration("0007_colonne", true),
                migration("0008_index_sur_colonne", true),
            ],
        };

        let ordre: Vec<&str> = r.undo_order().iter().map(|m| m.name.as_str()).collect();
        assert_eq!(ordre, vec!["0008_index_sur_colonne", "0007_colonne"]);
    }

    #[test]
    fn the_previous_binary_is_kept_on_disk() {
        // ⚠️ The day you need a rollback is usually a day when something is wrong -
        // and the network can be part of it.
        let r = Rollback {
            previous_version: Version::new(0, 1, 0),
            previous_binary: "/opt/hlb/hlb-0.1.0".into(),
            state_export: "/var/lib/hlb/avant.sql".into(),
            undo: vec![],
        };
        assert!(r.describe().contains("/opt/hlb/hlb-0.1.0"));
        assert!(r.describe().contains("/var/lib/hlb/avant.sql"));
    }
}
