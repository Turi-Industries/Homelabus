//! Vie du cluster : initialisation, nœuds, tiers et quorum (§2ter, §2bis, §10.3).
//!
//! Ce module est volontairement séparé du déploiement de services : ce sont deux
//! préoccupations différentes, et mélanger « faire tourner une app » avec « ajouter
//! une machine » rend les deux plus difficiles à raisonner.

use serde::{Deserialize, Serialize};

/// Le rôle d'un nœud dans Swarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    /// Participe au quorum Raft et peut piloter le cluster.
    Manager,
    /// Exécute des tâches, sans droit de décision.
    Worker,
}

impl NodeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manager => "manager",
            Self::Worker => "worker",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    pub id: String,
    pub hostname: String,
    pub role: NodeRole,
    /// `ready`, `down`, `disconnected`…
    pub status: String,
    /// `active`, `pause`, `drain`.
    pub availability: String,
    /// Le tier déclaré (§2bis.2), s'il est posé.
    pub tier: Option<String>,
    pub is_leader: bool,
    pub memory_mb: Option<u64>,
}

impl NodeInfo {
    pub fn is_ready(&self) -> bool {
        self.status.eq_ignore_ascii_case("ready")
    }
}

/// Le tier d'un nœud, déduit de sa mémoire (§2bis.2).
///
/// 🔴 Ce n'est pas cosmétique : c'est ce qui empêche PostgreSQL d'atterrir sur un
/// nœud à 4 Go, où il fonctionnerait jusqu'au jour où il tue la machine par OOM.
pub fn tier_for_memory(memory_mb: u64) -> &'static str {
    if memory_mb >= 8192 {
        "heavy"
    } else {
        "light"
    }
}

/// L'état de santé du quorum Raft (§10.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumHealth {
    /// Un seul manager : pas de tolérance de panne, mais cohérent.
    Solo,
    /// 🔴 Deux managers : **pire qu'un seul**. La perte de l'un fait perdre le
    /// quorum et bloque tout le cluster, alors qu'avec un seul manager on peut
    /// au moins redémarrer avec `--force-new-cluster`.
    Dangerous { managers: usize },
    /// Nombre impair ≥ 3 : tolère (n-1)/2 pannes.
    Healthy { managers: usize, tolerates: usize },
    /// Nombre pair ≥ 4 : fonctionne, mais un manager de plus ne sert à rien.
    Wasteful { managers: usize, tolerates: usize },
}

impl QuorumHealth {
    pub fn assess(managers: usize) -> Self {
        match managers {
            0 | 1 => Self::Solo,
            2 => Self::Dangerous { managers: 2 },
            n if n % 2 == 1 => Self::Healthy {
                managers: n,
                tolerates: (n - 1) / 2,
            },
            n => Self::Wasteful {
                managers: n,
                tolerates: (n - 1) / 2,
            },
        }
    }

    /// Faut-il alerter l'utilisateur ?
    pub fn needs_attention(&self) -> bool {
        matches!(self, Self::Dangerous { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Solo => "1 manager — aucune tolérance de panne, mais cohérent. \
                           Ajoute deux managers pour du vrai quorum."
                .into(),
            Self::Dangerous { managers } => format!(
                "🔴 {managers} managers — PIRE qu'un seul : perdre l'un des deux bloque \
                 tout le cluster. Passe à 3, ou redescends à 1."
            ),
            Self::Healthy { managers, tolerates } => {
                format!("{managers} managers — tolère {tolerates} panne(s)")
            }
            Self::Wasteful { managers, tolerates } => format!(
                "{managers} managers — tolère {tolerates} panne(s), soit autant qu'avec \
                 {}. Le manager en trop n'apporte rien.",
                managers - 1
            ),
        }
    }
}

/// Le profil du cluster, déduit du nombre de nœuds (§2ter.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterProfile {
    /// Un seul nœud : tout dessus, pas de contrainte de placement utile.
    Solo,
    /// Deux nœuds : 1 manager + 1 worker. **Jamais deux managers.**
    Paired,
    /// Trois nœuds ou plus : quorum réel.
    Quorum,
}

impl ClusterProfile {
    pub fn for_node_count(n: usize) -> Self {
        match n {
            0 | 1 => Self::Solo,
            2 => Self::Paired,
            _ => Self::Quorum,
        }
    }

    /// Combien de managers ce profil recommande-t-il ?
    pub fn recommended_managers(&self) -> usize {
        match self {
            // 🔴 Deux nœuds ⇒ UN seul manager. Deux managers feraient perdre le
            // quorum à la moindre panne (§10.3).
            Self::Solo | Self::Paired => 1,
            Self::Quorum => 3,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Solo => "solo",
            Self::Paired => "paired",
            Self::Quorum => "quorum",
        }
    }
}

/// Les jetons pour rattacher un nœud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinTokens {
    pub manager: String,
    pub worker: String,
    /// Adresse à laquelle les nouveaux nœuds doivent se connecter.
    pub advertise_addr: String,
}

impl JoinTokens {
    pub fn for_role(&self, role: NodeRole) -> &str {
        match role {
            NodeRole::Manager => &self.manager,
            NodeRole::Worker => &self.worker,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_managers_is_flagged_as_worse_than_one() {
        // 🔴 Le piège le plus contre-intuitif de Swarm, et le plus coûteux.
        let q = QuorumHealth::assess(2);
        assert!(q.needs_attention());
        assert!(q.describe().contains("PIRE qu'un seul"), "{}", q.describe());
    }

    #[test]
    fn one_manager_is_acceptable_though_fragile() {
        let q = QuorumHealth::assess(1);
        assert!(!q.needs_attention());
        assert!(q.describe().contains("aucune tolérance"));
    }

    #[test]
    fn three_managers_tolerate_one_failure() {
        assert_eq!(
            QuorumHealth::assess(3),
            QuorumHealth::Healthy { managers: 3, tolerates: 1 }
        );
        assert_eq!(
            QuorumHealth::assess(5),
            QuorumHealth::Healthy { managers: 5, tolerates: 2 }
        );
    }

    #[test]
    fn an_even_count_is_wasteful_but_not_dangerous() {
        // 4 managers tolèrent 1 panne, exactement comme 3.
        let q = QuorumHealth::assess(4);
        assert!(!q.needs_attention());
        assert!(q.describe().contains("n'apporte rien"), "{}", q.describe());
    }

    #[test]
    fn a_two_node_cluster_gets_a_single_manager() {
        // 🔴 C'est la conséquence directe du piège ci-dessus.
        assert_eq!(ClusterProfile::for_node_count(2), ClusterProfile::Paired);
        assert_eq!(ClusterProfile::Paired.recommended_managers(), 1);
    }

    #[test]
    fn three_nodes_get_a_real_quorum() {
        assert_eq!(ClusterProfile::for_node_count(3), ClusterProfile::Quorum);
        assert_eq!(ClusterProfile::Quorum.recommended_managers(), 3);
        assert_eq!(ClusterProfile::for_node_count(7), ClusterProfile::Quorum);
    }

    #[test]
    fn a_small_node_is_never_heavy() {
        // Les nœuds à 4 Go du plan doivent rester « light » : y placer une base de
        // données la ferait fonctionner jusqu'au jour de l'OOM.
        assert_eq!(tier_for_memory(3900), "light");
        assert_eq!(tier_for_memory(4096), "light");
        assert_eq!(tier_for_memory(8192), "heavy");
        assert_eq!(tier_for_memory(16384), "heavy");
    }

    #[test]
    fn tokens_are_selected_by_role() {
        let t = JoinTokens {
            manager: "SWMTKN-mgr".into(),
            worker: "SWMTKN-wrk".into(),
            advertise_addr: "10.0.0.1:2377".into(),
        };
        assert_eq!(t.for_role(NodeRole::Manager), "SWMTKN-mgr");
        assert_eq!(t.for_role(NodeRole::Worker), "SWMTKN-wrk");
    }

    #[test]
    fn readiness_is_case_insensitive() {
        let mut n = NodeInfo {
            id: "x".into(),
            hostname: "n1".into(),
            role: NodeRole::Manager,
            status: "Ready".into(),
            availability: "active".into(),
            tier: Some("heavy".into()),
            is_leader: true,
            memory_mb: Some(16384),
        };
        assert!(n.is_ready());
        n.status = "down".into();
        assert!(!n.is_ready());
    }
}
