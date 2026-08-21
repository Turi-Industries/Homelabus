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
    /// 🔴 Le **domaine de panne** : le fer physique, pas la machine logique (§2bis.2).
    ///
    /// Deux VM sur le même serveur sont deux nœuds Swarm et **un seul** point de
    /// panne. Répartir deux réplicas « sur deux nœuds différents » ne protège alors de
    /// rien — Swarm rend une illusion de redondance, et on la découvre le jour où le
    /// fer tombe.
    ///
    /// Swarm ne peut pas le deviner : il est déclaré à `hlb node add` et posé en
    /// étiquette `hlb.failureDomain`. `None` = non déclaré, ce qui doit se VOIR
    /// plutôt que de faire supposer que chaque nœud est isolé.
    pub failure_domain: Option<String>,
}

impl NodeInfo {
    pub fn is_ready(&self) -> bool {
        self.status.eq_ignore_ascii_case("ready")
    }
}

/// Un domaine de panne : un fer, et les nœuds qui vivent dessus.
///
/// ## 🔴 Ce que cette structure existe pour montrer
///
/// En ligne de commande, on voit trois nœuds et on se croit protégé. Deux d'entre eux
/// sont deux VM sur le même serveur : le fer tombe, deux tiers du cluster partent
/// avec. C'est l'illusion que la vue topologie (§11bis) doit dissiper, et elle ne le
/// peut que si le regroupement est explicite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureDomain {
    /// Le nom déclaré, ou `None` pour les nœuds sans domaine déclaré.
    pub nom: Option<String>,
    /// Les nœuds qui y vivent, par identifiant.
    pub noeuds: Vec<String>,
}

impl FailureDomain {
    /// Ce domaine porte-t-il assez de nœuds pour que sa perte soit grave ?
    pub fn concentre(&self, total_noeuds: usize) -> bool {
        // Plus de la moitié du cluster sur un seul fer : sa perte emporte le quorum.
        total_noeuds > 1 && self.noeuds.len() * 2 > total_noeuds
    }
}

/// Regroupe des nœuds par domaine de panne.
///
/// ⚠️ Les nœuds **sans domaine déclaré** forment un groupe à part, jamais un domaine
/// par nœud. Les supposer isolés serait exactement l'hypothèse optimiste qui produit
/// l'illusion de redondance — on ne sait pas, et il faut que ça se voie.
pub fn grouper_par_domaine(noeuds: &[NodeInfo]) -> Vec<FailureDomain> {
    let mut connus: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut inconnus = Vec::new();

    for n in noeuds {
        match &n.failure_domain {
            Some(d) => connus.entry(d.clone()).or_default().push(n.id.clone()),
            None => inconnus.push(n.id.clone()),
        }
    }

    let mut out: Vec<FailureDomain> = connus
        .into_iter()
        .map(|(nom, noeuds)| FailureDomain {
            nom: Some(nom),
            noeuds,
        })
        .collect();

    // Le plus concentré d'abord : c'est celui dont la perte fait le plus de dégâts.
    out.sort_by(|a, b| {
        b.noeuds
            .len()
            .cmp(&a.noeuds.len())
            .then_with(|| a.nom.cmp(&b.nom))
    });

    if !inconnus.is_empty() {
        out.push(FailureDomain {
            nom: None,
            noeuds: inconnus,
        });
    }
    out
}

/// Une violation d'anti-affinité : plusieurs réplicas d'un service sur le même fer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub service: String,
    /// Le domaine concerné. `None` = domaine non déclaré.
    pub domaine: Option<String>,
    /// Combien de réplicas s'y trouvent.
    pub replicas: usize,
    /// Sur combien au total.
    pub total: usize,
}

impl Violation {
    /// Tous les réplicas sont-ils au même endroit ?
    ///
    /// 🔴 Le cas le plus grave : le service paraît redondant et ne l'est pas du tout.
    pub fn totale(&self) -> bool {
        self.replicas == self.total && self.total > 1
    }

    pub fn describe(&self) -> String {
        let ou = match &self.domaine {
            Some(d) => format!("le domaine « {d} »"),
            // ⚠️ Un domaine non déclaré n'est pas une violation prouvée : c'est une
            // ignorance. Le dire ainsi évite de faire chercher un problème inexistant.
            None => "des nœuds sans domaine de panne déclaré".to_string(),
        };
        if self.totale() {
            format!(
                "{} : ses {} réplicas sont TOUS sur {ou} — la redondance est une illusion",
                self.service, self.total
            )
        } else {
            format!(
                "{} : {} de ses {} réplicas partagent {ou}",
                self.service, self.replicas, self.total
            )
        }
    }
}

/// Les services dont plusieurs réplicas partagent un domaine de panne.
///
/// `placements` est `(service, identifiant de nœud)` pour chaque réplica **vivant**.
pub fn violations_anti_affinite(
    placements: &[(String, String)],
    noeuds: &[NodeInfo],
) -> Vec<Violation> {
    let domaine_de: std::collections::BTreeMap<&str, Option<&str>> = noeuds
        .iter()
        .map(|n| (n.id.as_str(), n.failure_domain.as_deref()))
        .collect();

    // service → (domaine → nombre), et le total par service.
    let mut par_service: std::collections::BTreeMap<
        &str,
        std::collections::BTreeMap<Option<&str>, usize>,
    > = Default::default();
    for (service, noeud) in placements {
        let d = domaine_de.get(noeud.as_str()).copied().flatten();
        *par_service
            .entry(service.as_str())
            .or_default()
            .entry(d)
            .or_insert(0) += 1;
    }

    let mut out = Vec::new();
    for (service, domaines) in par_service {
        let total: usize = domaines.values().sum();
        // Un service à un seul réplica n'a rien à répartir : le signaler serait du
        // bruit, et le bruit fait cesser de lire les alertes.
        if total < 2 {
            continue;
        }
        for (domaine, n) in domaines {
            if n > 1 {
                out.push(Violation {
                    service: service.to_string(),
                    domaine: domaine.map(str::to_string),
                    replicas: n,
                    total,
                });
            }
        }
    }

    // Les violations totales d'abord : ce sont celles qui mentent le plus.
    out.sort_by(|a, b| {
        b.totale()
            .cmp(&a.totale())
            .then_with(|| b.replicas.cmp(&a.replicas))
            .then_with(|| a.service.cmp(&b.service))
    });
    out
}

/// L'étiquette Swarm qui porte le domaine de panne.
///
/// Posée par `hlb node add`, qui la DEMANDE : c'est la seule information que ni Swarm
/// ni l'agent ne peuvent déduire — savoir que deux VM tournent sur le même serveur
/// suppose de connaître la salle machine.
pub const LABEL_FAILURE_DOMAIN: &str = "hlb.failureDomain";

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
            Self::Healthy {
                managers,
                tolerates,
            } => {
                format!("{managers} managers — tolère {tolerates} panne(s)")
            }
            Self::Wasteful {
                managers,
                tolerates,
            } => format!(
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

    fn noeud(id: &str, domaine: Option<&str>) -> NodeInfo {
        NodeInfo {
            id: id.into(),
            hostname: id.into(),
            role: NodeRole::Worker,
            status: "ready".into(),
            availability: "active".into(),
            tier: None,
            is_leader: false,
            memory_mb: Some(8192),
            failure_domain: domaine.map(str::to_string),
        }
    }

    #[test]
    fn two_vms_on_one_box_form_one_domain() {
        // 🔴 LE cas du §2bis.2 : en ligne de commande on voit trois nœuds et on se
        // croit protégé. Deux sont des VM du même serveur — le fer tombe, deux tiers
        // du cluster partent avec.
        let noeuds = [
            noeud("swarm-heavy", Some("big-01")),
            noeud("mailcow", Some("big-01")),
            noeud("small-01", Some("small-01")),
        ];
        let d = grouper_par_domaine(&noeuds);

        assert_eq!(d.len(), 2, "trois nœuds, deux fers");
        assert_eq!(
            d[0].nom.as_deref(),
            Some("big-01"),
            "le plus concentré d'abord"
        );
        assert_eq!(d[0].noeuds.len(), 2);
        assert!(
            d[0].concentre(3),
            "deux nœuds sur trois : sa perte emporte le quorum"
        );
        assert!(!d[1].concentre(3));
    }

    #[test]
    fn undeclared_nodes_are_grouped_not_assumed_isolated() {
        // ⚠️ Supposer qu'un nœud sans domaine déclaré est isolé serait l'hypothèse
        // optimiste qui produit exactement l'illusion qu'on cherche à dissiper. On ne
        // sait pas, et il faut que ça se voie.
        let noeuds = [
            noeud("a", None),
            noeud("b", None),
            noeud("c", Some("fer-1")),
        ];
        let d = grouper_par_domaine(&noeuds);

        let inconnu = d
            .iter()
            .find(|x| x.nom.is_none())
            .expect("un groupe inconnu");
        assert_eq!(inconnu.noeuds.len(), 2, "regroupés, pas un domaine chacun");
        // Et il vient en dernier : ce n'est pas une violation prouvée.
        assert!(d.last().is_some_and(|x| x.nom.is_none()));
    }

    #[test]
    fn all_replicas_on_one_box_is_the_worst_case() {
        // 🔴 Le service paraît redondant et ne l'est pas du tout : c'est le mensonge
        // que Swarm produit quand l'anti-affinité porte sur `node.id`.
        let noeuds = [
            noeud("vm-a", Some("big-01")),
            noeud("vm-b", Some("big-01")),
            noeud("small-01", Some("small-01")),
        ];
        let placements = [
            ("gitea".to_string(), "vm-a".to_string()),
            ("gitea".to_string(), "vm-b".to_string()),
        ];

        let v = violations_anti_affinite(&placements, &noeuds);
        assert_eq!(v.len(), 1);
        assert!(v[0].totale(), "les DEUX réplicas sont sur le même fer");
        assert!(v[0].describe().contains("illusion"), "{}", v[0].describe());
    }

    #[test]
    fn a_properly_spread_service_raises_nothing() {
        let noeuds = [
            noeud("vm-a", Some("big-01")),
            noeud("small-01", Some("small-01")),
        ];
        let placements = [
            ("gitea".to_string(), "vm-a".to_string()),
            ("gitea".to_string(), "small-01".to_string()),
        ];
        assert!(violations_anti_affinite(&placements, &noeuds).is_empty());
    }

    #[test]
    fn a_single_replica_service_is_never_flagged() {
        // Un service à un seul réplica n'a rien à répartir. Le signaler serait du
        // bruit — et le bruit fait cesser de lire les alertes.
        let noeuds = [noeud("vm-a", Some("big-01"))];
        let placements = [("valkey".to_string(), "vm-a".to_string())];
        assert!(violations_anti_affinite(&placements, &noeuds).is_empty());
    }

    #[test]
    fn a_partial_violation_is_reported_but_ranked_lower() {
        // Trois réplicas, deux au même endroit : c'est moins grave que « tous au même
        // endroit », mais ça reste une redondance surévaluée.
        let noeuds = [
            noeud("vm-a", Some("big-01")),
            noeud("vm-b", Some("big-01")),
            noeud("small-01", Some("small-01")),
        ];
        let placements = [
            ("gitea".to_string(), "vm-a".to_string()),
            ("gitea".to_string(), "vm-b".to_string()),
            ("gitea".to_string(), "small-01".to_string()),
        ];

        let v = violations_anti_affinite(&placements, &noeuds);
        assert_eq!(v.len(), 1);
        assert!(!v[0].totale());
        assert_eq!((v[0].replicas, v[0].total), (2, 3));
    }

    #[test]
    fn total_violations_are_listed_before_partial_ones() {
        let noeuds = [
            noeud("vm-a", Some("big-01")),
            noeud("vm-b", Some("big-01")),
            noeud("small-01", Some("small-01")),
        ];
        let placements = [
            // vikunja : tous au même endroit — le pire.
            ("vikunja".to_string(), "vm-a".to_string()),
            ("vikunja".to_string(), "vm-b".to_string()),
            // gitea : deux sur trois.
            ("gitea".to_string(), "vm-a".to_string()),
            ("gitea".to_string(), "vm-b".to_string()),
            ("gitea".to_string(), "small-01".to_string()),
        ];

        let v = violations_anti_affinite(&placements, &noeuds);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].service, "vikunja", "la violation totale d'abord");
        assert!(v[0].totale());
    }

    #[test]
    fn an_undeclared_domain_is_not_reported_as_a_proven_violation() {
        // ⚠️ Deux réplicas sur des nœuds sans domaine déclaré : on ne SAIT PAS s'ils
        // partagent un fer. Le message doit le dire, sinon on cherche un problème qui
        // n'existe peut-être pas.
        let noeuds = [noeud("a", None), noeud("b", None)];
        let placements = [
            ("gitea".to_string(), "a".to_string()),
            ("gitea".to_string(), "b".to_string()),
        ];

        let v = violations_anti_affinite(&placements, &noeuds);
        assert_eq!(v.len(), 1);
        assert!(v[0].domaine.is_none());
        assert!(
            v[0].describe().contains("sans domaine de panne déclaré"),
            "{}",
            v[0].describe()
        );
    }

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
            QuorumHealth::Healthy {
                managers: 3,
                tolerates: 1
            }
        );
        assert_eq!(
            QuorumHealth::assess(5),
            QuorumHealth::Healthy {
                managers: 5,
                tolerates: 2
            }
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
            failure_domain: None,
        };
        assert!(n.is_ready());
        n.status = "down".into();
        assert!(!n.is_ready());
    }
}
