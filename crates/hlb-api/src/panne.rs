//! « Et si ça tombait ? » — le simulateur de panne (lot 9.3).
//!
//! ## Ce que ça ajoute
//!
//! La vue topologie DESSINE les domaines de panne ; elle ne dit pas ce qu'on perdrait.
//! Le simulateur transforme le dessin en réponse : quels services perdent tous leurs
//! réplicas, lesquels survivent diminués, le quorum tient-il, et quelles destinations
//! de sauvegarde deviennent injoignables.
//!
//! ## 🔴 On simule un DOMAINE, pas une machine
//!
//! Deux VM du même serveur sont deux nœuds Swarm et **un seul** point de panne. Simuler
//! la perte d'« un nœud » sur une telle installation sous-estime exactement ce que
//! l'anti-affinité est censée empêcher : on conclurait « l'app survit » alors que ses
//! deux réplicas s'éteignent ensemble.
//!
//! Un domaine **non déclaré** ne vaut pas un domaine isolé : chaque nœud sans domaine
//! est simulé seul, et le résultat le dit — supposer l'isolement serait l'hypothèse
//! optimiste qui crée l'illusion de redondance.

use serde::{Deserialize, Serialize};

use crate::{DomaineSummary, Topologie};

/// Ce qu'on fait tomber.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cible {
    /// Un domaine de panne déclaré, avec tous les nœuds qu'il porte.
    Domaine(String),
    /// Un nœud dont le domaine n'est pas déclaré : on ne peut simuler que lui.
    Noeud(String),
}

impl Cible {
    pub fn nom(&self) -> &str {
        match self {
            Self::Domaine(n) | Self::Noeud(n) => n,
        }
    }
}

/// Le résultat d'une simulation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Simulation {
    pub cible: Cible,
    /// Les nœuds qui disparaissent ensemble.
    pub noeuds_perdus: Vec<String>,
    /// Les nœuds qui restent.
    pub noeuds_restants: usize,
    /// 🔴 Services dont TOUS les réplicas étaient sur la cible : ils s'arrêtent.
    pub services_perdus: Vec<String>,
    /// Services qui survivent, mais avec moins de réplicas.
    pub services_diminues: Vec<ServiceDiminue>,
    /// Ce qu'il advient du quorum Swarm.
    pub quorum: SortQuorum,
    /// ⚠️ Vrai quand la cible est un nœud dont le domaine n'est pas déclaré : le
    /// résultat est alors un **minorant** de ce qu'on perdrait réellement.
    pub domaine_inconnu: bool,
}

/// Un service qui survit diminué.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDiminue {
    pub service: String,
    pub avant: usize,
    pub apres: usize,
}

/// Ce que devient le quorum après la panne.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortQuorum {
    /// Le cluster reste pilotable.
    Tient,
    /// 🔴 Le quorum est perdu : plus rien ne se planifie, ni ne se répare.
    Perdu,
    /// On ne sait pas quels nœuds sont managers.
    Inconnu,
}

impl Simulation {
    /// Y a-t-il quelque chose à craindre ?
    pub fn attention(&self) -> crate::Attention {
        if !self.services_perdus.is_empty() || self.quorum == SortQuorum::Perdu {
            crate::Attention::Critical
        } else if !self.services_diminues.is_empty() || self.domaine_inconnu {
            crate::Attention::Notice
        } else {
            crate::Attention::Ok
        }
    }

    /// La réponse en une phrase.
    pub fn verdict(&self) -> String {
        let quoi = match self.cible {
            Cible::Domaine(_) => "ce domaine de panne",
            Cible::Noeud(_) => "ce nœud",
        };

        // ⚠️ La mise en garde sur le domaine non déclaré est ajoutée à la FIN, quelle
        // que soit la branche : un premier jet la posait après un `return` anticipé, et
        // elle disparaissait précisément dans le cas le plus grave.
        let mut phrase = if self.noeuds_restants == 0 {
            // Le cas qu'un compte de services raterait : il ne reste rien pour porter
            // quoi que ce soit, et « 0 service perdu » se lirait « rien à craindre ».
            format!("Si {quoi} tombait, il ne resterait AUCUN nœud : tout s'arrête.")
        } else {
            self.phrase_des_services(quoi)
        };

        match self.quorum {
            SortQuorum::Perdu => phrase.push_str(
                " Le quorum Swarm serait PERDU : plus rien ne se planifie ni ne se \
                 répare tant qu'un manager n'est pas revenu.",
            ),
            SortQuorum::Tient => phrase.push_str(" Le quorum tiendrait."),
            SortQuorum::Inconnu => {}
        }

        if self.domaine_inconnu {
            phrase.push_str(
                " Attention : ce nœud n'a pas de domaine de panne déclaré. S'il partage un \
                 serveur ou une alimentation avec un autre, la perte réelle serait plus \
                 grande que celle-ci.",
            );
        }

        phrase
    }

    /// La partie « quels services » du verdict.
    fn phrase_des_services(&self, quoi: &str) -> String {
        // ⚠️ L'accord du verbe se fait à la main. `pluriel` accorde le NOM ; « 5
        // services s'arrêterait » se lit comme une faute de frappe et fait douter du
        // reste de l'écran. Constaté tel quel à l'affichage.
        let mut phrase = if self.services_perdus.is_empty() {
            format!("Si {quoi} tombait, aucun service ne s'arrêterait")
        } else {
            format!(
                "Si {quoi} tombait, {} s'arrêterai{} : {}",
                crate::pluriel(self.services_perdus.len() as u64, "service", "services"),
                accord(self.services_perdus.len()),
                self.services_perdus.join(", ")
            )
        };

        if !self.services_diminues.is_empty() {
            phrase.push_str(&format!(
                ", et {} continuerai{} avec moins de réplicas",
                crate::pluriel(self.services_diminues.len() as u64, "service", "services"),
                accord(self.services_diminues.len())
            ));
        }

        phrase.push('.');
        phrase
    }
}

/// La terminaison d'un conditionnel : « s'arrêterait » ou « s'arrêteraient ».
///
/// 🔴 Zéro et un prennent le SINGULIER en français — la règle qu'un `if n > 1` naïf
/// rate dans l'autre sens, et que `crate::pluriel` porte déjà pour les noms.
fn accord(n: usize) -> &'static str {
    if n > 1 {
        "ent"
    } else {
        "t"
    }
}

/// Simule la perte de chaque domaine, et de chaque nœud sans domaine déclaré.
///
/// `managers` : les identifiants des nœuds managers, quand on les connaît.
pub fn simuler_tout(topo: &Topologie, managers: &[String]) -> Vec<Simulation> {
    let mut out = Vec::new();
    for d in &topo.domaines {
        match &d.nom {
            Some(nom) => out.push(simuler(topo, Cible::Domaine(nom.clone()), managers)),
            // 🔴 Le groupe « on ne sait pas » n'est PAS un domaine : ses nœuds ne
            // tombent pas ensemble par construction, ils sont seulement non classés.
            // Les simuler ensemble inventerait une corrélation, les ignorer laisserait
            // ces machines hors de l'exercice. On les simule donc une par une.
            None => {
                for n in &d.noeuds {
                    out.push(simuler(topo, Cible::Noeud(n.id.clone()), managers));
                }
            }
        }
    }
    // Le pire d'abord : c'est celui qu'on veut lire.
    out.sort_by(|a, b| {
        b.services_perdus
            .len()
            .cmp(&a.services_perdus.len())
            .then_with(|| a.cible.nom().cmp(b.cible.nom()))
    });
    out
}

/// Simule la perte d'une cible.
pub fn simuler(topo: &Topologie, cible: Cible, managers: &[String]) -> Simulation {
    let dans_cible = |d: &DomaineSummary, id: &str| match &cible {
        Cible::Domaine(nom) => d.nom.as_deref() == Some(nom.as_str()),
        Cible::Noeud(n) => n == id,
    };

    let mut perdus = Vec::new();
    let mut restants = 0usize;
    let mut avant: std::collections::BTreeMap<String, usize> = Default::default();
    let mut apres: std::collections::BTreeMap<String, usize> = Default::default();
    let mut domaine_inconnu = false;

    for d in &topo.domaines {
        for n in &d.noeuds {
            for s in &n.services {
                *avant.entry(s.clone()).or_default() += 1;
            }
            if dans_cible(d, &n.id) {
                perdus.push(n.id.clone());
                if d.nom.is_none() {
                    domaine_inconnu = true;
                }
            } else {
                restants += 1;
                for s in &n.services {
                    *apres.entry(s.clone()).or_default() += 1;
                }
            }
        }
    }

    let mut services_perdus = Vec::new();
    let mut services_diminues = Vec::new();
    for (service, n_avant) in &avant {
        let n_apres = apres.get(service).copied().unwrap_or(0);
        if n_apres == 0 {
            services_perdus.push(service.clone());
        } else if n_apres < *n_avant {
            services_diminues.push(ServiceDiminue {
                service: service.clone(),
                avant: *n_avant,
                apres: n_apres,
            });
        }
    }

    let quorum = if managers.is_empty() {
        SortQuorum::Inconnu
    } else {
        let survivants = managers.iter().filter(|m| !perdus.contains(m)).count();
        // Swarm exige la MAJORITÉ STRICTE des managers déclarés, pas la moitié : sur
        // quatre managers, deux survivants ne suffisent pas.
        if survivants * 2 > managers.len() {
            SortQuorum::Tient
        } else {
            SortQuorum::Perdu
        }
    };

    Simulation {
        cible,
        noeuds_perdus: perdus,
        noeuds_restants: restants,
        services_perdus,
        services_diminues,
        quorum,
        domaine_inconnu,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoeudDansDomaine;

    fn noeud(id: &str, services: &[&str]) -> NoeudDansDomaine {
        NoeudDansDomaine {
            id: id.into(),
            hostname: id.into(),
            tier: None,
            joignable: true,
            services: services.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn topo(domaines: Vec<(Option<&str>, Vec<NoeudDansDomaine>)>) -> Topologie {
        Topologie {
            managers: Vec::new(),
            noeuds_total: domaines.iter().map(|(_, n)| n.len()).sum(),
            domaines: domaines
                .into_iter()
                .map(|(nom, noeuds)| DomaineSummary {
                    nom: nom.map(str::to_string),
                    concentre: false,
                    noeuds,
                })
                .collect(),
            violations: Vec::new(),
        }
    }

    #[test]
    fn two_replicas_in_the_same_domain_do_not_survive_that_domain() {
        // 🔴 Le cœur du simulateur. Swarm rend une illusion de redondance : deux
        // réplicas « sur deux nœuds », donc « réparti ». Les deux nœuds sont deux VM du
        // même serveur, et le service s'éteint entièrement avec lui.
        let t = topo(vec![
            (
                Some("serveur-a"),
                vec![noeud("vm-1", &["gitea"]), noeud("vm-2", &["gitea"])],
            ),
            (Some("serveur-b"), vec![noeud("vm-3", &["immich"])]),
        ]);

        let s = simuler(&t, Cible::Domaine("serveur-a".into()), &[]);
        assert_eq!(s.services_perdus, vec!["gitea"]);
        assert_eq!(s.noeuds_perdus.len(), 2);
        assert_eq!(s.attention(), crate::Attention::Critical);

        // La même installation, simulée nœud par nœud, dirait exactement l'inverse.
        let par_noeud = simuler(&t, Cible::Noeud("vm-1".into()), &[]);
        assert!(par_noeud.services_perdus.is_empty());
        assert_eq!(par_noeud.services_diminues[0].apres, 1);
    }

    #[test]
    fn a_surviving_service_is_not_the_same_as_an_untouched_one() {
        // Un service qui passe de 3 à 1 réplica survit, mais n'a plus aucune marge : le
        // dire « intact » ferait manquer la panne suivante.
        let t = topo(vec![
            (
                Some("a"),
                vec![noeud("n1", &["web"]), noeud("n2", &["web"])],
            ),
            (Some("b"), vec![noeud("n3", &["web"])]),
        ]);
        let s = simuler(&t, Cible::Domaine("a".into()), &[]);
        assert!(s.services_perdus.is_empty());
        assert_eq!(
            s.services_diminues,
            vec![ServiceDiminue {
                service: "web".into(),
                avant: 3,
                apres: 1
            }]
        );
        assert_eq!(s.attention(), crate::Attention::Notice);
    }

    #[test]
    fn an_undeclared_domain_is_simulated_alone_and_says_so() {
        // ⚠️ Supposer l'isolement serait l'hypothèse optimiste qui crée l'illusion. Le
        // résultat est un MINORANT, et l'écran doit le dire.
        let t = topo(vec![(None, vec![noeud("orphelin", &["vaultwarden"])])]);
        let s = simuler(&t, Cible::Noeud("orphelin".into()), &[]);

        assert!(s.domaine_inconnu);
        assert!(s.verdict().contains("plus grande"), "{}", s.verdict());
        // Et il ne peut pas être « Ok » : on ne sait pas ce qu'on perdrait vraiment.
        assert_ne!(s.attention(), crate::Attention::Ok);
    }

    #[test]
    fn the_undeclared_domain_warning_survives_the_total_loss_case() {
        // 🔴 Le défaut tel qu'il s'est présenté : un `return` anticipé pour « il ne
        // reste aucun nœud » sautait la mise en garde. Elle disparaissait donc dans le
        // cas le plus grave — celui où l'on a le plus besoin de savoir que le chiffre
        // affiché est un minorant.
        let t = topo(vec![(None, vec![noeud("seul", &["gitea"])])]);
        let s = simuler(&t, Cible::Noeud("seul".into()), &[]);
        assert_eq!(s.noeuds_restants, 0);
        assert!(s.verdict().contains("AUCUN nœud"), "{}", s.verdict());
        assert!(s.verdict().contains("plus grande"), "{}", s.verdict());
    }

    #[test]
    fn undeclared_nodes_are_never_simulated_as_falling_together() {
        // Ils ne sont pas corrélés : ils sont seulement non classés. Les faire tomber
        // ensemble inventerait une corrélation, et le pire cas affiché serait faux.
        let t = topo(vec![(
            None,
            vec![noeud("a", &["x"]), noeud("b", &["y"])],
        )]);
        let sims = simuler_tout(&t, &[]);
        assert_eq!(sims.len(), 2, "un par nœud, pas un pour le groupe");
        for s in &sims {
            assert_eq!(s.noeuds_perdus.len(), 1);
        }
    }

    #[test]
    fn losing_the_majority_of_managers_loses_the_quorum() {
        let t = topo(vec![
            (Some("a"), vec![noeud("m1", &[]), noeud("m2", &[])]),
            (Some("b"), vec![noeud("m3", &[])]),
        ]);
        let managers = vec!["m1".to_string(), "m2".into(), "m3".into()];

        let perte = simuler(&t, Cible::Domaine("a".into()), &managers);
        assert_eq!(perte.quorum, SortQuorum::Perdu);
        assert!(perte.verdict().contains("PERDU"), "{}", perte.verdict());

        let ok = simuler(&t, Cible::Domaine("b".into()), &managers);
        assert_eq!(ok.quorum, SortQuorum::Tient);
    }

    #[test]
    fn exactly_half_the_managers_is_not_a_majority() {
        // Swarm exige la majorité STRICTE. Sur quatre managers, deux survivants ne
        // suffisent pas — et un `>=` naïf conclurait que le cluster tient.
        let t = topo(vec![
            (Some("a"), vec![noeud("m1", &[]), noeud("m2", &[])]),
            (Some("b"), vec![noeud("m3", &[]), noeud("m4", &[])]),
        ]);
        let managers = vec!["m1".to_string(), "m2".into(), "m3".into(), "m4".into()];
        assert_eq!(
            simuler(&t, Cible::Domaine("a".into()), &managers).quorum,
            SortQuorum::Perdu
        );
    }

    #[test]
    fn an_unknown_manager_list_is_never_reported_as_a_healthy_quorum() {
        // Ne pas savoir n'est pas rassurant. `Inconnu` est distinct de `Tient`, et le
        // verdict se tait plutôt que d'affirmer.
        let t = topo(vec![(Some("a"), vec![noeud("n1", &["gitea"])])]);
        let s = simuler(&t, Cible::Domaine("a".into()), &[]);
        assert_eq!(s.quorum, SortQuorum::Inconnu);
        assert!(!s.verdict().contains("quorum"), "{}", s.verdict());
    }

    #[test]
    fn the_verb_agrees_with_the_number_of_services() {
        // 🔴 Constaté à l'écran : « 5 services s'arrêterait ». `pluriel` accorde le nom,
        // pas le verbe — et une faute d'accord fait douter de tout le reste.
        let t = topo(vec![
            (
                Some("gros"),
                vec![noeud("n1", &["a", "b"]), noeud("n2", &["c"])],
            ),
            (Some("autre"), vec![noeud("n3", &["d"])]),
        ]);
        let plusieurs = simuler(&t, Cible::Domaine("gros".into()), &[]);
        assert!(
            plusieurs.verdict().contains("s'arrêteraient"),
            "{}",
            plusieurs.verdict()
        );

        let un = simuler(&t, Cible::Domaine("autre".into()), &[]);
        assert!(un.verdict().contains("s'arrêterait :"), "{}", un.verdict());
    }

    #[test]
    fn losing_everything_is_not_reported_as_losing_nothing() {
        // Un cluster d'un seul nœud : il n'y a aucun service « diminué », et un compte
        // naïf afficherait une phrase rassurante sur un cluster entièrement éteint.
        let t = topo(vec![(Some("seul"), vec![noeud("n1", &["gitea"])])]);
        let s = simuler(&t, Cible::Domaine("seul".into()), &[]);
        assert_eq!(s.noeuds_restants, 0);
        assert!(s.verdict().contains("AUCUN nœud"), "{}", s.verdict());
    }

    #[test]
    fn the_worst_case_is_listed_first() {
        // C'est celui qu'on veut lire : un écran qui trie par nom ferait chercher.
        let t = topo(vec![
            (Some("petit"), vec![noeud("n1", &["a"])]),
            (
                Some("gros"),
                vec![noeud("n2", &["b", "c", "d"]), noeud("n3", &["e"])],
            ),
        ]);
        let sims = simuler_tout(&t, &[]);
        assert_eq!(sims[0].cible, Cible::Domaine("gros".into()));
    }
}
