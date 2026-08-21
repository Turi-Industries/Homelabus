//! Le budget de capacité, avant de planifier (lot 9.6).
//!
//! ## 🔴 Le symptôme qu'on veut éviter
//!
//! Une app placée sur un tier qui n'a plus de mémoire ne rend pas une erreur claire :
//! Swarm accepte le service, la tâche est planifiée, le conteneur est tué par le noyau,
//! et `wait_healthy` **expire** — sans que rien ne dise pourquoi. On cherche alors du
//! côté de la sonde de santé, de l'image, du réseau. Le §2bis.4 protège les nœuds à
//! 4 Go pour cette raison précise.
//!
//! ## ⚠️ Ce que ce module NE peut PAS faire
//!
//! Aucun manifest ne déclare la mémoire dont l'app a besoin — ce champ n'existe pas
//! dans le schéma. On ne peut donc pas dire « il en faut 512 Mo et il en reste 300 ».
//! On dit ce qu'on sait : **ce qui reste sur le tier visé**, avant de planifier plutôt
//! qu'au bout d'un délai d'attente. Prétendre calculer une marge qu'on n'a pas serait
//! pire qu'un silence : on s'y fierait.

/// Ce qui reste sur un tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    pub tier: String,
    /// Mémoire disponible cumulée, en Mo.
    pub disponible_mb: u64,
    /// Le nœud le plus large du tier : c'est LUI qui décide, pas la somme.
    ///
    /// 🔴 Un service ne se répartit pas entre deux machines. Deux nœuds à 400 Mo
    /// disponibles ne font pas 800 Mo utilisables : ils font 400.
    pub meilleur_noeud_mb: u64,
    pub noeuds: usize,
    /// Des nœuds du tier ne répondent pas : le budget est un MINORANT.
    pub noeuds_muets: usize,
}

/// Sous ce seuil, on prévient : le §2bis.4 protège les nœuds à 4 Go.
pub const SEUIL_ETROIT_MB: u64 = 512;

impl Budget {
    /// L'avertissement à afficher, s'il y a lieu.
    pub fn avertissement(&self) -> Option<String> {
        if self.noeuds == 0 {
            return Some(format!(
                "Aucun nœud n'est étiqueté « {} » : rien ne se planifiera, et l'attente \
                 de mise en santé expirera sans expliquer pourquoi. Pose l'étiquette : \
                 docker node update --label-add tier={} <nœud>",
                self.tier, self.tier
            ));
        }

        if self.meilleur_noeud_mb < SEUIL_ETROIT_MB {
            return Some(format!(
                "Le tier « {} » n'a que {} Mo disponibles sur son nœud le plus large. \
                 Un conteneur tué par manque de mémoire ne dit rien : l'installation \
                 échouera sur une attente de mise en santé expirée.",
                self.tier, self.meilleur_noeud_mb
            ));
        }

        if self.noeuds_muets > 0 {
            // On ne sait pas ce que ces machines ont : le chiffre affiché est un
            // minorant, et le dire vaut mieux que de laisser croire à une mesure.
            return Some(format!(
                "{} du tier « {} » ne répond pas : {} Mo est un MINORANT, pas une \
                 mesure.",
                hlb_api::pluriel(self.noeuds_muets as u64, "nœud", "nœuds"),
                self.tier,
                self.disponible_mb
            ));
        }

        None
    }
}

/// Ce qui reste sur un tier.
///
/// `noeuds` : pour chaque machine, son tier (`None` = inconnu) et sa mémoire
/// disponible (`None` = l'agent ne répond pas).
///
/// ⚠️ La jointure entre l'inventaire Swarm et les rapports d'agent est faite par
/// l'appelant : elle passe par le nom d'hôte, une règle qui vit déjà dans l'API et
/// qu'on ne duplique pas ici.
pub fn budget(noeuds_du_parc: &[(Option<String>, Option<u64>)], tier: &str) -> Budget {
    let mut disponible_mb = 0u64;
    let mut meilleur = 0u64;
    let mut noeuds = 0usize;
    let mut muets = 0usize;

    for (son_tier, dispo) in noeuds_du_parc {
        // ⚠️ Un nœud dont on ignore le tier n'est PAS supposé appartenir à celui-ci :
        // supposer ferait annoncer de la place là où il n'y en a pas.
        if son_tier.as_deref() != Some(tier) {
            continue;
        }
        noeuds += 1;

        match dispo {
            Some(mb) => {
                disponible_mb += mb;
                meilleur = meilleur.max(*mb);
            }
            None => muets += 1,
        }
    }

    Budget {
        tier: tier.to_string(),
        disponible_mb,
        meilleur_noeud_mb: meilleur,
        noeuds,
        noeuds_muets: muets,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parc(v: &[(&str, Option<u64>)]) -> Vec<(Option<String>, Option<u64>)> {
        v.iter()
            .map(|(tier, mb)| (Some(tier.to_string()), *mb))
            .collect()
    }

    #[test]
    fn two_small_nodes_do_not_add_up_to_one_big_one() {
        // 🔴 Le cœur du calcul : un service ne se répartit pas entre deux machines.
        // Additionner donnerait « 800 Mo disponibles » et laisserait installer une app
        // qu'aucun des deux nœuds ne peut porter.
        let b = budget(
            &parc(&[("light", Some(400)), ("light", Some(400))]),
            "light",
        );

        assert_eq!(b.disponible_mb, 800);
        assert_eq!(b.meilleur_noeud_mb, 400, "c'est le plus large qui décide");
        assert!(b.avertissement().is_some(), "400 Mo est sous le seuil");
    }

    #[test]
    fn a_tier_with_no_node_is_named_as_such() {
        // ⚠️ Le piège documenté du projet : sans étiquette de tier, rien ne se planifie
        // et `wait_healthy` expire sans dire pourquoi.
        let b = budget(&parc(&[("light", Some(2_000))]), "heavy");

        assert_eq!(b.noeuds, 0);
        let a = b.avertissement().expect("un avertissement");
        assert!(a.contains("label-add tier=heavy"), "{a}");
    }

    #[test]
    fn a_node_of_unknown_tier_is_never_counted_in() {
        // Supposer l'appartenance ferait annoncer de la place là où il n'y en a pas.
        let b = budget(&[(None, Some(8_000))], "light");

        assert_eq!(b.noeuds, 0);
        assert_eq!(b.disponible_mb, 0);
    }

    #[test]
    fn a_silent_node_makes_the_figure_a_lower_bound() {
        // Le chiffre reste utile, mais il ne doit pas passer pour une mesure.
        let b = budget(&parc(&[("light", Some(3_000)), ("light", None)]), "light");

        assert_eq!(b.noeuds_muets, 1);
        let a = b.avertissement().expect("un avertissement");
        assert!(a.contains("MINORANT"), "{a}");
    }

    #[test]
    fn a_comfortable_tier_says_nothing_at_all() {
        // 🔴 Un avertissement affiché en permanence cesse d'être lu.
        let b = budget(
            &parc(&[("heavy", Some(12_000)), ("heavy", Some(9_000))]),
            "heavy",
        );
        assert_eq!(b.avertissement(), None);
    }
}
