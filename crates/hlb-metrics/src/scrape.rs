//! La configuration de collecte de VictoriaMetrics (§8bis).
//!
//! ## Pourquoi VictoriaMetrics seul, sans Prometheus ni Alloy
//!
//! VictoriaMetrics en nœud unique sait **collecter** (`-promscrape.config`), stocker et
//! répondre en PromQL. Le trio Prometheus + Alloy + un stockage distant, sur un homelab,
//! ajoute deux services à maintenir pour un résultat identique. Le §8bis parlait
//! d'Alloy ; il n'apporte rien ici tant qu'on n'a pas de journaux à router.
//!
//! Il consomme aussi nettement moins de mémoire que Prometheus à volume égal, ce qui
//! compte sur un nœud `light`.
//!
//! ## 🔴 La cible qu'on oublie toujours
//!
//! Le controller expose `/metrics`, et c'est bien lui la source. Mais si VictoriaMetrics
//! ne collecte QUE le controller, alors la mort du controller rend la collecte muette —
//! et un graphe qui s'arrête ressemble beaucoup à un graphe plat. C'est précisément ce
//! que le deadman switch ([`crate::deadman`]) rattrape : les deux dispositifs sont
//! complémentaires, et aucun ne remplace l'autre.

use std::fmt::Write as _;

/// Une cible à collecter.
#[derive(Debug, Clone)]
pub struct Cible {
    /// Nom du travail de collecte.
    pub job: String,
    /// `hôte:port`.
    pub adresse: String,
    /// Chemin de la route de métriques.
    pub chemin: String,
    /// Jeton de lecture, si la route est protégée.
    pub jeton: Option<String>,
}

impl Cible {
    /// La cible du controller.
    ///
    /// ⚠️ `/metrics` est protégé par jeton (§9ter) : sans lui, VictoriaMetrics collecte
    /// des 401 et le tableau de bord reste vide sans dire pourquoi.
    pub fn controller(adresse: impl Into<String>, jeton: Option<String>) -> Self {
        Self {
            job: "hlb-controller".into(),
            adresse: adresse.into(),
            chemin: "/metrics".into(),
            jeton,
        }
    }
}

/// L'intervalle de collecte.
///
/// 30 s : les métriques de HomelabUS changent à l'échelle de la minute (âge de
/// sauvegarde, état d'app). Collecter toutes les secondes multiplierait le stockage
/// par trente sans rien révéler de plus.
pub const INTERVALLE_S: u32 = 30;

/// Produit le `promscrape.config` de VictoriaMetrics.
///
/// ⚠️ Le jeton est écrit **en clair** dans ce fichier : il doit être posé en secret
/// Docker, jamais monté depuis un dépôt Git. C'est un jeton en LECTURE SEULE
/// (rôle `metrics`), ce qui limite les dégâts d'une fuite sans les annuler.
pub fn config_collecte(cibles: &[Cible]) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Généré par HomelabUS (§8bis). Ne pas modifier à la main.");
    let _ = writeln!(s, "#");
    let _ = writeln!(s, "# ⚠️ Ce fichier contient un jeton en clair : pose-le en secret");
    let _ = writeln!(s, "#    Docker, jamais dans un dépôt Git.");
    let _ = writeln!(s, "global:");
    let _ = writeln!(s, "  scrape_interval: {INTERVALLE_S}s");
    let _ = writeln!(s, "scrape_configs:");

    for c in cibles {
        let _ = writeln!(s, "  - job_name: {}", c.job);
        let _ = writeln!(s, "    metrics_path: {}", c.chemin);
        let _ = writeln!(s, "    static_configs:");
        let _ = writeln!(s, "      - targets: ['{}']", c.adresse);
        if let Some(j) = &c.jeton {
            let _ = writeln!(s, "    authorization:");
            let _ = writeln!(s, "      type: Bearer");
            let _ = writeln!(s, "      credentials: '{j}'");
        }
    }
    s
}

/// La rétention des données.
///
/// 🔴 Treize mois, et non trente jours. La question qu'on pose à un historique de
/// métriques est presque toujours « est-ce que c'était déjà comme ça l'an dernier ? » —
/// une rétention courte y répond « je ne sais pas » précisément quand elle servirait.
/// Le coût est dérisoire : les métriques de HomelabUS sont peu nombreuses et
/// VictoriaMetrics les compresse fortement.
pub const RETENTION: &str = "13mo";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_reaches_the_scrape_config() {
        // 🔴 `/metrics` est protégé par jeton (§9ter). Sans lui, VictoriaMetrics
        // collecte des 401 en boucle et le tableau de bord reste vide — sans que rien
        // n'indique que c'est un problème d'authentification.
        let c = Cible::controller("controller:8080", Some("hlb_lecture_xyz".into()));
        let y = config_collecte(&[c]);

        assert!(y.contains("credentials: 'hlb_lecture_xyz'"), "{y}");
        assert!(y.contains("type: Bearer"), "{y}");
        assert!(y.contains("metrics_path: /metrics"), "{y}");
    }

    #[test]
    fn a_config_without_token_says_nothing_about_authorization() {
        // Un bloc `authorization` vide ferait échouer le démarrage de VictoriaMetrics.
        let c = Cible::controller("controller:8080", None);
        let y = config_collecte(&[c]);
        assert!(!y.contains("authorization"), "{y}");
    }

    #[test]
    fn the_config_warns_that_it_holds_a_secret() {
        // Un fichier de configuration paraît anodin ; celui-ci porte un jeton en clair
        // et finirait dans un dépôt Git sans cet avertissement.
        let y = config_collecte(&[Cible::controller("c:8080", Some("x".into()))]);
        assert!(y.contains("jamais dans un dépôt Git"), "{y}");
    }

    #[test]
    fn retention_covers_more_than_a_year() {
        // 🔴 La question posée à un historique est « était-ce déjà comme ça l'an
        // dernier ? ». Une rétention de 30 jours répond « je ne sais pas » exactement
        // quand elle servirait.
        assert_eq!(RETENTION, "13mo");
    }

    #[test]
    fn several_targets_are_all_kept() {
        let cibles = vec![
            Cible::controller("c1:8080", None),
            Cible {
                job: "node".into(),
                adresse: "n2:9100".into(),
                chemin: "/metrics".into(),
                jeton: None,
            },
        ];
        let y = config_collecte(&cibles);
        assert!(y.contains("c1:8080"), "{y}");
        assert!(y.contains("n2:9100"), "{y}");
        assert_eq!(y.matches("job_name").count(), 2, "{y}");
    }
}
