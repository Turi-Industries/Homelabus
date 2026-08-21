//! Métriques au format Prometheus (§8bis).
//!
//! ## Pourquoi si peu de métriques
//!
//! La tentation est d'exporter tout ce qu'on peut mesurer. C'est une erreur : une
//! métrique qu'on n'utilise jamais coûte du stockage, du bruit dans les tableaux de
//! bord, et masque celles qui comptent.
//!
//! On n'exporte donc que ce sur quoi on **agirait** :
//!
//! - l'âge de la dernière sauvegarde réussie — une sauvegarde qui ne tourne plus est
//!   invisible jusqu'au jour où on en a besoin ;
//! - l'âge de la dernière **vérification** de restauration — une sauvegarde jamais
//!   restaurée n'est pas une sauvegarde ;
//! - les actions manuelles bloquantes en attente ;
//! - l'occupation disque par nœud (§9bis) ;
//! - les nœuds injoignables.
//!
//! Le CPU et la charge n'y sont pas : ils ne déclenchent aucune décision ici. Docker
//! et le noyau les exposent déjà pour qui veut regarder.
//!
//! ## Sur le format
//!
//! Le texte est produit à la main plutôt qu'avec une bibliothèque cliente. Le format
//! d'exposition Prometheus tient en quelques lignes, et une dépendance de plus pour
//! concaténer des chaînes ne se justifie pas.

use std::fmt::Write as _;

use std::collections::BTreeMap;

use hlb_agent::{DiskPressure, Thresholds};

use crate::agents::AgentStatus;

/// Un échantillon prêt à rendre.
#[derive(Debug, Clone, PartialEq)]
pub struct AppMetrics {
    pub name: String,
    pub status: String,
    pub last_backup_secs: Option<i64>,
    pub last_verification_secs: Option<i64>,
    pub blocking_guides: i64,
}

/// Échappe une valeur d'étiquette Prometheus.
///
/// Un nom d'app ne devrait jamais contenir de guillemet, mais une métrique mal formée
/// fait rejeter **tout** le lot par le collecteur — pas seulement la ligne fautive.
fn label(v: &str) -> String {
    v.replace('\\', r"\\")
        .replace('"', "\\\"")
        .replace('\n', r"\n")
}

fn entete(out: &mut String, nom: &str, aide: &str, genre: &str) {
    let _ = writeln!(out, "# HELP {nom} {aide}");
    let _ = writeln!(out, "# TYPE {nom} {genre}");
}

/// Rend l'ensemble des métriques.
pub fn render(apps: &[AppMetrics], nodes: &BTreeMap<String, AgentStatus>) -> String {
    render_avec_couverture(apps, nodes, &[])
}

/// Rend les métriques, couverture des sauvegardes comprise.
pub fn render_avec_couverture(
    apps: &[AppMetrics],
    nodes: &BTreeMap<String, AgentStatus>,
    couvertures: &[hlb_backup::Couverture],
) -> String {
    let mut o = render_base(apps, nodes);

    entete(
        &mut o,
        "hlb_backup_copies",
        "Nombre de copies À JOUR d'une app. C'est le chiffre du 3-2-1 (§8.1).",
        "gauge",
    );
    for c in couvertures {
        // 🔴 Le nombre de destinations DÉCLARÉES ne dit rien du nombre de copies : une
        // destination en échec est une destination qui ne protège de rien. C'est
        // `copies_a_jour()` qui compte, et c'est ce chiffre qu'attendait la règle
        // `copie-unique` — laquelle interrogeait jusqu'ici une métrique inexistante.
        let _ = writeln!(
            o,
            "hlb_backup_copies{{app=\"{}\"}} {}",
            label(&c.app),
            c.copies_a_jour()
        );
    }

    o
}

fn render_base(apps: &[AppMetrics], nodes: &BTreeMap<String, AgentStatus>) -> String {
    let mut o = String::new();

    entete(
        &mut o,
        "hlb_app_up",
        "1 si l'app est en fonctionnement, 0 sinon.",
        "gauge",
    );
    for a in apps {
        let _ = writeln!(
            o,
            "hlb_app_up{{app=\"{}\",status=\"{}\"}} {}",
            label(&a.name),
            label(&a.status),
            u8::from(a.status == "running")
        );
    }

    entete(
        &mut o,
        "hlb_backup_age_seconds",
        "Âge de la dernière sauvegarde réussie. Absent si aucune n'a jamais réussi.",
        "gauge",
    );
    for a in apps {
        // 🔴 On n'émet RIEN plutôt qu'un 0 ou un -1 quand il n'y a jamais eu de
        // sauvegarde. Un 0 signifierait « sauvegardée à l'instant » — soit
        // exactement le contraire, et l'alerte ne partirait jamais.
        if let Some(s) = a.last_backup_secs {
            let _ = writeln!(
                o,
                "hlb_backup_age_seconds{{app=\"{}\"}} {s}",
                label(&a.name)
            );
        }
    }

    entete(
        &mut o,
        "hlb_backup_verification_age_seconds",
        "Âge de la dernière vérification de restauration réussie.",
        "gauge",
    );
    for a in apps {
        if let Some(s) = a.last_verification_secs {
            let _ = writeln!(
                o,
                "hlb_backup_verification_age_seconds{{app=\"{}\"}} {s}",
                label(&a.name)
            );
        }
    }

    entete(
        &mut o,
        "hlb_blocking_guides",
        "Actions manuelles bloquantes en attente.",
        "gauge",
    );
    for a in apps {
        let _ = writeln!(
            o,
            "hlb_blocking_guides{{app=\"{}\"}} {}",
            label(&a.name),
            a.blocking_guides
        );
    }

    entete(
        &mut o,
        "hlb_node_reachable",
        "1 si l'agent du nœud a répondu au dernier sondage.",
        "gauge",
    );
    for (addr, s) in nodes {
        // 🔴 L'étiquette est l'adresse, pas le nom d'hôte : un nœud injoignable n'a
        // pas de nom d'hôte à donner. Changer d'étiquette selon qu'il répond ou non
        // ferait apparaître deux séries distinctes pour la même machine — et
        // l'alerte « nœud muet » ne se déclencherait jamais.
        let _ = writeln!(
            o,
            "hlb_node_reachable{{node=\"{}\"}} {}",
            label(addr),
            u8::from(s.report().is_some())
        );
    }

    entete(
        &mut o,
        "hlb_disk_used_ratio",
        "Occupation du système de fichiers, sur l'espace réellement utilisable.",
        "gauge",
    );
    for (addr, s) in nodes {
        let Some(r) = s.report() else { continue };
        for d in &r.disks {
            let _ = writeln!(
                o,
                "hlb_disk_used_ratio{{node=\"{}\",path=\"{}\"}} {:.4}",
                label(addr),
                label(&d.path),
                d.used_percent() / 100.0
            );
        }
    }

    entete(
        &mut o,
        "hlb_disk_pressure",
        "Palier de pression disque (§9bis) : 0 sain, 1 avis, 2 récupération, 3 gel, 4 critique.",
        "gauge",
    );
    let seuils = Thresholds::default();
    for (addr, s) in nodes {
        let Some(r) = s.report() else { continue };
        for d in &r.disks {
            let _ = writeln!(
                o,
                "hlb_disk_pressure{{node=\"{}\",path=\"{}\"}} {}",
                label(addr),
                label(&d.path),
                palier(d.pressure(&seuils))
            );
        }
    }

    // ─── Protocole 2 : ce que l'agent sait désormais de son système ─────────
    //
    // 🔴 Chaque mesure est émise UNIQUEMENT si elle existe. Un agent de protocole 1,
    // ou une lecture ratée, ne produit pas de série — plutôt qu'une série à zéro qui
    // se lirait « machine au repos » et rendrait toute alerte muette.

    entete(
        &mut o,
        "hlb_cpu_used_ratio",
        "Occupation CPU sur l'intervalle écoulé. Absente au premier relevé.",
        "gauge",
    );
    for (addr, s) in nodes {
        if let Some(v) = s.report().and_then(|r| r.cpu_occupation) {
            let _ = writeln!(o, "hlb_cpu_used_ratio{{node=\"{}\"}} {v:.4}", label(addr));
        }
    }

    entete(
        &mut o,
        "hlb_load_per_core",
        "Charge à une minute divisée par le nombre de cœurs. 1.0 = pleinement chargé.",
        "gauge",
    );
    for (addr, s) in nodes {
        // La charge PAR CŒUR, jamais la brute : 4 est dramatique sur un cœur et
        // confortable sur seize, et un homelab est fait de machines hétérogènes.
        if let Some(v) = s.report().and_then(|r| r.charge_par_coeur()) {
            let _ = writeln!(o, "hlb_load_per_core{{node=\"{}\"}} {v:.3}", label(addr));
        }
    }

    entete(
        &mut o,
        "hlb_memory_used_ratio",
        "Mémoire utilisée, mesurée sur la mémoire DISPONIBLE et non sur la libre.",
        "gauge",
    );
    for (addr, s) in nodes {
        if let Some(v) = s.report().and_then(|r| r.memoire_utilisee()) {
            let _ = writeln!(
                o,
                "hlb_memory_used_ratio{{node=\"{}\"}} {v:.4}",
                label(addr)
            );
        }
    }

    entete(
        &mut o,
        "hlb_swap_used_ratio",
        "Occupation du swap. Un swap qui sert est un signal AVANT la panne.",
        "gauge",
    );
    for (addr, s) in nodes {
        let Some(r) = s.report() else { continue };
        if let (Some(t), Some(u)) = (r.swap_total_mb, r.swap_utilise_mb) {
            if t > 0 {
                let _ = writeln!(
                    o,
                    "hlb_swap_used_ratio{{node=\"{}\"}} {:.4}",
                    label(addr),
                    u as f64 / t as f64
                );
            }
        }
    }

    entete(
        &mut o,
        "hlb_net_bytes_total",
        "Octets transférés depuis le démarrage du nœud, par interface et par sens.",
        "counter",
    );
    for (addr, s) in nodes {
        let Some(r) = s.report() else { continue };
        for i in &r.interfaces {
            // Un `counter` et non une `gauge` : ce sont des cumuls, et c'est
            // `rate()` qui en tire un débit. Les déclarer en gauge ferait produire à
            // VictoriaMetrics des graphes montants à l'infini.
            let _ = writeln!(
                o,
                "hlb_net_bytes_total{{node=\"{}\",interface=\"{}\",sens=\"rx\"}} {}",
                label(addr),
                label(&i.nom),
                i.rx_octets
            );
            let _ = writeln!(
                o,
                "hlb_net_bytes_total{{node=\"{}\",interface=\"{}\",sens=\"tx\"}} {}",
                label(addr),
                label(&i.nom),
                i.tx_octets
            );
        }
    }

    entete(
        &mut o,
        "hlb_node_uptime_seconds",
        "Depuis combien de temps le nœud tourne. Un redémarrage récent explique beaucoup.",
        "gauge",
    );
    for (addr, s) in nodes {
        if let Some(v) = s
            .report()
            .and_then(|r| r.systeme.as_ref())
            .and_then(|y| y.uptime_s)
        {
            let _ = writeln!(o, "hlb_node_uptime_seconds{{node=\"{}\"}} {v}", label(addr));
        }
    }

    entete(
        &mut o,
        "hlb_agent_protocol",
        "Version du dialogue de l'agent. Un parc dépareillé est un piège (§7bis).",
        "gauge",
    );
    for (addr, s) in nodes {
        if let Some(r) = s.report() {
            let _ = writeln!(
                o,
                "hlb_agent_protocol{{node=\"{}\",version=\"{}\"}} {}",
                label(addr),
                label(&r.agent_version),
                r.protocol
            );
        }
    }

    o
}

/// Un palier en nombre, pour que les seuils d'alerte s'écrivent naturellement
/// (`hlb_disk_pressure >= 3` = « on ne déploie plus »).
pub fn palier_public(p: DiskPressure) -> u8 {
    palier(p)
}

fn palier(p: DiskPressure) -> u8 {
    match p {
        DiskPressure::Normal => 0,
        DiskPressure::Notice => 1,
        DiskPressure::Reclaim => 2,
        DiskPressure::Freeze => 3,
        DiskPressure::Critical => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_measurement_emits_no_series_at_all() {
        // 🔴 La règle centrale de ce module, étendue aux mesures du protocole 2. Une
        // série à zéro se lirait « CPU au repos, mémoire libre, rien ne swappe » : le
        // tableau de bord serait au vert pour un nœud dont on ne sait RIEN, et aucune
        // alerte ne partirait.
        let mut noeuds = BTreeMap::new();
        noeuds.insert(
            "10.0.0.9:8421".to_string(),
            AgentStatus::Reporting(Box::new(hlb_agent::report::NodeReport {
                hostname: "vieux".into(),
                at: 1_000,
                agent_version: "0.1.0".into(),
                protocol: 1,
                ..Default::default()
            })),
        );

        let o = render(&[], &noeuds);
        for absente in [
            "hlb_cpu_used_ratio{",
            "hlb_load_per_core{",
            "hlb_memory_used_ratio{",
            "hlb_swap_used_ratio{",
            "hlb_net_bytes_total{",
            "hlb_node_uptime_seconds{",
        ] {
            assert!(!o.contains(absente), "{absente} émise sans donnée :\n{o}");
        }
        // Mais le nœud reste joignable, et ça doit se voir.
        assert!(o.contains("hlb_node_reachable{node=\"10.0.0.9:8421\"} 1"));
    }

    #[test]
    fn network_counters_are_declared_as_counters() {
        // ⚠️ Ce sont des cumuls depuis le démarrage. Les déclarer en `gauge` ferait
        // produire à VictoriaMetrics des graphes montants à l'infini au lieu d'un
        // débit — et personne ne penserait à regarder le type.
        let mut noeuds = BTreeMap::new();
        noeuds.insert(
            "n:1".to_string(),
            AgentStatus::Reporting(Box::new(hlb_agent::report::NodeReport {
                hostname: "n".into(),
                at: 1,
                protocol: 2,
                interfaces: vec![hlb_agent::systeme::Interface {
                    nom: "eth0".into(),
                    rx_octets: 100,
                    tx_octets: 200,
                }],
                ..Default::default()
            })),
        );
        let o = render(&[], &noeuds);
        assert!(o.contains("# TYPE hlb_net_bytes_total counter"), "{o}");
        assert!(
            o.contains("sens=\"rx\"}} 100".replace("}}", "}").as_str())
                || o.contains("sens=\"rx\"} 100")
        );
        assert!(o.contains("sens=\"tx\"} 200"));
    }

    #[test]
    fn a_node_that_swaps_is_visible_in_the_metrics() {
        let mut noeuds = BTreeMap::new();
        noeuds.insert(
            "n:1".to_string(),
            AgentStatus::Reporting(Box::new(hlb_agent::report::NodeReport {
                hostname: "n".into(),
                at: 1,
                protocol: 2,
                swap_total_mb: Some(1_000),
                swap_utilise_mb: Some(600),
                ..Default::default()
            })),
        );
        let o = render(&[], &noeuds);
        assert!(
            o.contains("hlb_swap_used_ratio{node=\"n:1\"} 0.6000"),
            "{o}"
        );
    }

    #[test]
    fn a_swapless_machine_does_not_divide_by_zero() {
        // Beaucoup de nœuds n'ont pas de swap du tout. Émettre une série serait faux,
        // et diviser par zéro produirait `NaN` — que Prometheus refuse d'ingérer.
        let mut noeuds = BTreeMap::new();
        noeuds.insert(
            "n:1".to_string(),
            AgentStatus::Reporting(Box::new(hlb_agent::report::NodeReport {
                hostname: "n".into(),
                at: 1,
                protocol: 2,
                swap_total_mb: Some(0),
                swap_utilise_mb: Some(0),
                ..Default::default()
            })),
        );
        let o = render(&[], &noeuds);
        assert!(!o.contains("hlb_swap_used_ratio{"), "{o}");
        assert!(!o.contains("NaN"), "{o}");
    }
    use hlb_agent::{DiskUsage, NodeReport};

    fn app(name: &str) -> AppMetrics {
        AppMetrics {
            name: name.into(),
            status: "running".into(),
            last_backup_secs: Some(3600),
            last_verification_secs: Some(86_400),
            blocking_guides: 0,
        }
    }

    fn nodes(v: Vec<(&str, AgentStatus)>) -> BTreeMap<String, AgentStatus> {
        v.into_iter().map(|(a, s)| (a.to_string(), s)).collect()
    }

    fn sain(nom: &str, used: u64, free: u64) -> AgentStatus {
        AgentStatus::Reporting(Box::new(NodeReport {
            hostname: nom.into(),
            at: 0,
            disks: vec![DiskUsage {
                path: "/".into(),
                total_mb: used + free,
                used_mb: used,
                free_mb: free,
            }],
            memory_total_mb: None,
            memory_available_mb: None,
            agent_version: "test".into(),
            protocol: hlb_agent::PROTOCOL,
            ..Default::default()
        }))
    }

    #[test]
    fn a_never_backed_up_app_emits_no_sample() {
        // 🔴 Le piège central de ce module. Un 0 voudrait dire « sauvegardée à
        // l'instant » : l'alerte « sauvegarde trop vieille » ne partirait JAMAIS
        // pour précisément les apps qui n'ont jamais été sauvegardées.
        let mut a = app("gitea");
        a.last_backup_secs = None;

        let m = render(&[a], &BTreeMap::new());
        assert!(!m.contains("hlb_backup_age_seconds{app=\"gitea\"}"), "{m}");
        // L'en-tête reste : un collecteur doit voir la métrique déclarée.
        assert!(m.contains("# TYPE hlb_backup_age_seconds gauge"));
    }

    #[test]
    fn a_backed_up_app_emits_its_age() {
        let m = render(&[app("gitea")], &BTreeMap::new());
        assert!(
            m.contains("hlb_backup_age_seconds{app=\"gitea\"} 3600"),
            "{m}"
        );
        assert!(
            m.contains("hlb_backup_verification_age_seconds{app=\"gitea\"} 86400"),
            "{m}"
        );
    }

    #[test]
    fn a_stopped_app_is_zero() {
        let mut a = app("gitea");
        a.status = "failed".into();
        let m = render(&[a], &BTreeMap::new());
        assert!(
            m.contains("hlb_app_up{app=\"gitea\",status=\"failed\"} 0"),
            "{m}"
        );
    }

    #[test]
    fn an_unreachable_node_is_reported_without_disks() {
        // Un nœud muet ne doit pas produire de métrique disque : la dernière valeur
        // connue serait interprétée comme actuelle.
        let n = AgentStatus::Unreachable {
            detail: "délai dépassé".into(),
        };
        let m = render(&[], &nodes(vec![("node2", n)]));
        assert!(m.contains("hlb_node_reachable{node=\"node2\"} 0"), "{m}");
        assert!(!m.contains("hlb_disk_used_ratio{node=\"node2\""), "{m}");
    }

    #[test]
    fn the_disk_ratio_uses_usable_space() {
        // 12057 utilisés, 6964 libres → 63,4 % de l'utilisable. Sur `total_mb`
        // (qui inclut la réserve root de 5 %), le chiffre serait plus bas.
        let m = render(&[], &nodes(vec![("node1", sain("node1", 12_057, 6_964))]));
        assert!(
            m.contains("hlb_disk_used_ratio{node=\"node1\",path=\"/\"} 0.63"),
            "{m}"
        );
    }

    #[test]
    fn the_pressure_tier_is_exported() {
        // 96 utilisés / 4 libres = 96 % → Critical (§9bis).
        let m = render(&[], &nodes(vec![("node1", sain("node1", 96, 4))]));
        assert!(
            m.contains("hlb_disk_pressure{node=\"node1\",path=\"/\"} 4"),
            "{m}"
        );
    }

    #[test]
    fn every_metric_declares_its_help_and_type() {
        let m = render(
            &[app("gitea")],
            &nodes(vec![("node1", sain("node1", 10, 90))]),
        );
        let noms: Vec<&str> = m
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split(['{', ' ']).next())
            .filter(|s| !s.is_empty())
            .collect();

        for n in noms {
            assert!(
                m.contains(&format!("# TYPE {n} ")),
                "{n} sans # TYPE :\n{m}"
            );
            assert!(
                m.contains(&format!("# HELP {n} ")),
                "{n} sans # HELP :\n{m}"
            );
        }
    }

    #[test]
    fn a_quote_in_a_name_cannot_break_the_batch() {
        // 🔴 Une seule ligne mal formée fait rejeter TOUT le lot par le collecteur,
        // pas seulement la ligne fautive.
        let mut a = app("mechant\"nom");
        a.blocking_guides = 1;
        let m = render(&[a], &BTreeMap::new());
        assert!(m.contains(r#"app="mechant\"nom""#), "{m}");
    }
}
