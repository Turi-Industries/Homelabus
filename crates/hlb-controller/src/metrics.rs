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
    v.replace('\\', r"\\").replace('"', "\\\"").replace('\n', r"\n")
}

fn entete(out: &mut String, nom: &str, aide: &str, genre: &str) {
    let _ = writeln!(out, "# HELP {nom} {aide}");
    let _ = writeln!(out, "# TYPE {nom} {genre}");
}

/// Rend l'ensemble des métriques.
pub fn render(apps: &[AppMetrics], nodes: &BTreeMap<String, AgentStatus>) -> String {
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
            let _ = writeln!(o, "hlb_backup_age_seconds{{app=\"{}\"}} {s}", label(&a.name));
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

    o
}

/// Un palier en nombre, pour que les seuils d'alerte s'écrivent naturellement
/// (`hlb_disk_pressure >= 3` = « on ne déploie plus »).
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
        assert!(m.contains("hlb_backup_age_seconds{app=\"gitea\"} 3600"), "{m}");
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
        assert!(m.contains("hlb_app_up{app=\"gitea\",status=\"failed\"} 0"), "{m}");
    }

    #[test]
    fn an_unreachable_node_is_reported_without_disks() {
        // Un nœud muet ne doit pas produire de métrique disque : la dernière valeur
        // connue serait interprétée comme actuelle.
        let n = AgentStatus::Unreachable { detail: "délai dépassé".into() };
        let m = render(&[], &nodes(vec![("node2", n)]));
        assert!(m.contains("hlb_node_reachable{node=\"node2\"} 0"), "{m}");
        assert!(!m.contains("hlb_disk_used_ratio{node=\"node2\""), "{m}");
    }

    #[test]
    fn the_disk_ratio_uses_usable_space() {
        // 12057 utilisés, 6964 libres → 63,4 % de l'utilisable. Sur `total_mb`
        // (qui inclut la réserve root de 5 %), le chiffre serait plus bas.
        let m = render(&[], &nodes(vec![("node1", sain("node1", 12_057, 6_964))]));
        assert!(m.contains("hlb_disk_used_ratio{node=\"node1\",path=\"/\"} 0.63"), "{m}");
    }

    #[test]
    fn the_pressure_tier_is_exported() {
        // 96 utilisés / 4 libres = 96 % → Critical (§9bis).
        let m = render(&[], &nodes(vec![("node1", sain("node1", 96, 4))]));
        assert!(m.contains("hlb_disk_pressure{node=\"node1\",path=\"/\"} 4"), "{m}");
    }

    #[test]
    fn every_metric_declares_its_help_and_type() {
        let m = render(&[app("gitea")], &nodes(vec![("node1", sain("node1", 10, 90))]));
        let noms: Vec<&str> = m
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split(['{', ' ']).next())
            .filter(|s| !s.is_empty())
            .collect();

        for n in noms {
            assert!(m.contains(&format!("# TYPE {n} ")), "{n} sans # TYPE :\n{m}");
            assert!(m.contains(&format!("# HELP {n} ")), "{n} sans # HELP :\n{m}");
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
