//! Ce que l'agent rapporte au controller.
//!
//! Volontairement minimal : un rapport qu'on ne sait pas exploiter est du bruit qui
//! coûte de la bande passante et de l'attention. Chaque champ ici alimente une
//! décision concrète.

use serde::{Deserialize, Serialize};

use crate::disk::{DiskPressure, DiskUsage, Thresholds};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeReport {
    pub hostname: String,
    /// Horodatage Unix. Sert à détecter un agent muet, pas seulement à dater.
    pub at: u64,
    pub disks: Vec<DiskUsage>,
    pub memory_total_mb: Option<u64>,
    pub memory_available_mb: Option<u64>,
    /// Version de l'agent : un cluster avec des agents dépareillés est un piège
    /// (§7bis, compatibilité N/N+1).
    pub agent_version: String,
    /// Version du DIALOGUE, distincte de celle du binaire (§7bis).
    ///
    /// ⚠️ `serde(default)` : un agent antérieur à ce champ ne l'envoie pas, et sa
    /// réponse doit rester lisible. Sans ça, la première mise à jour rendrait tous
    /// les agents « injoignables » — exactement au moment où on en a besoin.
    #[serde(default)]
    pub protocol: u32,
}

impl NodeReport {
    /// La pression la plus forte parmi tous les systèmes de fichiers.
    ///
    /// C'est le pire qui compte : un `/var/lib/docker` saturé casse tout, même si
    /// `/` est à moitié vide.
    pub fn worst_pressure(&self, t: &Thresholds) -> DiskPressure {
        self.disks
            .iter()
            .map(|d| d.pressure(t))
            .max()
            .unwrap_or(DiskPressure::Normal)
    }

    /// Ce nœud peut-il accueillir un déploiement ?
    pub fn allows_deploy(&self, t: &Thresholds) -> bool {
        self.worst_pressure(t).allows_deploy()
    }

    /// Les systèmes de fichiers qui posent problème, du pire au moins grave.
    pub fn problems(&self, t: &Thresholds) -> Vec<(&DiskUsage, DiskPressure)> {
        let mut p: Vec<_> = self
            .disks
            .iter()
            .map(|d| (d, d.pressure(t)))
            .filter(|(_, pr)| *pr > DiskPressure::Normal)
            .collect();
        // Décroissant : le plus critique en premier, c'est ce qu'on lit d'abord.
        p.sort_by_key(|(_, pression)| std::cmp::Reverse(*pression));
        p
    }

    /// L'agent a-t-il donné signe de vie récemment ?
    ///
    /// Un agent silencieux est une information : le nœud est peut-être injoignable,
    /// et ses données ne sont donc plus sauvegardées.
    pub fn is_stale(&self, now: u64, max_age_secs: u64) -> bool {
        now.saturating_sub(self.at) > max_age_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disque(path: &str, total: u64, used: u64) -> DiskUsage {
        DiskUsage {
            path: path.into(),
            total_mb: total,
            used_mb: used,
            free_mb: total - used,
        }
    }

    fn rapport(disks: Vec<DiskUsage>) -> NodeReport {
        NodeReport {
            hostname: "node1".into(),
            at: 1_000_000,
            disks,
            memory_total_mb: Some(16384),
            memory_available_mb: Some(8192),
            agent_version: "0.1.0".into(),
            protocol: 1,
        }
    }

    #[test]
    fn the_worst_filesystem_decides() {
        // 🔴 Un /var/lib/docker saturé casse tout, même si / est à moitié vide.
        let r = rapport(vec![
            disque("/", 100_000, 30_000),
            // 48/50 Go = 96 %, au-delà du seuil critique.
            disque("/var/lib/docker", 50_000, 48_000),
        ]);
        assert_eq!(r.worst_pressure(&Thresholds::default()), DiskPressure::Critical);
        assert!(!r.allows_deploy(&Thresholds::default()));
    }

    #[test]
    fn a_healthy_node_accepts_deployments() {
        let r = rapport(vec![disque("/", 100_000, 40_000)]);
        assert!(r.allows_deploy(&Thresholds::default()));
        assert!(r.problems(&Thresholds::default()).is_empty());
    }

    #[test]
    fn problems_are_sorted_worst_first() {
        let r = rapport(vec![
            disque("/a", 100_000, 78_000),
            disque("/b", 100_000, 96_000),
            disque("/c", 100_000, 87_000),
        ]);
        let p = r.problems(&Thresholds::default());
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].0.path, "/b", "le plus critique en premier");
        assert_eq!(p[0].1, DiskPressure::Critical);
    }

    #[test]
    fn a_node_without_disks_is_not_assumed_broken() {
        let r = rapport(Vec::new());
        assert_eq!(r.worst_pressure(&Thresholds::default()), DiskPressure::Normal);
        assert!(r.allows_deploy(&Thresholds::default()));
    }

    #[test]
    fn a_silent_agent_is_detected() {
        // Un agent muet signifie peut-être un nœud injoignable — dont les données ne
        // sont donc plus sauvegardées.
        let r = rapport(vec![disque("/", 100, 10)]);
        assert!(!r.is_stale(1_000_060, 120));
        assert!(r.is_stale(1_000_300, 120));
    }

    #[test]
    fn a_clock_going_backwards_does_not_panic() {
        // Deux machines mal synchronisées peuvent donner un « maintenant » antérieur.
        let r = rapport(vec![disque("/", 100, 10)]);
        assert!(!r.is_stale(999_000, 120));
    }

    #[test]
    fn a_report_survives_a_json_roundtrip() {
        // L'agent et le controller peuvent avoir des versions différentes : le
        // format doit rester lisible des deux côtés (§7bis).
        let r = rapport(vec![disque("/", 100_000, 50_000)]);
        let j = serde_json::to_string(&r).expect("sérialisable");
        let relu: NodeReport = serde_json::from_str(&j).expect("relisible");
        assert_eq!(relu, r);
    }
}
