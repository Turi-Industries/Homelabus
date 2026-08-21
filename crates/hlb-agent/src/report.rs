//! Ce que l'agent rapporte au controller.
//!
//! Volontairement minimal : un rapport qu'on ne sait pas exploiter est du bruit qui
//! coûte de la bande passante et de l'attention. Chaque champ ici alimente une
//! décision concrète.

use serde::{Deserialize, Serialize};

use crate::disk::{DiskPressure, DiskUsage, Thresholds};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
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

    // ─── Protocole 2 ────────────────────────────────────────────────────────
    //
    // 🔴 TOUS `Option` + `serde(default)`. Un agent de protocole 1 ne les envoie pas,
    // et son rapport doit rester lisible : c'est ce qui permet de mettre à jour le
    // controller avant les agents, ou l'inverse, sans que le parc devienne
    // « injoignable » en bloc.
    //
    // Et `Option` plutôt que `0` : « je ne sais pas » et « zéro » ne se lisent pas
    // pareil. Un CPU à 0 % dit « au repos », une case vide dit « à vérifier ».
    /// Nombre de cœurs. Sans lui, la charge n'est pas comparable entre machines.
    #[serde(default)]
    pub cpu_coeurs: Option<u32>,
    #[serde(default)]
    pub charge: Option<crate::systeme::Charge>,
    /// Taux d'occupation CPU dans `[0, 1]`.
    ///
    /// ⚠️ `None` au tout premier relevé : il faut deux lectures de `/proc/stat` pour
    /// calculer une différence.
    #[serde(default)]
    pub cpu_occupation: Option<f64>,
    #[serde(default)]
    pub swap_total_mb: Option<u64>,
    #[serde(default)]
    pub swap_utilise_mb: Option<u64>,
    #[serde(default)]
    pub interfaces: Vec<crate::systeme::Interface>,
    #[serde(default)]
    pub systeme: Option<crate::systeme::Systeme>,
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

    /// La charge rapportée au nombre de cœurs — le seul chiffre comparable entre
    /// machines d'un parc hétérogène.
    pub fn charge_par_coeur(&self) -> Option<f64> {
        self.charge?.par_coeur(self.cpu_coeurs?)
    }

    /// La mémoire utilisée, en fraction de `[0, 1]`.
    ///
    /// ⚠️ Calculée sur la mémoire **disponible**, pas sur « total moins libre » :
    /// Linux garde en cache tout ce qu'il peut, et « libre » y est presque toujours
    /// proche de zéro sur une machine saine. Se fier à « libre » ferait crier au
    /// manque de mémoire en permanence.
    pub fn memoire_utilisee(&self) -> Option<f64> {
        let t = self.memory_total_mb?;
        let d = self.memory_available_mb?;
        (t > 0).then(|| ((t.saturating_sub(d)) as f64 / t as f64).clamp(0.0, 1.0))
    }

    /// La machine échange-t-elle sur le disque ?
    ///
    /// 🔴 Un swap qui commence à servir est un signal AVANT-COUREUR : la machine
    /// ralentit sans être encore en panne, et c'est le moment d'agir. Le seuil est bas
    /// (5 %) pour cette raison — attendre la saturation serait attendre trop tard.
    pub fn echange_sur_disque(&self) -> bool {
        match (self.swap_total_mb, self.swap_utilise_mb) {
            (Some(t), Some(u)) if t > 0 => (u as f64 / t as f64) > 0.05,
            _ => false,
        }
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
            ..Default::default()
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
        assert_eq!(
            r.worst_pressure(&Thresholds::default()),
            DiskPressure::Critical
        );
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
        assert_eq!(
            r.worst_pressure(&Thresholds::default()),
            DiskPressure::Normal
        );
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
    fn a_protocol_1_agent_stays_readable() {
        // 🔴 LE test de compatibilité (§7bis). Sans lui, la première mise à jour du
        // controller rendrait tous les agents « injoignables » — exactement au moment
        // où l'on a besoin de les voir.
        let ancien = r#"{
            "hostname": "small-01",
            "at": 1000,
            "disks": [{"path":"/","total_mb":100,"used_mb":40,"free_mb":60}],
            "memory_total_mb": 4096,
            "memory_available_mb": 2048,
            "agent_version": "0.1.0",
            "protocol": 1
        }"#;
        let r: NodeReport = serde_json::from_str(ancien).expect("un agent v1 reste lisible");
        assert_eq!(r.hostname, "small-01");
        assert_eq!(r.protocol, 1);
        // Les mesures du protocole 2 sont absentes — et c'est ce qu'il faut afficher :
        // « inconnu », pas « 0 % ».
        assert_eq!(r.cpu_occupation, None);
        assert_eq!(r.charge, None);
        assert!(r.interfaces.is_empty());
        // Mais ce qu'il envoyait reste exploitable.
        assert_eq!(r.memoire_utilisee(), Some(0.5));
    }

    #[test]
    fn a_controller_that_predates_a_field_ignores_it() {
        // L'autre sens : un rapport v2 doit rester lisible par un code qui n'en connaît
        // qu'une partie. `deny_unknown_fields` ici casserait la mise à jour dans
        // l'ordre inverse.
        let futur = r#"{
            "hostname": "n1", "at": 1, "disks": [],
            "memory_total_mb": null, "memory_available_mb": null,
            "agent_version": "9.9.9", "protocol": 99,
            "un_champ_du_futur": {"quelconque": true}
        }"#;
        let r: NodeReport = serde_json::from_str(futur).expect("un champ inconnu est ignoré");
        assert_eq!(r.protocol, 99);
    }

    #[test]
    fn memory_pressure_is_measured_on_available_not_free() {
        // ⚠️ Linux garde en cache tout ce qu'il peut : « libre » est presque toujours
        // proche de zéro sur une machine saine. S'y fier ferait crier au manque de
        // mémoire en permanence, et on cesserait d'écouter.
        let mut r = rapport(Vec::new());
        r.memory_total_mb = Some(16_000);
        r.memory_available_mb = Some(4_000);
        assert_eq!(r.memoire_utilisee(), Some(0.75));

        r.memory_available_mb = None;
        assert_eq!(r.memoire_utilisee(), None, "inconnu, pas 100 %");
    }

    #[test]
    fn swapping_is_detected_before_the_machine_is_stuck() {
        // 🔴 Un swap qui commence à servir est un signal avant-coureur : la machine
        // ralentit sans être encore en panne. Attendre la saturation serait attendre
        // trop tard.
        let mut r = rapport(Vec::new());
        r.swap_total_mb = Some(2_000);

        r.swap_utilise_mb = Some(0);
        assert!(!r.echange_sur_disque());
        r.swap_utilise_mb = Some(50);
        assert!(!r.echange_sur_disque(), "2,5 % : du bruit");
        r.swap_utilise_mb = Some(200);
        assert!(r.echange_sur_disque(), "10 % : ça commence");

        // Sans swap configuré, aucune alerte — et surtout pas de division par zéro.
        r.swap_total_mb = Some(0);
        assert!(!r.echange_sur_disque());
    }

    #[test]
    fn load_without_a_core_count_is_not_reported() {
        // Une charge brute sans nombre de cœurs n'est pas comparable : mieux vaut ne
        // rien dire que d'afficher un chiffre qu'on interprétera de travers.
        let mut r = rapport(Vec::new());
        r.charge = Some(crate::systeme::Charge {
            une_min: 8.0,
            cinq_min: 6.0,
            quinze_min: 4.0,
        });
        assert_eq!(r.charge_par_coeur(), None);

        r.cpu_coeurs = Some(4);
        assert_eq!(r.charge_par_coeur(), Some(2.0));
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
