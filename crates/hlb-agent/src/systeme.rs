//! Ce que le nœud sait de lui-même : charge, mémoire, réseau, versions.
//!
//! ## 🔴 `Option` partout, et jamais un zéro
//!
//! Chaque mesure peut manquer : un `/proc` absent (macOS en développement), un fichier
//! illisible, une première lecture qui n'a pas de précédente à comparer. Dans **tous**
//! ces cas la valeur est `None`, jamais `0.0`.
//!
//! C'est la même règle qu'ailleurs dans le projet : une métrique absente vaut mieux
//! qu'un zéro. Un CPU à « 0 % » se lit « machine au repos », soit exactement le
//! contraire de « je ne sais pas ». Sur un tableau de bord, c'est la différence entre
//! une case vide qu'on va vérifier et un voyant vert qui rassure à tort.
//!
//! ## Pourquoi `/proc` et pas Docker
//!
//! L'agent ne parle **jamais** à Docker. Lui donner le socket ferait de chaque nœud une
//! porte d'entrée vers le démon, avec les privilèges que cela suppose. Les statistiques
//! par conteneur viennent de cadvisor, déployé comme une app du catalogue et scrapé par
//! VictoriaMetrics — pas de notre agent.

use serde::{Deserialize, Serialize};

/// La charge moyenne du système.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Charge {
    pub une_min: f64,
    pub cinq_min: f64,
    pub quinze_min: f64,
}

impl Charge {
    /// La charge rapportée au nombre de cœurs.
    ///
    /// 🔴 C'est **le seul chiffre comparable** entre machines. Une charge de 4 est
    /// dramatique sur un cœur et confortable sur seize ; afficher la valeur brute
    /// côte à côte pour des nœuds hétérogènes — ce qu'est un homelab — ne veut rien
    /// dire.
    pub fn par_coeur(&self, coeurs: u32) -> Option<f64> {
        (coeurs > 0).then(|| self.une_min / f64::from(coeurs))
    }
}

/// Le compteur d'une interface réseau.
///
/// ⚠️ Des compteurs **cumulés depuis le démarrage**, pas un débit. Le débit se calcule
/// par différence entre deux relevés, et c'est au consommateur de le faire : l'agent ne
/// sait pas quand il sera interrogé la prochaine fois.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub nom: String,
    pub rx_octets: u64,
    pub tx_octets: u64,
}

/// L'identité du système.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Systeme {
    #[serde(default)]
    pub noyau: Option<String>,
    #[serde(default)]
    pub distro: Option<String>,
    /// Depuis combien de temps la machine tourne.
    ///
    /// Utile pour une raison précise : un nœud qui vient de redémarrer explique
    /// beaucoup de choses, et on ne pense pas toujours à le vérifier.
    #[serde(default)]
    pub uptime_s: Option<u64>,
}

/// L'état du CPU au moment de la lecture.
///
/// Les compteurs de `/proc/stat` sont cumulés : le taux d'occupation est une
/// **différence** entre deux relevés. Cette structure porte le relevé brut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelevéCpu {
    pub total: u64,
    pub inactif: u64,
}

impl RelevéCpu {
    /// Le taux d'occupation entre deux relevés, dans `[0, 1]`.
    ///
    /// 🔴 Rend `None` quand le calcul n'a pas de sens — pas de relevé précédent,
    /// compteurs qui ont reculé (redémarrage), aucun temps écoulé. Un `0.0` dans ces
    /// cas ferait passer une machine dont on ne sait rien pour une machine au repos.
    pub fn occupation(&self, precedent: &RelevéCpu) -> Option<f64> {
        let dt = self.total.checked_sub(precedent.total)?;
        let di = self.inactif.checked_sub(precedent.inactif)?;
        if dt == 0 {
            return None;
        }
        Some(((dt - di.min(dt)) as f64 / dt as f64).clamp(0.0, 1.0))
    }
}

/// Lit `/proc/loadavg`.
pub fn charge() -> Option<Charge> {
    let s = std::fs::read_to_string("/proc/loadavg").ok()?;
    let mut m = s.split_whitespace();
    Some(Charge {
        une_min: m.next()?.parse().ok()?,
        cinq_min: m.next()?.parse().ok()?,
        quinze_min: m.next()?.parse().ok()?,
    })
}

/// Le nombre de cœurs vus par le noyau.
pub fn coeurs() -> Option<u32> {
    std::thread::available_parallelism()
        .ok()
        .map(|n| n.get() as u32)
}

/// Lit la ligne `cpu` agrégée de `/proc/stat`.
pub fn releve_cpu() -> Option<RelevéCpu> {
    let s = std::fs::read_to_string("/proc/stat").ok()?;
    parser_cpu(&s)
}

/// Extrait le relevé de la première ligne `cpu ` (agrégée, avec l'espace).
///
/// ⚠️ « cpu » **avec l'espace** : sans lui, on attraperait `cpu0`, le premier cœur, et
/// on rapporterait la charge d'un seul cœur pour celle de la machine.
pub fn parser_cpu(proc_stat: &str) -> Option<RelevéCpu> {
    let ligne = proc_stat.lines().find(|l| l.starts_with("cpu "))?;
    let champs: Vec<u64> = ligne
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    if champs.len() < 4 {
        return None;
    }
    // Ordre de /proc/stat : user, nice, system, idle, iowait, irq, softirq, steal…
    // `iowait` compte comme inactif : le CPU y attend un disque, il n'est pas occupé.
    let inactif = champs[3] + champs.get(4).copied().unwrap_or(0);
    Some(RelevéCpu {
        total: champs.iter().sum(),
        inactif,
    })
}

/// Lit `/proc/net/dev`.
pub fn interfaces() -> Vec<Interface> {
    std::fs::read_to_string("/proc/net/dev")
        .map(|s| parser_interfaces(&s))
        .unwrap_or_default()
}

/// Extrait les interfaces de `/proc/net/dev`.
///
/// ⚠️ `lo` est écartée : le trafic de boucle locale gonfle les chiffres sans rien dire
/// du réseau réel — sur un nœud Swarm, il représente l'essentiel du volume.
pub fn parser_interfaces(proc_net_dev: &str) -> Vec<Interface> {
    proc_net_dev
        .lines()
        .skip(2) // Deux lignes d'en-tête.
        .filter_map(|l| {
            let (nom, reste) = l.split_once(':')?;
            let nom = nom.trim();
            if nom == "lo" || nom.is_empty() {
                return None;
            }
            let champs: Vec<u64> = reste
                .split_whitespace()
                .filter_map(|v| v.parse().ok())
                .collect();
            // Colonnes : rx_bytes … (8 champs) … tx_bytes …
            Some(Interface {
                nom: nom.to_string(),
                rx_octets: *champs.first()?,
                tx_octets: *champs.get(8)?,
            })
        })
        .collect()
}

/// Lit l'uptime en secondes.
pub fn uptime_s() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/uptime").ok()?;
    s.split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|v| v as u64)
}

/// Le noyau et la distribution.
pub fn systeme() -> Systeme {
    Systeme {
        noyau: std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        distro: std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| pretty_name(&s)),
        uptime_s: uptime_s(),
    }
}

/// Extrait `PRETTY_NAME` de `/etc/os-release`.
pub fn pretty_name(os_release: &str) -> Option<String> {
    os_release.lines().find_map(|l| {
        l.strip_prefix("PRETTY_NAME=")
            .map(|v| v.trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    })
}

/// La mémoire d'échange, en mégaoctets.
pub fn swap_mb() -> (Option<u64>, Option<u64>) {
    let Ok(s) = std::fs::read_to_string("/proc/meminfo") else {
        return (None, None);
    };
    let ko = |cle: &str| -> Option<u64> {
        s.lines()
            .find(|l| l.starts_with(cle))?
            .split_whitespace()
            .nth(1)?
            .parse::<u64>()
            .ok()
    };
    let total = ko("SwapTotal:").map(|v| v / 1024);
    let libre = ko("SwapFree:").map(|v| v / 1024);
    // L'utilisé se calcule ; l'exposer directement évite que chaque consommateur
    // refasse la soustraction, et se trompe de sens une fois sur deux.
    let utilise = match (total, libre) {
        (Some(t), Some(l)) => Some(t.saturating_sub(l)),
        _ => None,
    };
    (total, utilise)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_usage_needs_two_readings() {
        // 🔴 La toute première lecture n'a rien à comparer. Rendre 0 % ferait passer un
        // nœud dont on ne sait rien pour un nœud au repos.
        let a = RelevéCpu {
            total: 1000,
            inactif: 800,
        };
        let b = RelevéCpu {
            total: 1100,
            inactif: 850,
        };
        // 100 ticks écoulés, 50 inactifs → 50 % occupé.
        assert_eq!(b.occupation(&a), Some(0.5));
    }

    #[test]
    fn a_reboot_does_not_produce_an_absurd_figure() {
        // Après un redémarrage, les compteurs repartent de zéro : la soustraction
        // déborderait, et un `wrapping_sub` donnerait un taux aberrant.
        let avant = RelevéCpu {
            total: 1_000_000,
            inactif: 900_000,
        };
        let apres = RelevéCpu {
            total: 500,
            inactif: 400,
        };
        assert_eq!(apres.occupation(&avant), None);
    }

    #[test]
    fn two_identical_readings_yield_nothing_rather_than_idle() {
        // Aucun temps écoulé : on ne sait rien. « 0 % » dirait « au repos ».
        let a = RelevéCpu {
            total: 1000,
            inactif: 800,
        };
        assert_eq!(a.occupation(&a), None);
    }

    #[test]
    fn the_aggregate_cpu_line_is_read_not_the_first_core() {
        // ⚠️ « cpu » AVEC l'espace : sans lui, on attrape `cpu0` et on rapporte la
        // charge d'un seul cœur pour celle de la machine.
        let proc_stat = "cpu  100 20 30 800 50 0 0 0 0 0\n\
                         cpu0 10 2 3 80 5 0 0 0 0 0\n\
                         cpu1 90 18 27 720 45 0 0 0 0 0\n\
                         intr 12345\n";
        let r = parser_cpu(proc_stat).expect("relevé");
        assert_eq!(r.total, 1000, "la ligne agrégée, pas cpu0");
        assert_eq!(r.inactif, 850, "idle + iowait");
    }

    #[test]
    fn iowait_counts_as_idle() {
        // Le CPU y attend un disque : il n'est pas occupé. Le compter comme du travail
        // ferait paraître saturée une machine qui attend son NAS.
        let sans = parser_cpu("cpu  100 0 0 900 0 0 0 0\n").expect("relevé");
        let avec = parser_cpu("cpu  100 0 0 400 500 0 0 0\n").expect("relevé");
        assert_eq!(sans.inactif, avec.inactif);
    }

    #[test]
    fn a_missing_proc_file_yields_nothing_rather_than_zero() {
        assert_eq!(parser_cpu(""), None);
        assert_eq!(parser_cpu("intr 12345\n"), None);
        assert_eq!(parser_cpu("cpu  1 2\n"), None, "champs insuffisants");
    }

    #[test]
    fn loopback_traffic_is_excluded() {
        // 🔴 Sur un nœud Swarm, `lo` représente l'essentiel du volume : l'inclure
        // rendrait le chiffre réseau inutilisable.
        let dev = "Inter-|   Receive                    |  Transmit\n\
                   face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets\n\
                   \x20 lo: 999999 100 0 0 0 0 0 0 999999 100 0 0 0 0 0 0\n\
                   \x20eth0: 1234 10 0 0 0 0 0 0 5678 20 0 0 0 0 0 0\n";
        let v = parser_interfaces(dev);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].nom, "eth0");
        assert_eq!(v[0].rx_octets, 1234);
        assert_eq!(v[0].tx_octets, 5678);
    }

    #[test]
    fn load_is_comparable_only_once_divided_by_cores() {
        // 🔴 Une charge de 4 est dramatique sur un cœur et confortable sur seize. Un
        // homelab est fait de machines hétérogènes : la valeur brute côte à côte ne
        // veut rien dire.
        let c = Charge {
            une_min: 4.0,
            cinq_min: 3.0,
            quinze_min: 2.0,
        };
        assert_eq!(c.par_coeur(1), Some(4.0));
        assert_eq!(c.par_coeur(16), Some(0.25));
        assert_eq!(c.par_coeur(0), None, "aucune division par zéro");
    }

    #[test]
    fn the_distribution_name_is_read_without_its_quotes() {
        let os = "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\n";
        assert_eq!(
            pretty_name(os).as_deref(),
            Some("Debian GNU/Linux 12 (bookworm)")
        );
        assert_eq!(pretty_name("ID=debian\n"), None);
        assert_eq!(pretty_name("PRETTY_NAME=\"\"\n"), None, "vide vaut absent");
    }
}
