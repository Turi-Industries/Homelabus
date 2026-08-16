//! Vérifications avant bootstrap (§2ter.4).
//!
//! Le principe du plan : **tu valides un plan, tu ne subis pas un script.** Ces
//! contrôles s'exécutent avant toute modification et produisent un verdict lisible.
//!
//! Chaque refus ici correspond à un piège documenté — pas à de la prudence
//! décorative. Un bootstrap qui échoue à mi-parcours sur une machine à moitié
//! configurée est bien pire qu'un refus net au départ.

use crate::distro::Distro;

/// Gravité d'un constat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Information : rien à faire.
    Ok,
    /// À savoir, mais on continue.
    Warning,
    /// 🔴 On refuse de continuer.
    Blocking,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
    /// Quoi faire. Vide quand il n'y a rien à faire.
    pub remedy: Option<String>,
}

impl Check {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self { name, level: Level::Ok, detail: detail.into(), remedy: None }
    }
    fn warn(name: &'static str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            name,
            level: Level::Warning,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }
    fn block(name: &'static str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            name,
            level: Level::Blocking,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }

    pub fn describe(&self) -> String {
        let marque = match self.level {
            Level::Ok => "✓",
            Level::Warning => "🟠",
            Level::Blocking => "🔴",
        };
        let mut s = format!("{marque} {}: {}", self.name, self.detail);
        if let Some(r) = &self.remedy {
            s.push_str(&format!("\n     → {r}"));
        }
        s
    }
}

/// Ce qu'on a observé sur la machine, avant de juger.
#[derive(Debug, Clone, Default)]
pub struct Observation {
    pub os_release: String,
    /// Sortie de `docker --version`, si la commande existe.
    pub docker_version: Option<String>,
    /// Docker installé via snap ? Confinement incompatible avec certains montages.
    pub docker_is_snap: bool,
    /// Podman présent à la place de Docker ?
    pub podman_present: bool,
    pub total_memory_mb: Option<u64>,
    pub free_disk_mb: Option<u64>,
    /// L'horloge est-elle synchronisée ? (`timedatectl`, `chronyc`…)
    pub clock_synced: Option<bool>,
    /// Utilisateur effectif. Le bootstrap a besoin des droits d'administration.
    pub is_root: bool,
    /// cgroups v2 : Docker moderne en dépend pour les limites de ressources.
    pub cgroups_v2: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub checks: Vec<Check>,
    pub distro: Option<Distro>,
}

impl Report {
    /// Le bootstrap peut-il démarrer ?
    pub fn can_proceed(&self) -> bool {
        !self.checks.iter().any(|c| c.level == Level::Blocking)
    }

    pub fn blocking(&self) -> Vec<&Check> {
        self.checks.iter().filter(|c| c.level == Level::Blocking).collect()
    }

    pub fn warnings(&self) -> Vec<&Check> {
        self.checks.iter().filter(|c| c.level == Level::Warning).collect()
    }
}

/// Mémoire minimale pour un nœud utilisable. En dessous, Swarm démarre mais tout
/// s'écroule dès la première app.
const MIN_MEMORY_MB: u64 = 1800;

/// Espace minimal : les images Docker sont volumineuses, et un disque plein est la
/// panne n°1 des homelabs (§9bis).
const MIN_DISK_MB: u64 = 8192;

pub fn run(obs: &Observation) -> Report {
    let mut checks = Vec::new();

    // 1. Droits. Sans eux, rien de ce qui suit ne peut aboutir.
    if obs.is_root {
        checks.push(Check::ok("privilèges", "administrateur"));
    } else {
        checks.push(Check::block(
            "privilèges",
            "le bootstrap installe des paquets et configure le réseau",
            "relance avec sudo, ou depuis un compte administrateur",
        ));
    }

    // 2. Distribution.
    let distro = Distro::parse(&obs.os_release);
    match &distro {
        Some(d) => checks.push(Check::ok(
            "distribution",
            format!("{} (famille {})", d.pretty_name, d.family.as_str()),
        )),
        None => checks.push(Check::block(
            "distribution",
            "impossible d'identifier la distribution depuis /etc/os-release",
            "distribution non prise en charge — ouvre une issue avec le contenu \
             de /etc/os-release",
        )),
    }

    // 3. 🔴 Podman. Il émule l'API conteneur mais PAS Swarm : on échouerait bien
    // plus tard, avec un message incompréhensible.
    if obs.podman_present && obs.docker_version.is_none() {
        checks.push(Check::block(
            "moteur de conteneurs",
            "Podman détecté, Docker absent — Podman n'implémente pas Swarm",
            "installe Docker Engine, ou choisis un autre nœud",
        ));
    }

    // 4. 🔴 Docker en snap. Le confinement empêche certains montages de volumes,
    // et l'échec se produit au déploiement d'une app, pas ici.
    if obs.docker_is_snap {
        checks.push(Check::block(
            "docker",
            "Docker installé via snap : son confinement casse les montages de volumes",
            "snap remove docker, puis laisse HomelabUS installer le paquet officiel",
        ));
    } else {
        match &obs.docker_version {
            Some(v) => checks.push(Check::ok("docker", format!("présent ({v})"))),
            None => checks.push(Check::ok("docker", "absent — sera installé")),
        }
    }

    // 5. Mémoire.
    match obs.total_memory_mb {
        Some(m) if m < MIN_MEMORY_MB => checks.push(Check::block(
            "mémoire",
            format!("{m} Mo — insuffisant pour un nœud Swarm utilisable"),
            format!("au moins {MIN_MEMORY_MB} Mo sont nécessaires"),
        )),
        Some(m) if m < 4096 => checks.push(Check::warn(
            "mémoire",
            format!("{m} Mo — nœud contraint"),
            "réserve ce nœud au tier « light » : pas de base de données dessus (§2bis.2)",
        )),
        Some(m) => checks.push(Check::ok("mémoire", format!("{m} Mo"))),
        None => checks.push(Check::warn(
            "mémoire",
            "non détectée",
            "vérifie manuellement qu'il y a au moins 2 Go",
        )),
    }

    // 6. Disque.
    match obs.free_disk_mb {
        Some(d) if d < MIN_DISK_MB => checks.push(Check::block(
            "disque",
            format!("{d} Mo libres — les images Docker n'y tiendront pas"),
            format!("libère de l'espace : au moins {MIN_DISK_MB} Mo"),
        )),
        Some(d) => checks.push(Check::ok("disque", format!("{d} Mo libres"))),
        None => checks.push(Check::warn("disque", "non détecté", "vérifie l'espace libre")),
    }

    // 7. 🔴 Horloge. Une dérive casse le chiffrement Raft de Swarm ET la validation
    // des certificats. Le symptôme — « certificat non encore valide », nœuds qui se
    // désynchronisent — n'évoque jamais l'horloge.
    match obs.clock_synced {
        Some(true) => checks.push(Check::ok("horloge", "synchronisée")),
        Some(false) => checks.push(Check::warn(
            "horloge",
            "non synchronisée — casse Swarm et la validation TLS",
            "chrony sera installé ; vérifie ensuite que la synchronisation aboutit",
        )),
        None => checks.push(Check::warn(
            "horloge",
            "état de synchronisation inconnu",
            "assure-toi qu'un service NTP tourne",
        )),
    }

    // 8. cgroups v2 — nécessaire aux limites de ressources.
    match obs.cgroups_v2 {
        Some(true) => checks.push(Check::ok("cgroups", "v2")),
        Some(false) => checks.push(Check::warn(
            "cgroups",
            "v1 — les limites de ressources par conteneur seront partielles",
            "un redémarrage avec systemd.unified_cgroup_hierarchy=1 les active. \
             🔴 HomelabUS ne redémarre JAMAIS une machine tout seul : à toi de le faire",
        )),
        None => {}
    }

    Report { checks, distro }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saine() -> Observation {
        Observation {
            os_release: "ID=debian\nPRETTY_NAME=\"Debian 12\"\n".into(),
            docker_version: Some("27.3.1".into()),
            docker_is_snap: false,
            podman_present: false,
            total_memory_mb: Some(16384),
            free_disk_mb: Some(102_400),
            clock_synced: Some(true),
            is_root: true,
            cgroups_v2: Some(true),
        }
    }

    #[test]
    fn a_healthy_machine_passes() {
        let r = run(&saine());
        assert!(r.can_proceed(), "{:?}", r.blocking());
        assert!(r.warnings().is_empty());
        assert!(r.distro.is_some());
    }

    #[test]
    fn without_privileges_nothing_starts() {
        let mut o = saine();
        o.is_root = false;
        let r = run(&o);
        assert!(!r.can_proceed());
        assert!(r.blocking()[0].remedy.as_ref().expect("remède").contains("sudo"));
    }

    #[test]
    fn podman_without_docker_is_refused_early() {
        // 🔴 Podman n'implémente pas Swarm. Sans ce contrôle, l'échec surviendrait
        // bien plus tard avec un message incompréhensible.
        let mut o = saine();
        o.podman_present = true;
        o.docker_version = None;
        let r = run(&o);

        assert!(!r.can_proceed());
        assert!(r.blocking()[0].detail.contains("Swarm"));
    }

    #[test]
    fn podman_alongside_docker_is_fine() {
        // Avoir les deux n'est pas un problème : c'est Docker qu'on utilisera.
        let mut o = saine();
        o.podman_present = true;
        assert!(run(&o).can_proceed());
    }

    #[test]
    fn snap_docker_is_refused() {
        // Le confinement snap casse les montages de volumes — et l'échec se
        // produirait au déploiement d'une app, pas ici.
        let mut o = saine();
        o.docker_is_snap = true;
        let r = run(&o);

        assert!(!r.can_proceed());
        let b = r.blocking()[0];
        assert!(b.detail.contains("snap"));
        assert!(b.remedy.as_ref().expect("remède").contains("snap remove"));
    }

    #[test]
    fn an_unknown_distribution_is_refused_rather_than_guessed() {
        let mut o = saine();
        o.os_release = "ID=exotique\n".into();
        let r = run(&o);
        assert!(!r.can_proceed());
        assert!(r.distro.is_none());
    }

    #[test]
    fn a_small_node_warns_without_blocking() {
        // Les nœuds à 4 Go du plan doivent passer, avec un avertissement utile.
        let mut o = saine();
        o.total_memory_mb = Some(3900);
        let r = run(&o);

        assert!(r.can_proceed());
        let w = r.warnings();
        assert!(w.iter().any(|c| c.remedy.as_ref().is_some_and(|r| r.contains("light"))));
    }

    #[test]
    fn a_tiny_node_is_refused() {
        let mut o = saine();
        o.total_memory_mb = Some(512);
        assert!(!run(&o).can_proceed());
    }

    #[test]
    fn insufficient_disk_blocks() {
        let mut o = saine();
        o.free_disk_mb = Some(2000);
        let r = run(&o);
        assert!(!r.can_proceed());
        assert!(r.blocking()[0].detail.contains("images Docker"));
    }

    #[test]
    fn an_unsynced_clock_warns_loudly() {
        // Pas bloquant — chrony sera installé — mais il faut le dire : le symptôme
        // d'une dérive n'évoque jamais l'horloge.
        let mut o = saine();
        o.clock_synced = Some(false);
        let r = run(&o);

        assert!(r.can_proceed());
        assert!(r.warnings().iter().any(|c| c.name == "horloge"));
    }

    #[test]
    fn cgroups_v1_says_a_reboot_is_needed_but_never_does_it() {
        // 🔴 HomelabUS ne redémarre jamais une machine tout seul.
        let mut o = saine();
        o.cgroups_v2 = Some(false);
        let r = run(&o);

        assert!(r.can_proceed());
        let w = r.warnings().into_iter().find(|c| c.name == "cgroups").expect("constat");
        let remede = w.remedy.as_ref().expect("remède");
        assert!(remede.contains("JAMAIS"), "{remede}");
        assert!(remede.contains("à toi de le faire"));
    }

    #[test]
    fn every_problem_comes_with_a_remedy() {
        // Un diagnostic sans remède force l'utilisateur à chercher seul.
        let mut o = saine();
        o.is_root = false;
        o.docker_is_snap = true;
        o.total_memory_mb = Some(100);
        o.clock_synced = Some(false);

        for c in run(&o).checks.iter().filter(|c| c.level != Level::Ok) {
            assert!(c.remedy.is_some(), "{} sans remède", c.name);
        }
    }

    #[test]
    fn descriptions_are_readable() {
        let r = run(&saine());
        for c in &r.checks {
            assert!(c.describe().contains(c.name));
        }
    }
}
