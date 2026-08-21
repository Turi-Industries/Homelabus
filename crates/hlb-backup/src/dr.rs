//! Reprise après sinistre : basculer PostgreSQL sur un petit nœud (§2bis.5).
//!
//! ## Le scénario
//!
//! `big-01` est mort — carte mère, disque, inondation. C'est le seul nœud `heavy`,
//! donc PostgreSQL n'a nulle part où aller : la contrainte de placement
//! `node.labels.tier==heavy` ne correspond plus à rien, et Swarm laisse le service en
//! attente indéfiniment, sans erreur.
//!
//! Le mode dégradé consiste à accepter un PostgreSQL **plus petit** sur un nœud
//! `light` : moins de mémoire, moins de connexions, plus lent — mais qui tourne.
//!
//! Objectif : **RTO ≈ 20 min**, service dégradé mais fonctionnel.
//!
//! ## 🔴 Ce que cette procédure ne fait PAS
//!
//! Elle **ne s'exécute pas toute seule**, et c'est délibéré.
//!
//! Une bascule automatique sur détection de panne est le meilleur moyen de perdre des
//! données : un nœud injoignable pendant deux minutes (redémarrage, câble réseau) ne
//! signifie pas qu'il est mort. Une promotion déclenchée pendant que l'ancien primaire
//! est encore vivant donne **deux PostgreSQL qui écrivent** — un « split-brain ». Les
//! deux jeux de données divergent, et les réconcilier après coup demande de choisir
//! quelles transactions perdre.
//!
//! Ce module calcule donc un plan, dit ce qui va être dégradé, et attend une décision
//! humaine.
//!
//! ## 🔴 Le profil réduit n'est pas une préférence, c'est une contrainte
//!
//! PostgreSQL démarre avec `shared_buffers` par défaut à 128 Mo mais l'image officielle
//! le laisse souvent monter plus haut selon la configuration. Sur un nœud à 4 Go qui
//! fait déjà tourner d'autres services, un PostgreSQL configuré pour 32 Go se fait tuer
//! par l'OOM killer — parfois immédiatement, parfois trois jours plus tard sous charge.
//! C'est pire qu'un refus net : le service paraît reparti.

use crate::Result;

/// Le profil de ressources d'une instance PostgreSQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Nœud `heavy` : le fonctionnement normal.
    Normal,
    /// Nœud `light` en secours : ce qui tient dans 4 Go partagés.
    Minimal,
}

impl Profile {
    /// Choisit le profil d'après la mémoire du nœud d'accueil.
    ///
    /// Le seuil est celui du §2bis.2 pour le tier `heavy`.
    pub fn for_memory(mb: u64) -> Self {
        if mb >= 8192 {
            Self::Normal
        } else {
            Self::Minimal
        }
    }

    /// Les réglages `postgresql.conf` correspondants.
    ///
    /// ⚠️ `max_connections` bas **exige** un PgBouncer devant : sans lui, une app qui
    /// ouvre son pool habituel de 20 connexions épuise les 50 disponibles à la
    /// troisième app, et les suivantes échouent sur « too many clients ».
    pub fn settings(&self) -> Vec<(&'static str, &'static str)> {
        match self {
            Self::Normal => vec![
                ("shared_buffers", "2GB"),
                ("work_mem", "32MB"),
                ("maintenance_work_mem", "512MB"),
                ("max_connections", "200"),
                ("effective_cache_size", "6GB"),
            ],
            Self::Minimal => vec![
                // 🔴 512 Mo et pas plus : le nœud a 4 Go et fait tourner autre chose.
                ("shared_buffers", "512MB"),
                ("work_mem", "8MB"),
                ("maintenance_work_mem", "128MB"),
                // ⚠️ Impose PgBouncer devant, sinon la 3e app n'obtient plus de
                // connexion et échoue sur « too many clients ».
                ("max_connections", "50"),
                ("effective_cache_size", "1GB"),
            ],
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Minimal => "réduit (mode dégradé)",
        }
    }

    /// Ce que l'utilisateur perd en dégradé.
    pub fn tradeoffs(&self) -> Vec<&'static str> {
        match self {
            Self::Normal => Vec::new(),
            Self::Minimal => vec![
                "requêtes analytiques nettement plus lentes (work_mem divisé par 4)",
                "50 connexions au lieu de 200 — PgBouncer devient OBLIGATOIRE",
                "réindexation et VACUUM plus lents (maintenance_work_mem réduit)",
                "aucune marge : une seconde app lourde sur ce nœud le fera tomber",
            ],
        }
    }
}

/// Pourquoi une promotion ne peut pas avoir lieu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocked {
    /// 🔴 L'ancien primaire répond encore.
    PrimaryStillAlive { node: String },
    /// Aucune sauvegarde de base : il n'y a rien à restaurer.
    NoBaseBackup,
    /// Le nœud d'accueil n'a pas assez de mémoire, même en dégradé.
    NotEnoughMemory { node: String, mb: u64, needed_mb: u64 },
    /// Le nœud d'accueil n'est pas joignable.
    TargetUnreachable { node: String },
}

impl Blocked {
    pub fn describe(&self) -> String {
        match self {
            Self::PrimaryStillAlive { node } => format!(
                "🔴 {node} répond encore. Promouvoir maintenant donnerait DEUX PostgreSQL \
                 qui écrivent, et les deux jeux de données divergeraient. Arrête d'abord \
                 l'ancien primaire pour de bon : docker node update --availability drain {node}"
            ),
            Self::NoBaseBackup => "🔴 aucune sauvegarde de base : il n'y a rien à \
                 restaurer. Les journaux WAL seuls ne reconstruisent pas une base."
                .to_string(),
            Self::NotEnoughMemory { node, mb, needed_mb } => format!(
                "🔴 {node} n'a que {mb} Mo, il en faut au moins {needed_mb} même en \
                 profil réduit. Un PostgreSQL qui démarre puis se fait tuer par l'OOM \
                 est pire qu'un refus net : le service paraît reparti."
            ),
            Self::TargetUnreachable { node } => {
                format!("🔴 {node} ne répond pas — on ne bascule pas vers l'inconnu.")
            }
        }
    }
}

/// Mémoire minimale pour un PostgreSQL même réduit.
///
/// En dessous, `shared_buffers=512MB` plus les connexions plus le système ne tiennent
/// pas, et l'OOM killer intervient sous la première charge réelle.
pub const MIN_MEMORY_MB: u64 = 2048;

/// Ce qu'une promotion ferait.
#[derive(Debug, Clone)]
pub struct Plan {
    pub target_node: String,
    pub profile: Profile,
    /// Sauvegarde de base à restaurer.
    pub base_backup: String,
    /// Instant jusqu'auquel les journaux permettent de rejouer.
    pub recover_to: i64,
    /// Apps qui repartiront.
    pub apps_resumed: Vec<String>,
    /// 🔴 Apps mises en pause : elles ne tiennent pas dans le profil réduit.
    pub apps_paused: Vec<String>,
}

impl Plan {
    pub fn describe(&self) -> String {
        let mut s = format!(
            "Promotion de PostgreSQL sur {} en profil {}\n",
            self.target_node,
            self.profile.describe()
        );
        s.push_str(&format!(
            "  base      : {} (rejeu jusqu'à {})\n",
            self.base_backup,
            crate::pitr::iso8601(self.recover_to)
        ));
        s.push_str(&format!("  reprises  : {}\n", liste(&self.apps_resumed)));
        s.push_str(&format!("  en pause  : {}\n", liste(&self.apps_paused)));
        s
    }
}

fn liste(v: &[String]) -> String {
    if v.is_empty() {
        "aucune".to_string()
    } else {
        v.join(", ")
    }
}

/// Un nœud candidat à l'accueil.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub node: String,
    pub memory_mb: u64,
    pub reachable: bool,
}

/// Calcule le plan de promotion, ou dit pourquoi c'est impossible.
///
/// `primary_alive` vient d'une observation réelle du cluster, pas d'une supposition :
/// c'est le garde-fou contre le split-brain.
#[allow(clippy::result_large_err)]
pub fn plan_promotion(
    target: &Candidate,
    primary: Option<&str>,
    primary_alive: bool,
    bases: &[crate::pitr::BaseBackup],
    wal_coverage: Option<i64>,
    apps: &[(String, bool)],
) -> std::result::Result<Plan, Blocked> {
    // 🔴 Dans cet ordre : le split-brain se vérifie AVANT tout le reste. Découvrir
    // que l'ancien primaire est vivant après avoir restauré une base serait trop tard.
    if primary_alive {
        return Err(Blocked::PrimaryStillAlive {
            node: primary.unwrap_or("l'ancien primaire").to_string(),
        });
    }
    if !target.reachable {
        return Err(Blocked::TargetUnreachable {
            node: target.node.clone(),
        });
    }
    if target.memory_mb < MIN_MEMORY_MB {
        return Err(Blocked::NotEnoughMemory {
            node: target.node.clone(),
            mb: target.memory_mb,
            needed_mb: MIN_MEMORY_MB,
        });
    }

    let derniere = bases
        .iter()
        .max_by_key(|b| b.finished_at)
        .ok_or(Blocked::NoBaseBackup)?;

    // La couverture WAL peut aller plus loin que la dernière base ; sinon on s'arrête
    // à la base elle-même. On n'annonce jamais plus que ce qu'on a.
    let recover_to = wal_coverage
        .filter(|c| *c >= derniere.finished_at)
        .unwrap_or(derniere.finished_at);

    let profile = Profile::for_memory(target.memory_mb);

    // En profil réduit, les apps déclarées gourmandes restent en pause : les faire
    // repartir épuiserait les 50 connexions et ferait tomber les autres avec.
    let (paused, resumed): (Vec<_>, Vec<_>) = apps
        .iter()
        .partition(|(_, lourde)| *lourde && profile == Profile::Minimal);

    Ok(Plan {
        target_node: target.node.clone(),
        profile,
        base_backup: derniere.id.clone(),
        recover_to,
        apps_resumed: resumed.into_iter().map(|(n, _)| n.clone()).collect(),
        apps_paused: paused.into_iter().map(|(n, _)| n.clone()).collect(),
    })
}

/// Les réglages à écrire, prêts à poser.
pub fn render_settings(p: Profile) -> Result<String> {
    let mut s = String::from(
        "# Généré par Homelabus (§2bis.5) — profil de ressources PostgreSQL.\n",
    );
    if p == Profile::Minimal {
        s.push_str(
            "# 🔴 MODE DÉGRADÉ. Ces valeurs tiennent dans un nœud « light » qui fait\n\
             # déjà tourner autre chose. Les remonter fera tuer PostgreSQL par l'OOM\n\
             # killer — parfois tout de suite, parfois trois jours plus tard.\n\
             #\n\
             # ⚠️ max_connections=50 EXIGE un PgBouncer devant : sans lui, la troisième\n\
             # app n'obtient plus de connexion et échoue sur « too many clients ».\n",
        );
    }
    for (k, v) in p.settings() {
        s.push_str(&format!("{k} = {v}\n"));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pitr::BaseBackup;

    const J0: i64 = 1_786_881_600;

    fn bases() -> Vec<BaseBackup> {
        vec![
            BaseBackup { id: "base-1".into(), finished_at: J0 },
            BaseBackup { id: "base-2".into(), finished_at: J0 + 3600 },
        ]
    }

    fn petit() -> Candidate {
        Candidate { node: "small-01".into(), memory_mb: 4096, reachable: true }
    }

    fn apps() -> Vec<(String, bool)> {
        vec![
            ("vaultwarden".into(), false),
            ("gitea".into(), true),
            ("vikunja".into(), false),
        ]
    }

    #[test]
    fn a_live_primary_blocks_everything() {
        // 🔴 LE garde-fou. Deux PostgreSQL qui écrivent, ce sont deux jeux de données
        // qui divergent — et réconcilier après coup demande de choisir quelles
        // transactions perdre.
        let e = plan_promotion(&petit(), Some("big-01"), true, &bases(), None, &apps())
            .unwrap_err();

        assert_eq!(e, Blocked::PrimaryStillAlive { node: "big-01".into() });
        assert!(e.describe().contains("DEUX PostgreSQL"), "{}", e.describe());
        // Le message doit dire QUOI FAIRE, pas seulement constater.
        assert!(e.describe().contains("drain"), "{}", e.describe());
    }

    #[test]
    fn the_split_brain_check_comes_first() {
        // Même sans sauvegarde de base et avec un nœud injoignable, c'est le
        // split-brain qui doit être signalé : découvrir que l'ancien primaire est
        // vivant APRÈS avoir restauré serait trop tard.
        let injoignable = Candidate { reachable: false, ..petit() };
        let e = plan_promotion(&injoignable, Some("big-01"), true, &[], None, &[]).unwrap_err();
        assert!(matches!(e, Blocked::PrimaryStillAlive { .. }), "{e:?}");
    }

    #[test]
    fn a_node_too_small_is_refused_rather_than_killed_later() {
        // 🔴 Un PostgreSQL qui démarre puis se fait tuer par l'OOM est pire qu'un
        // refus : le service paraît reparti.
        let minuscule = Candidate { memory_mb: 1024, ..petit() };
        let e = plan_promotion(&minuscule, None, false, &bases(), None, &apps()).unwrap_err();

        assert!(matches!(e, Blocked::NotEnoughMemory { .. }), "{e:?}");
        assert!(e.describe().contains("OOM"), "{}", e.describe());
    }

    #[test]
    fn wal_alone_promotes_nothing() {
        let e = plan_promotion(&petit(), None, false, &[], Some(J0), &apps()).unwrap_err();
        assert_eq!(e, Blocked::NoBaseBackup);
    }

    #[test]
    fn a_small_node_gets_the_reduced_profile() {
        let p = plan_promotion(&petit(), None, false, &bases(), None, &apps()).expect("plan");
        assert_eq!(p.profile, Profile::Minimal);
        assert_eq!(p.base_backup, "base-2", "la base la PLUS RÉCENTE");
    }

    #[test]
    fn a_big_node_keeps_the_normal_profile() {
        let gros = Candidate { node: "big-02".into(), memory_mb: 32768, reachable: true };
        let p = plan_promotion(&gros, None, false, &bases(), None, &apps()).expect("plan");
        assert_eq!(p.profile, Profile::Normal);
        // Rien n'est mis en pause : le nœud tient la charge.
        assert!(p.apps_paused.is_empty(), "{:?}", p.apps_paused);
    }

    #[test]
    fn heavy_apps_stay_paused_in_degraded_mode() {
        // 🔴 Les faire repartir épuiserait les 50 connexions et ferait tomber les
        // autres avec — un mode dégradé qui dégrade tout n'a aucun intérêt.
        let p = plan_promotion(&petit(), None, false, &bases(), None, &apps()).expect("plan");
        assert_eq!(p.apps_paused, vec!["gitea"]);
        assert_eq!(p.apps_resumed, vec!["vaultwarden", "vikunja"]);
    }

    #[test]
    fn the_recovery_point_never_claims_more_than_the_wal_covers() {
        // Sans couverture WAL, on s'arrête à la base : annoncer plus promettrait un
        // rejeu qu'on ne peut pas faire.
        let p = plan_promotion(&petit(), None, false, &bases(), None, &apps()).expect("plan");
        assert_eq!(p.recover_to, J0 + 3600);

        // Avec des journaux qui vont plus loin, on en profite.
        let p = plan_promotion(&petit(), None, false, &bases(), Some(J0 + 7200), &apps())
            .expect("plan");
        assert_eq!(p.recover_to, J0 + 7200);

        // Une couverture ANTÉRIEURE à la base est ignorée : elle ne sert à rien.
        let p = plan_promotion(&petit(), None, false, &bases(), Some(J0 - 100), &apps())
            .expect("plan");
        assert_eq!(p.recover_to, J0 + 3600);
    }

    #[test]
    fn the_reduced_profile_fits_a_small_node() {
        let s = Profile::Minimal.settings();
        let sb = s.iter().find(|(k, _)| *k == "shared_buffers").expect("shared_buffers");
        assert_eq!(sb.1, "512MB");

        let mc = s.iter().find(|(k, _)| *k == "max_connections").expect("max_connections");
        assert_eq!(mc.1, "50");
    }

    #[test]
    fn the_degraded_settings_warn_about_pgbouncer() {
        // ⚠️ Sans PgBouncer, la 3e app n'obtient plus de connexion et échoue sur
        // « too many clients » — une panne qui ne ressemble pas à un manque de RAM.
        let s = render_settings(Profile::Minimal).expect("rendu");
        assert!(s.contains("PgBouncer"), "{s}");
        assert!(s.contains("MODE DÉGRADÉ"), "{s}");
        assert!(s.contains("OOM"), "{s}");
    }

    #[test]
    fn the_normal_settings_carry_no_warning() {
        let s = render_settings(Profile::Normal).expect("rendu");
        assert!(!s.contains("DÉGRADÉ"), "{s}");
        assert!(s.contains("shared_buffers = 2GB"), "{s}");
    }

    #[test]
    fn the_tradeoffs_are_spelled_out() {
        // L'utilisateur doit savoir ce qu'il perd AVANT de valider, pas le découvrir.
        let t = Profile::Minimal.tradeoffs();
        assert!(!t.is_empty());
        assert!(t.iter().any(|x| x.contains("PgBouncer")), "{t:?}");
        assert!(Profile::Normal.tradeoffs().is_empty());
    }

    #[test]
    fn the_profile_threshold_matches_the_tier_rule() {
        // Cohérent avec §2bis.2 : au-dessus de 8 Go, le nœud est « heavy ».
        assert_eq!(Profile::for_memory(8192), Profile::Normal);
        assert_eq!(Profile::for_memory(8191), Profile::Minimal);
        assert_eq!(Profile::for_memory(4096), Profile::Minimal);
    }
}
