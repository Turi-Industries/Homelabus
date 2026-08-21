//! Le deadman switch (§8bis).
//!
//! ## 🔴 Le problème que rien d'autre ne résout
//!
//! Toutes les alertes de [`crate::rules`] partagent un défaut fatal : **elles tournent
//! sur le controller**. Si le controller meurt, se fige, perd son réseau ou voit son
//! disque saturer, il n'émet plus aucune alerte — et le silence est indiscernable du
//! bon fonctionnement. Le tableau de bord reste au vert, le téléphone reste muet, et
//! l'on apprend la panne en essayant d'utiliser un service, parfois des semaines après.
//!
//! Un deadman switch inverse la charge de la preuve. Au lieu d'attendre un message
//! disant « ça va mal », on attend un message disant « ça va » — et c'est **son
//! absence** qui déclenche l'alerte. Le silence devient un signal.
//!
//! ## 🔴 Trois règles, dont chacune annule le dispositif si on l'oublie
//!
//! **1. Le veilleur ne tourne PAS sur la machine qu'il surveille.** C'est toute
//! l'idée. Un deadman hébergé par le controller meurt avec lui, et l'on a construit
//! une élaborate machinerie qui ne détecte rien. Le NAS est le veilleur naturel : il
//! est déjà la cible des sauvegardes, donc déjà une autre machine, déjà allumée en
//! permanence.
//!
//! **2. L'alerte du veilleur ne passe PAS par le système surveillé.** Si le NAS
//! constate le silence puis demande au controller de notifier, il n'y a pas d'alerte —
//! le controller est précisément ce qui est mort. Le veilleur doit avoir sa propre
//! voie de sortie (ses propres identifiants ntfy), et [`script_veilleur`] la lui donne.
//!
//! **3. Le battement n'est PAS un minuteur.** C'est le point le plus facile à rater.
//! Un battement émis par une simple boucle temporelle prouve seulement qu'un fil
//! d'exécution vit encore : le controller peut avoir une boucle de réconciliation
//! bloquée, un Docker injoignable et une base illisible, et continuer à battre
//! joyeusement. Le battement doit être **conditionné à une vérification réussie** —
//! voir [`Battement::emettre_si`].
//!
//! ## Ce que ça ne résout pas, et qu'il vaut mieux savoir
//!
//! Le veilleur peut mourir à son tour, et son silence à lui n'est surveillé par
//! personne. On ne supprime donc pas le point unique de défaillance : on le **déplace**
//! d'un système complexe (le controller, qui orchestre, sauvegarde, met à jour) vers un
//! script trivial qui ne fait qu'une chose. C'est un gain réel, et ce n'est pas une
//! garantie. Le dire est plus utile que de laisser croire à une preuve.

use std::fmt::Write as _;

/// Intervalle recommandé entre deux battements.
///
/// Cinq minutes : assez court pour que la panne se voie dans l'heure, assez long pour
/// qu'une reprise de service ou un redémarrage n'émette pas de fausse alerte.
pub const INTERVALLE_BATTEMENT_S: u64 = 300;

/// Au-delà de ce silence, le veilleur alerte.
///
/// 🔴 Trois battements manqués, pas un. Un seul battement raté est le fonctionnement
/// normal d'un réseau domestique : redémarrage, mise à jour, Wi-Fi qui hoquette. Une
/// alerte à chaque hoquet est une alerte qu'on finit par couper — et un deadman coupé
/// ne protège de rien.
pub const SILENCE_MAX_S: u64 = INTERVALLE_BATTEMENT_S * 3 + 60;

/// Ce qui doit être vrai pour qu'un battement parte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sante {
    /// La base d'état répond.
    pub etat_lisible: bool,
    /// L'orchestrateur répond.
    pub orchestrateur_joignable: bool,
    /// La dernière boucle de réconciliation est allée au bout.
    pub reconciliation_recente: bool,
}

impl Sante {
    /// Le système est-il en état de prétendre qu'il va bien ?
    pub fn est_saine(&self) -> bool {
        self.etat_lisible && self.orchestrateur_joignable && self.reconciliation_recente
    }

    /// Ce qui cloche, pour les journaux.
    pub fn manquements(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if !self.etat_lisible {
            v.push("base d'état illisible");
        }
        if !self.orchestrateur_joignable {
            v.push("orchestrateur injoignable");
        }
        if !self.reconciliation_recente {
            v.push("réconciliation bloquée");
        }
        v
    }
}

/// Le battement émis par le système surveillé.
pub struct Battement {
    /// Où pousser le battement. Sur le NAS, hors du système surveillé.
    pub url: String,
}

/// Ce qu'il faut faire d'un battement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emission {
    /// À envoyer.
    Envoyer,
    /// 🔴 À **taire**. Le silence est le signal : se taire déclenchera l'alerte du
    /// veilleur, et c'est exactement ce qu'on veut quand le système va mal.
    Taire { manquements: Vec<&'static str> },
}

impl Battement {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// Décide d'émettre, ou de se taire.
    ///
    /// 🔴 **Le battement est conditionnel, jamais périodique.** Un battement émis par
    /// un simple minuteur prouve qu'un fil d'exécution vit, rien de plus : le
    /// controller peut avoir sa boucle de réconciliation bloquée, son Docker
    /// injoignable et sa base illisible, et battre imperturbablement. Le deadman
    /// resterait vert sur un système inutilisable, ce qui est pire que pas de deadman
    /// du tout — parce qu'on lui fait confiance.
    pub fn emettre_si(sante: &Sante) -> Emission {
        if sante.est_saine() {
            Emission::Envoyer
        } else {
            Emission::Taire {
                manquements: sante.manquements(),
            }
        }
    }
}

/// L'état constaté par le veilleur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veille {
    /// Battement frais.
    Vivant { depuis_s: u64 },
    /// 🔴 Silence prolongé : le système surveillé est probablement mort.
    Silencieux { depuis_s: u64 },
    /// 🔴 **Aucun battement n'a JAMAIS été reçu.**
    ///
    /// Distinct de `Silencieux`, et pour la même raison que `NeverSucceeded` l'est de
    /// `Stale` dans l'UI : un deadman jamais armé n'a jamais rien protégé. Le
    /// confondre avec un silence récent laisserait croire à une panne fraîche, alors
    /// que le dispositif n'a tout simplement jamais fonctionné — l'installation était
    /// mauvaise depuis le premier jour, et personne ne l'a su.
    JamaisArme,
}

impl Veille {
    /// Juge la fraîcheur du dernier battement.
    ///
    /// `dernier_s` est `None` quand aucun battement n'a jamais été reçu.
    pub fn juger(dernier_s: Option<u64>, maintenant_s: u64) -> Self {
        let Some(dernier) = dernier_s else {
            return Self::JamaisArme;
        };

        let age = maintenant_s.saturating_sub(dernier);
        if age > SILENCE_MAX_S {
            Self::Silencieux { depuis_s: age }
        } else {
            Self::Vivant { depuis_s: age }
        }
    }

    pub fn est_alarmant(&self) -> bool {
        !matches!(self, Self::Vivant { .. })
    }

    /// Le message à pousser, ou `None` si tout va bien.
    pub fn message(&self) -> Option<String> {
        match self {
            Self::Vivant { .. } => None,

            Self::Silencieux { depuis_s } => Some(format!(
                "🔴 Homelabus ne donne plus signe de vie depuis {} minutes.\n\n\
                 Le controller est probablement arrêté, figé, ou coupé du réseau. \
                 Tant qu'il l'est, AUCUNE autre alerte ne peut partir : ni sauvegarde \
                 manquée, ni app tombée, ni disque plein. Ce silence est donc le seul \
                 signal disponible.",
                depuis_s / 60
            )),

            Self::JamaisArme => Some(
                "🔴 Le deadman switch n'a JAMAIS reçu de battement.\n\n\
                 Ce n'est pas une panne récente : le dispositif n'a jamais fonctionné, \
                 donc il n'a jamais rien protégé. Vérifie que le controller connaît \
                 bien l'URL du veilleur, et qu'il peut l'atteindre."
                    .into(),
            ),
        }
    }
}

/// Le script à poser sur le NAS.
///
/// 🔴 Délibérément trivial : `curl`, `date`, une comparaison. Ce script est le dernier
/// maillon, celui que personne ne surveille — chaque ligne qu'on y ajoute est une ligne
/// qui peut le faire échouer en silence. Sa bêtise est une propriété, pas une limite.
///
/// ⚠️ Il pousse vers ntfy **directement**, sans passer par Homelabus : demander au
/// système surveillé de relayer l'alerte de sa propre mort ne peut pas marcher.
///
/// 🔴 **Et si ntfy est injoignable ?** Constaté en exécutant réellement le script : un
/// `curl` en échec est avalé par la redirection, et l'alerte disparaît sans laisser de
/// trace — le veilleur ne peut pas signaler qu'il n'a pas pu signaler. D'où le repli
/// sur **stderr**, que cron envoie par courriel : une seconde voie qui ne partage ni le
/// réseau ni le service de la première, pour une ligne de shell.
pub fn script_veilleur(fichier_battement: &str, ntfy_url: &str, sujet: &str) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "#!/bin/sh");
    let _ = writeln!(s, "# Veilleur Homelabus (§8bis) — à lancer par cron sur le NAS.");
    let _ = writeln!(s, "#");
    let _ = writeln!(s, "# 🔴 Ce script NE DOIT PAS tourner sur la machine qu'il");
    let _ = writeln!(s, "#    surveille : il mourrait avec elle, et ne détecterait rien.");
    let _ = writeln!(s, "#");
    let _ = writeln!(s, "# 🔴 Il pousse vers ntfy DIRECTEMENT. Passer par Homelabus pour");
    let _ = writeln!(s, "#    signaler que Homelabus est mort ne peut pas fonctionner.");
    let _ = writeln!(s, "#");
    let _ = writeln!(s, "# Pose-le en cron toutes les 5 minutes :");
    let _ = writeln!(s, "#   */5 * * * * /chemin/veilleur.sh");
    let _ = writeln!(s);
    let _ = writeln!(s, "set -u");
    let _ = writeln!(s, "BATTEMENT='{fichier_battement}'");
    let _ = writeln!(s, "SILENCE_MAX={SILENCE_MAX_S}");
    let _ = writeln!(s);
    let _ = writeln!(s, "if [ ! -f \"$BATTEMENT\" ]; then");
    let _ = writeln!(s, "  # Jamais armé : distinct d'un silence récent. Le dispositif");
    let _ = writeln!(s, "  # n'a jamais fonctionné, donc n'a jamais rien protégé.");
    let _ = writeln!(s, "  curl -fsS -H 'Priority: urgent' -H 'Title: {sujet} jamais armé' \\");
    let _ = writeln!(s, "    -d 'Aucun battement reçu, jamais. Le deadman ne protège rien.' \\");
    let _ = writeln!(s, "    '{ntfy_url}' >/dev/null 2>&1 \\");
    let _ = writeln!(s, "    || echo 'VEILLEUR: ntfy injoignable, alerte PERDUE' >&2");
    let _ = writeln!(s, "  exit 1");
    let _ = writeln!(s, "fi");
    let _ = writeln!(s);
    let _ = writeln!(s, "MAINTENANT=$(date +%s)");
    let _ = writeln!(s, "DERNIER=$(cat \"$BATTEMENT\" 2>/dev/null || echo 0)");
    let _ = writeln!(s, "AGE=$((MAINTENANT - DERNIER))");
    let _ = writeln!(s);
    let _ = writeln!(s, "if [ \"$AGE\" -gt \"$SILENCE_MAX\" ]; then");
    let _ = writeln!(s, "  curl -fsS -H 'Priority: urgent' -H 'Title: {sujet} silencieux' \\");
    let _ = writeln!(s, "    -d \"Aucun signe de vie depuis $((AGE / 60)) minutes. \\");
    let _ = writeln!(s, "Tant que dure ce silence, AUCUNE autre alerte ne peut partir.\" \\");
    let _ = writeln!(s, "    '{ntfy_url}' >/dev/null 2>&1 \\");
    let _ = writeln!(s, "    || echo 'VEILLEUR: ntfy injoignable, alerte PERDUE' >&2");
    let _ = writeln!(s, "  exit 1");
    let _ = writeln!(s, "fi");
    let _ = writeln!(s);
    let _ = writeln!(s, "exit 0");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saine() -> Sante {
        Sante {
            etat_lisible: true,
            orchestrateur_joignable: true,
            reconciliation_recente: true,
        }
    }

    #[test]
    fn a_sick_system_stays_silent() {
        // 🔴 LE point du module. Un battement périodique prouve qu'un fil vit, pas que
        // le système marche : le controller peut avoir sa réconciliation bloquée et
        // son Docker injoignable, et battre imperturbablement. Le deadman resterait
        // vert sur un système inutilisable — pire que pas de deadman, car on s'y fie.
        assert_eq!(Battement::emettre_si(&saine()), Emission::Envoyer);

        for casser in [
            |s: &mut Sante| s.etat_lisible = false,
            |s: &mut Sante| s.orchestrateur_joignable = false,
            |s: &mut Sante| s.reconciliation_recente = false,
        ] {
            let mut s = saine();
            casser(&mut s);
            assert!(
                matches!(Battement::emettre_si(&s), Emission::Taire { .. }),
                "un système en panne ne doit PAS battre : {s:?}"
            );
        }
    }

    #[test]
    fn silence_says_what_was_wrong() {
        let mut s = saine();
        s.orchestrateur_joignable = false;
        s.reconciliation_recente = false;

        let Emission::Taire { manquements } = Battement::emettre_si(&s) else {
            panic!("doit se taire");
        };
        assert_eq!(manquements.len(), 2);
        assert!(manquements.contains(&"orchestrateur injoignable"));
    }

    #[test]
    fn never_armed_is_distinct_from_recently_silent() {
        // 🔴 Même distinction que `NeverSucceeded` / `Stale` dans l'UI. Un deadman
        // jamais armé n'a jamais rien protégé : le confondre avec une panne fraîche
        // ferait chercher un incident récent, alors que l'installation était mauvaise
        // depuis le premier jour.
        assert_eq!(Veille::juger(None, 1_000_000), Veille::JamaisArme);

        let silencieux = Veille::juger(Some(0), SILENCE_MAX_S + 100);
        assert!(matches!(silencieux, Veille::Silencieux { .. }));
        assert_ne!(silencieux, Veille::JamaisArme);

        // Et les deux messages doivent être différents, pas seulement les variantes.
        let m_jamais = Veille::JamaisArme.message().expect("message");
        let m_silence = silencieux.message().expect("message");
        assert!(m_jamais.contains("JAMAIS"), "{m_jamais}");
        assert!(m_jamais.contains("jamais rien protégé"), "{m_jamais}");
        assert_ne!(m_jamais, m_silence);
    }

    #[test]
    fn one_missed_beat_is_not_an_alert() {
        // 🔴 Une alerte à chaque hoquet du Wi-Fi est une alerte qu'on finit par
        // couper. Un deadman coupé ne protège de rien.
        let un_rate = INTERVALLE_BATTEMENT_S + 30;
        assert!(!Veille::juger(Some(0), un_rate).est_alarmant());

        let deux_rates = INTERVALLE_BATTEMENT_S * 2 + 30;
        assert!(!Veille::juger(Some(0), deux_rates).est_alarmant());

        // Trois, en revanche, ce n'est plus un hoquet.
        assert!(Veille::juger(Some(0), SILENCE_MAX_S + 1).est_alarmant());
    }

    #[test]
    fn a_healthy_watch_says_nothing() {
        let v = Veille::juger(Some(1000), 1060);
        assert_eq!(v, Veille::Vivant { depuis_s: 60 });
        assert!(v.message().is_none());
        assert!(!v.est_alarmant());
    }

    #[test]
    fn a_clock_going_backwards_does_not_panic() {
        // Un NAS qui resynchronise son horloge peut rendre un battement « futur ».
        // Une soustraction qui déborde ferait planter le veilleur — donc plus de
        // surveillance du tout, en silence.
        let v = Veille::juger(Some(2000), 1000);
        assert_eq!(v, Veille::Vivant { depuis_s: 0 });
    }

    #[test]
    fn the_watcher_never_routes_through_the_watched_system() {
        // 🔴 Demander au système surveillé de signaler sa propre mort ne peut pas
        // marcher. Le veilleur doit pousser vers ntfy directement.
        let s = script_veilleur("/var/lib/hlb/battement", "https://ntfy.sh/mon-sujet", "Homelabus");

        assert!(s.contains("https://ntfy.sh/mon-sujet"), "{s}");
        assert!(
            !s.contains("hlb ") && !s.contains("localhost"),
            "le veilleur ne doit dépendre de rien du système surveillé : {s}"
        );
        assert!(s.contains("NE DOIT PAS tourner sur la machine"), "{s}");
    }

    #[test]
    fn the_watcher_distinguishes_never_armed_too() {
        // La distinction doit survivre jusque dans le script, sinon elle ne sert à
        // rien : c'est lui qui parle à l'humain.
        let s = script_veilleur("/b", "https://ntfy.sh/x", "Homelabus");
        assert!(s.contains("jamais armé"), "{s}");
        assert!(s.contains("if [ ! -f"), "il doit tester l'absence du fichier : {s}");
    }

    #[test]
    fn a_lost_alert_leaves_a_trace() {
        // 🔴 Constaté en exécutant le script pour de vrai : `curl … >/dev/null 2>&1`
        // avale son propre échec. Si ntfy est injoignable — panne réseau, sujet
        // supprimé, service tombé — l'alerte disparaît sans laisser de trace, et le
        // veilleur ne peut pas signaler qu'il n'a pas pu signaler.
        //
        // stderr est le repli : cron l'envoie par courriel, et cette voie-là ne partage
        // ni le réseau ni le service de ntfy.
        let s = script_veilleur("/b", "https://ntfy.sh/x", "Homelabus");
        assert_eq!(
            s.matches("alerte PERDUE").count(),
            2,
            "les DEUX chemins d'alerte doivent avoir leur repli : {s}"
        );
        assert!(s.contains(">&2"), "le repli doit passer par stderr : {s}");
    }

    #[test]
    fn the_watcher_stays_trivial() {
        // 🔴 C'est le dernier maillon, celui que personne ne surveille. Chaque ligne
        // ajoutée est une ligne qui peut le faire échouer en silence. Sa bêtise est
        // une propriété.
        let s = script_veilleur("/b", "https://ntfy.sh/x", "Homelabus");
        let code: Vec<&str> = s
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
            .collect();

        assert!(
            code.len() < 25,
            "le veilleur doit rester trivial, {} lignes de code",
            code.len()
        );
        assert!(s.starts_with("#!/bin/sh"), "pas de dépendance à bash");
    }
}
