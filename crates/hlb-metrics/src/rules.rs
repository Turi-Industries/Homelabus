//! Les règles d'alerte (§8bis).
//!
//! ## 🔴 Pourquoi HomelabUS évalue lui-même, plutôt qu'Alertmanager
//!
//! La chaîne canonique est `vmalert → Alertmanager → webhook → ntfy`. On ne la prend
//! pas, pour une raison précise : `hlb-notify` porte déjà les quatre niveaux du §8bis
//! et les heures calmes, testés. Confier le routage à Alertmanager obligerait à
//! **redire** ces règles dans sa configuration, dans une autre syntaxe, sans test — et
//! deux définitions de « qu'est-ce qui mérite de réveiller quelqu'un » finissent
//! toujours par diverger. On garde donc une seule autorité, et VictoriaMetrics ne sert
//! qu'à ce qu'il fait le mieux : stocker et répondre.
//!
//! ## 🔴 L'invariant central : une métrique absente n'est pas une métrique à zéro
//!
//! C'est le même piège que `hlb_backup_age_seconds` (§8.1) : émettre `0` pour une app
//! jamais sauvegardée signifierait « sauvegardée à l'instant », et l'alerte ne partirait
//! jamais pour les apps les plus à risque. La métrique est donc **absente**.
//!
//! Conséquence directe ici : une règle qui ne trouve rien ne doit **jamais** conclure
//! « tout va bien ». Elle conclut « je ne sais pas », ce qui est un état distinct et
//! visible — voir [`Evaluation::Inconnu`]. Un tableau de bord tout vert parce que la
//! collecte est tombée est exactement la panne que ce module existe pour empêcher.

use hlb_notify::{Level, Notification};

/// Ce qu'une règle conclut après interrogation.
#[derive(Debug, Clone, PartialEq)]
pub enum Evaluation {
    /// Le seuil est respecté.
    Ok,
    /// Le seuil est franchi, avec la valeur observée.
    Declenchee { valeur: f64 },
    /// 🔴 Aucune donnée. **Ce n'est pas `Ok`.**
    ///
    /// La collecte est peut-être tombée, la cible peut-être injoignable. Confondre
    /// avec `Ok` produit un tableau de bord vert pendant que le cluster brûle.
    Inconnu { raison: String },
}

/// La comparaison qui décide du déclenchement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparaison {
    /// Déclenche au-dessus du seuil (âge de sauvegarde, remplissage disque…).
    Depasse,
    /// Déclenche en dessous (nœuds joignables, réplicas vivants…).
    TombeSous,
}

/// Une règle d'alerte.
#[derive(Debug, Clone)]
pub struct Regle {
    /// Identifiant court, stable — sert de sujet de notification.
    pub nom: &'static str,
    /// La requête PromQL à poser.
    pub requete: &'static str,
    pub comparaison: Comparaison,
    pub seuil: f64,
    pub niveau: Level,
    /// Ce que la personne doit comprendre, en une phrase.
    pub explication: &'static str,
    /// 🔴 L'absence de donnée est-elle en soi une alerte ?
    ///
    /// Pour la plupart des règles, oui : si `hlb_app_up` disparaît, c'est que le
    /// controller ou la collecte est tombé, ce qui est plus grave que la plupart des
    /// seuils. Voir [`Regle::juger`].
    pub absence_alarmante: bool,
}

impl Regle {
    /// Traduit un résultat de requête en évaluation.
    ///
    /// `valeurs` est vide quand la requête n'a rien rendu.
    pub fn juger(&self, valeurs: &[f64]) -> Evaluation {
        let Some(pire) = (match self.comparaison {
            // On juge sur le cas le plus défavorable : une seule app sans sauvegarde
            // suffit à mériter l'alerte, la moyenne la noierait.
            Comparaison::Depasse => valeurs.iter().cloned().fold(None, |a: Option<f64>, v| {
                Some(a.map_or(v, |x| x.max(v)))
            }),
            Comparaison::TombeSous => valeurs.iter().cloned().fold(None, |a: Option<f64>, v| {
                Some(a.map_or(v, |x| x.min(v)))
            }),
        }) else {
            return Evaluation::Inconnu {
                raison: "aucune donnée".into(),
            };
        };

        let franchi = match self.comparaison {
            Comparaison::Depasse => pire > self.seuil,
            Comparaison::TombeSous => pire < self.seuil,
        };

        if franchi {
            Evaluation::Declenchee { valeur: pire }
        } else {
            Evaluation::Ok
        }
    }

    /// La notification à envoyer, ou `None` s'il n'y a rien à dire.
    ///
    /// 🔴 Une évaluation `Inconnu` sur une règle `absence_alarmante` produit une
    /// notification **de son propre chef**, distincte du déclenchement normal : « je ne
    /// sais pas » et « tout va bien » ne doivent jamais donner la même sortie.
    pub fn notification(&self, e: &Evaluation) -> Option<Notification> {
        match e {
            Evaluation::Ok => None,

            Evaluation::Declenchee { valeur } => Some(Notification::new(
                self.niveau,
                self.nom,
                self.nom,
                &format!("{} (mesuré : {valeur:.2}, seuil : {})", self.explication, self.seuil),
            )),

            Evaluation::Inconnu { raison } if self.absence_alarmante => Some(Notification::new(
                // 🔴 Le niveau n'est PAS celui de la règle : ne pas savoir est un
                // problème d'observabilité, pas le problème que la règle surveille.
                // Le dire au niveau de la règle laisserait croire que le seuil est
                // franchi, alors qu'on ignore s'il l'est.
                Level::Important,
                self.nom,
                &format!("{} : plus de données", self.nom),
                &format!(
                    "La règle « {} » ne peut plus être évaluée ({raison}). \
                     Ce n'est PAS « tout va bien » : la collecte ou la cible est \
                     probablement tombée, et cette surveillance est aveugle depuis.",
                    self.nom
                ),
            )),

            Evaluation::Inconnu { .. } => None,
        }
    }
}

/// Les règles livrées avec HomelabUS.
///
/// Elles portent sur les métriques que le controller expose déjà : rien à instrumenter
/// de plus, et chacune correspond à une panne qu'on a réellement vue coûter cher.
pub fn regles_par_defaut() -> Vec<Regle> {
    vec![
        Regle {
            nom: "sauvegarde-absente",
            // 🔴 Pas de seuil sur `hlb_backup_age_seconds` : la métrique est ABSENTE
            // quand rien n'a jamais réussi. C'est le compte d'apps connues moins le
            // compte d'apps ayant une sauvegarde qui révèle le trou.
            requete: "count(hlb_app_up) - count(hlb_backup_age_seconds)",
            comparaison: Comparaison::Depasse,
            seuil: 0.0,
            niveau: Level::Critical,
            explication: "Des apps n'ont AUCUNE sauvegarde réussie. \
                          Elles tournent peut-être parfaitement — c'est le pire état \
                          du système, et celui qui paraît le plus sain.",
            absence_alarmante: true,
        },
        Regle {
            nom: "sauvegarde-en-retard",
            requete: "max(hlb_backup_age_seconds)",
            comparaison: Comparaison::Depasse,
            // 48 h : une sauvegarde quotidienne peut sauter une nuit sans que ce soit
            // un incident. Deux, c'est une panne.
            seuil: 172_800.0,
            niveau: Level::Important,
            explication: "Une sauvegarde a plus de 48 h.",
            absence_alarmante: false,
        },
        Regle {
            nom: "verification-perimee",
            // 🔴 Une sauvegarde jamais restaurée n'est pas une sauvegarde, c'est une
            // hypothèse. §8.3.
            requete: "max(hlb_backup_verification_age_seconds)",
            comparaison: Comparaison::Depasse,
            seuil: 2_678_400.0, // 31 jours
            niveau: Level::Important,
            explication: "Aucune restauration vérifiée depuis plus d'un mois. \
                          Une sauvegarde jamais restaurée est une hypothèse.",
            absence_alarmante: false,
        },
        Regle {
            nom: "app-en-echec",
            requete: "min(hlb_app_up)",
            comparaison: Comparaison::TombeSous,
            seuil: 1.0,
            niveau: Level::Critical,
            explication: "Une app est en échec.",
            absence_alarmante: true,
        },
        Regle {
            nom: "noeud-injoignable",
            requete: "min(hlb_node_reachable)",
            comparaison: Comparaison::TombeSous,
            seuil: 1.0,
            niveau: Level::Critical,
            explication: "Un nœud ne répond plus.",
            absence_alarmante: true,
        },
        Regle {
            nom: "disque-plein",
            requete: "max(hlb_disk_used_ratio)",
            comparaison: Comparaison::Depasse,
            // 🔴 85 % et non 95 % : au-delà, PostgreSQL et restic n'ont plus la place
            // de travailler, et c'est précisément le moment où l'on voudrait
            // sauvegarder avant d'intervenir. Alerter trop tard revient à ne pas
            // alerter.
            seuil: 0.85,
            niveau: Level::Important,
            explication: "Un disque dépasse 85 %. Au-delà, sauvegardes et dumps \
                          n'ont plus la place de s'exécuter.",
            absence_alarmante: false,
        },
        Regle {
            nom: "guides-bloquants",
            requete: "sum(hlb_blocking_guides)",
            comparaison: Comparaison::Depasse,
            seuil: 0.0,
            niveau: Level::Info,
            explication: "Des actions manuelles bloquent une installation.",
            absence_alarmante: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regle(comparaison: Comparaison, seuil: f64, absence_alarmante: bool) -> Regle {
        Regle {
            nom: "essai",
            requete: "x",
            comparaison,
            seuil,
            niveau: Level::Critical,
            explication: "explication",
            absence_alarmante,
        }
    }

    #[test]
    fn no_data_is_never_ok() {
        // 🔴 L'invariant du module. Une règle sans donnée ne conclut PAS « tout va
        // bien » : la collecte est peut-être tombée, et un tableau de bord vert
        // pendant que le cluster brûle est la panne qu'on cherche à éviter.
        let e = regle(Comparaison::Depasse, 10.0, true).juger(&[]);
        assert!(matches!(e, Evaluation::Inconnu { .. }), "{e:?}");
        assert_ne!(e, Evaluation::Ok);
    }

    #[test]
    fn missing_data_alerts_on_its_own() {
        // Et cette ignorance se DIT, au lieu d'être avalée en silence.
        let r = regle(Comparaison::Depasse, 10.0, true);
        let n = r
            .notification(&r.juger(&[]))
            .expect("l'absence de donnée doit produire une notification");

        assert!(n.body.contains("PAS « tout va bien »"), "{}", n.body);
        assert!(n.body.contains("aveugle"), "{}", n.body);
    }

    #[test]
    fn not_knowing_is_not_reported_as_the_threshold_being_crossed() {
        // 🔴 Le niveau d'une absence de donnée n'est pas celui de la règle. Envoyer un
        // « critique » ferait croire que le seuil est franchi, alors qu'on ignore
        // justement s'il l'est. C'est un problème d'observabilité, pas de seuil.
        let r = regle(Comparaison::Depasse, 10.0, true);
        assert_eq!(r.niveau, Level::Critical);

        let n = r.notification(&r.juger(&[])).expect("notification");
        assert_eq!(n.level, Level::Important);

        // Le vrai franchissement, lui, garde bien le niveau de la règle.
        let d = r.notification(&r.juger(&[42.0])).expect("notification");
        assert_eq!(d.level, Level::Critical);
    }

    #[test]
    fn silence_is_allowed_only_when_it_was_declared_harmless() {
        // Certaines règles n'ont légitimement rien à dire quand la métrique manque —
        // mais c'est un choix EXPLICITE, jamais le défaut.
        let r = regle(Comparaison::Depasse, 10.0, false);
        assert!(r.notification(&r.juger(&[])).is_none());
    }

    #[test]
    fn the_worst_case_decides_never_the_average() {
        // 🔴 Une seule app sans sauvegarde mérite l'alerte. Une moyenne la noierait
        // sous les apps saines — d'autant plus efficacement qu'il y en a beaucoup.
        let haut = regle(Comparaison::Depasse, 10.0, false);
        assert_eq!(
            haut.juger(&[1.0, 2.0, 99.0]),
            Evaluation::Declenchee { valeur: 99.0 }
        );

        // Et symétriquement pour les seuils bas : un seul nœud tombé suffit.
        let bas = regle(Comparaison::TombeSous, 1.0, false);
        assert_eq!(
            bas.juger(&[1.0, 1.0, 0.0]),
            Evaluation::Declenchee { valeur: 0.0 }
        );
        assert_eq!(bas.juger(&[1.0, 1.0]), Evaluation::Ok);
    }

    #[test]
    fn the_threshold_is_strict() {
        // Pile au seuil, on ne déclenche pas : sinon un disque à exactement 85 %
        // alerterait en permanence sans que rien n'empire.
        let r = regle(Comparaison::Depasse, 0.85, false);
        assert_eq!(r.juger(&[0.85]), Evaluation::Ok);
        assert!(matches!(
            r.juger(&[0.8501]),
            Evaluation::Declenchee { .. }
        ));
    }

    #[test]
    fn never_backed_up_outranks_everything_else() {
        // 🔴 La même hiérarchie que dans l'UI : une app qui tourne parfaitement et n'a
        // aucune sauvegarde est le pire état du système, et celui qui paraît le plus
        // sain sur un tableau de bord.
        let r = regles_par_defaut();
        let absente = r
            .iter()
            .find(|x| x.nom == "sauvegarde-absente")
            .expect("règle présente");

        assert_eq!(absente.niveau, Level::Critical);
        assert!(
            absente.absence_alarmante,
            "si cette règle elle-même devient muette, il faut le savoir"
        );

        let retard = r
            .iter()
            .find(|x| x.nom == "sauvegarde-en-retard")
            .expect("règle présente");
        assert!(
            absente.niveau > retard.niveau,
            "jamais sauvegardée est plus grave qu'en retard"
        );
    }

    #[test]
    fn the_never_backed_up_rule_does_not_read_an_absent_metric() {
        // 🔴 Le cœur du piège : `hlb_backup_age_seconds` est ABSENTE pour une app
        // jamais sauvegardée. Un seuil posé dessus ne verrait donc jamais ces
        // apps-là — exactement celles qu'on veut détecter. Il faut compter l'écart.
        let r = regles_par_defaut();
        let absente = r
            .iter()
            .find(|x| x.nom == "sauvegarde-absente")
            .expect("règle présente");

        assert!(
            absente.requete.contains("count("),
            "la règle doit COMPTER, pas comparer une métrique absente : {}",
            absente.requete
        );
        assert!(absente.requete.contains("hlb_app_up"));
    }

    #[test]
    fn every_rule_explains_itself() {
        // Une alerte qui ne dit pas ce qu'elle veut est une alerte qu'on finit par
        // ignorer, et une alerte ignorée ne protège de rien.
        for r in regles_par_defaut() {
            assert!(!r.explication.is_empty(), "{} sans explication", r.nom);
            assert!(
                r.explication.len() > 15,
                "{} : explication trop courte pour agir",
                r.nom
            );
            assert!(!r.requete.is_empty(), "{} sans requête", r.nom);
        }
    }

    #[test]
    fn a_disk_alert_leaves_room_to_act() {
        // 🔴 Alerter à 95 % revient à ne pas alerter : PostgreSQL et restic n'ont
        // alors plus la place de travailler, et c'est précisément le moment où l'on
        // voudrait sauvegarder avant d'intervenir.
        let r = regles_par_defaut();
        let d = r.iter().find(|x| x.nom == "disque-plein").expect("règle");
        assert!(d.seuil <= 0.85, "seuil trop tardif : {}", d.seuil);
    }
}
