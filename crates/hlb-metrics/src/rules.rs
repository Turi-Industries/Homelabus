//! The alert rules.
//!
//! ## 🔴 Why Homelabus evaluates them itself rather than using Alertmanager
//!
//! The canonical chain is `vmalert → Alertmanager → webhook → ntfy`. It is not taken
//! here, for a precise reason: `hlb-notify` already carries the four levels and the
//! quiet hours, tested. Handing routing to Alertmanager would mean **restating** those
//! rules in its configuration, in another syntax, untested - and two definitions of
//! "what deserves waking someone" always end up diverging. So there is one authority,
//! and VictoriaMetrics only does what it does best: store and answer.
//!
//! ## 🔴 The central invariant: an absent metric is not a metric at zero
//!
//! Same trap as `hlb_backup_age_seconds`: emitting `0` for an app that was never backed
//! up would mean "backed up just now", and the alert would never fire for the apps most
//! at risk. So the metric is **absent**.
//!
//! Direct consequence here: a rule that finds nothing must **never** conclude "all is
//! well". It concludes "I do not know", which is a distinct and visible state - see
//! [`Evaluation::Inconnu`]. An all-green dashboard because the scrape died is exactly
//! the failure this module exists to prevent.

use hlb_notify::{Level, Notification};

/// What a rule concludes after querying.
#[derive(Debug, Clone, PartialEq)]
pub enum Evaluation {
    /// The threshold is respected.
    Ok,
    /// The threshold is breached, with the observed value.
    Declenchee { valeur: f64 },
    /// 🔴 No data. **This is not `Ok`.**
    ///
    /// The scrape may have died, the target may be unreachable. Confusing this with
    /// `Ok` produces a green dashboard while the cluster burns.
    Inconnu { raison: String },
}

/// The comparison that decides whether to fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparaison {
    /// Fires above the threshold (backup age, disk usage...).
    Depasse,
    /// Fires below it (reachable nodes, live replicas...).
    TombeSous,
}

/// An alert rule.
#[derive(Debug, Clone)]
pub struct Regle {
    /// Identifiant court, stable — sert de sujet de notification.
    pub nom: &'static str,
    /// The PromQL query to run.
    pub requete: &'static str,
    pub comparaison: Comparaison,
    pub seuil: f64,
    pub niveau: Level,
    /// Ce que la personne doit comprendre, en une phrase.
    pub explication: &'static str,
    /// 🔴 Is the absence of data itself an alert?
    ///
    /// For most rules, yes: if `hlb_app_up` disappears, the controller or the scrape
    /// has died, which is more serious than most thresholds. See [`Regle::juger`].
    pub absence_alarmante: bool,
}

impl Regle {
    /// Turns a query result into an evaluation.
    ///
    /// `valeurs` is empty when the query returned nothing.
    pub fn juger(&self, valeurs: &[f64]) -> Evaluation {
        let Some(pire) = (match self.comparaison {
            // Judged on the worst case: a single app with no backup deserves the
            // alert, and an average would drown it.
            Comparaison::Depasse => valeurs
                .iter()
                .cloned()
                .fold(None, |a: Option<f64>, v| Some(a.map_or(v, |x| x.max(v)))),
            Comparaison::TombeSous => valeurs
                .iter()
                .cloned()
                .fold(None, |a: Option<f64>, v| Some(a.map_or(v, |x| x.min(v)))),
        }) else {
            return Evaluation::Inconnu {
                raison: "no data".into(),
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

    /// The notification to send, or `None` when there is nothing to say.
    ///
    /// 🔴 An `Inconnu` evaluation on an `absence_alarmante` rule produces a
    /// notification **of its own**, distinct from a normal firing: "I do not know" and
    /// "all is well" must never produce the same output.
    pub fn notification(&self, e: &Evaluation) -> Option<Notification> {
        match e {
            Evaluation::Ok => None,

            Evaluation::Declenchee { valeur } => Some(Notification::new(
                self.niveau,
                self.nom,
                self.nom,
                &format!(
                    "{} (measured: {valeur:.2}, threshold: {})",
                    self.explication, self.seuil
                ),
            )),

            Evaluation::Inconnu { raison } if self.absence_alarmante => Some(Notification::new(
                // 🔴 The level is NOT the rule's: not knowing is an observability
                // problem, not the problem the rule watches. Reporting it at the rule's
                // level would suggest the threshold is breached, when we do not know
                // whether it is.
                Level::Important,
                self.nom,
                &format!("{}: no more data", self.nom),
                &format!(
                    "Rule \"{}\" can no longer be evaluated ({raison}). \
                     This is NOT \"all is well\": the scrape or the target has \
                     probably died, and this check has been blind ever since.",
                    self.nom
                ),
            )),

            Evaluation::Inconnu { .. } => None,
        }
    }
}

/// The rules shipped with Homelabus.
///
/// They query metrics the controller already exposes: nothing more to instrument, and
/// each corresponds to a failure that really cost something.
pub fn regles_par_defaut() -> Vec<Regle> {
    vec![
        Regle {
            nom: "sauvegarde-absente",
            // 🔴 No threshold on `hlb_backup_age_seconds`: the metric is ABSENT when
            // nothing ever succeeded. It is the count of known apps minus the count of
            // apps with a backup that reveals the gap.
            requete: "count(hlb_app_up) - count(hlb_backup_age_seconds)",
            comparaison: Comparaison::Depasse,
            seuil: 0.0,
            niveau: Level::Critical,
            explication: "Some apps have NO successful backup. \
                          They may be running perfectly - which is the worst state \
                          of the system, and the one that looks healthiest.",
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
            nom: "copie-unique",
            // 🔴 The number of CONFIGURED destinations says nothing about the number
            // of copies. Three destinations with two failing is not 3-2-1 - and it is
            // exactly the state an aggregated dashboard would pass off as healthy.
            requete: "min(hlb_backup_copies)",
            comparaison: Comparaison::TombeSous,
            seuil: 2.0,
            niveau: Level::Important,
            explication: "An app has only ONE up-to-date copy left. The other \
                          destinations are configured but failing - configured \
                          is not protected.",
            absence_alarmante: false,
        },
        Regle {
            nom: "verification-perimee",
            // 🔴 A backup never restored is not a backup, it is a hypothesis.
            requete: "max(hlb_backup_verification_age_seconds)",
            comparaison: Comparaison::Depasse,
            seuil: 2_678_400.0, // 31 jours
            niveau: Level::Important,
            explication: "No verified restore for over a month. \
                          A backup never restored is a hypothesis.",
            absence_alarmante: false,
        },
        Regle {
            nom: "app-en-echec",
            requete: "min(hlb_app_up)",
            comparaison: Comparaison::TombeSous,
            seuil: 1.0,
            niveau: Level::Critical,
            explication: "An app has failed.",
            absence_alarmante: true,
        },
        Regle {
            nom: "noeud-injoignable",
            requete: "min(hlb_node_reachable)",
            comparaison: Comparaison::TombeSous,
            seuil: 1.0,
            niveau: Level::Critical,
            explication: "A node has stopped answering.",
            absence_alarmante: true,
        },
        Regle {
            nom: "disque-plein",
            requete: "max(hlb_disk_used_ratio)",
            comparaison: Comparaison::Depasse,
            // 🔴 85 % and not 95 %: beyond that, PostgreSQL and restic have no room
            // left to work, and that is precisely when you would want to back up before
            // intervening. Alerting too late amounts to not alerting.
            seuil: 0.85,
            niveau: Level::Important,
            explication: "A disk is over 85 %. Beyond that, backups and dumps \
                          have no room left to run.",
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
        // 🔴 The module's invariant. A rule with no data does NOT conclude "all is
        // well": the scrape may have died, and a green dashboard while the cluster
        // burns is the failure being avoided.
        let e = regle(Comparaison::Depasse, 10.0, true).juger(&[]);
        assert!(matches!(e, Evaluation::Inconnu { .. }), "{e:?}");
        assert_ne!(e, Evaluation::Ok);
    }

    #[test]
    fn missing_data_alerts_on_its_own() {
        // And that ignorance is SAID, instead of being swallowed silently.
        let r = regle(Comparaison::Depasse, 10.0, true);
        let n = r
            .notification(&r.juger(&[]))
            .expect("absent data must produce a notification");

        assert!(n.body.contains("NOT \"all is well\""), "{}", n.body);
        assert!(n.body.contains("blind"), "{}", n.body);
    }

    #[test]
    fn not_knowing_is_not_reported_as_the_threshold_being_crossed() {
        // 🔴 The level of absent data is not the rule's. Sending a "critical" would
        // suggest the threshold is breached, when whether it is is precisely what we do
        // not know. This is an observability problem, not a threshold one.
        let r = regle(Comparaison::Depasse, 10.0, true);
        assert_eq!(r.niveau, Level::Critical);

        let n = r.notification(&r.juger(&[])).expect("notification");
        assert_eq!(n.level, Level::Important);

        // A real breach, on the other hand, keeps the rule's own level.
        let d = r.notification(&r.juger(&[42.0])).expect("notification");
        assert_eq!(d.level, Level::Critical);
    }

    #[test]
    fn silence_is_allowed_only_when_it_was_declared_harmless() {
        // Some rules legitimately have nothing to say when the metric is missing - but
        // that is an EXPLICIT choice, never the default.
        let r = regle(Comparaison::Depasse, 10.0, false);
        assert!(r.notification(&r.juger(&[])).is_none());
    }

    #[test]
    fn the_worst_case_decides_never_the_average() {
        // 🔴 A single app with no backup deserves the alert. An average would drown it
        // under the healthy ones - the more of them there are, the more effectively.
        let haut = regle(Comparaison::Depasse, 10.0, false);
        assert_eq!(
            haut.juger(&[1.0, 2.0, 99.0]),
            Evaluation::Declenchee { valeur: 99.0 }
        );

        // And symmetrically for low thresholds: a single downed node is enough.
        let bas = regle(Comparaison::TombeSous, 1.0, false);
        assert_eq!(
            bas.juger(&[1.0, 1.0, 0.0]),
            Evaluation::Declenchee { valeur: 0.0 }
        );
        assert_eq!(bas.juger(&[1.0, 1.0]), Evaluation::Ok);
    }

    #[test]
    fn the_threshold_is_strict() {
        // Exactly at the threshold nothing fires: otherwise a disk at exactly 85 %
        // would alert permanently without anything getting worse.
        let r = regle(Comparaison::Depasse, 0.85, false);
        assert_eq!(r.juger(&[0.85]), Evaluation::Ok);
        assert!(matches!(r.juger(&[0.8501]), Evaluation::Declenchee { .. }));
    }

    #[test]
    fn never_backed_up_outranks_everything_else() {
        // 🔴 The same hierarchy as in the UI: an app running perfectly with no backup
        // is the worst state of the system, and the one that looks healthiest on a
        // dashboard.
        let r = regles_par_defaut();
        let absente = r
            .iter()
            .find(|x| x.nom == "sauvegarde-absente")
            .expect("rule present");

        assert_eq!(absente.niveau, Level::Critical);
        assert!(
            absente.absence_alarmante,
            "if this rule itself goes quiet, that must be known"
        );

        let retard = r
            .iter()
            .find(|x| x.nom == "sauvegarde-en-retard")
            .expect("rule present");
        assert!(
            absente.niveau > retard.niveau,
            "never backed up is more serious than overdue"
        );
    }

    #[test]
    fn the_never_backed_up_rule_does_not_read_an_absent_metric() {
        // 🔴 The heart of the trap: `hlb_backup_age_seconds` is ABSENT for an app that
        // was never backed up. A threshold over it would therefore never see those apps
        // - exactly the ones to detect. The gap has to be counted.
        let r = regles_par_defaut();
        let absente = r
            .iter()
            .find(|x| x.nom == "sauvegarde-absente")
            .expect("rule present");

        assert!(
            absente.requete.contains("count("),
            "the rule must COUNT, not compare an absent metric: {}",
            absente.requete
        );
        assert!(absente.requete.contains("hlb_app_up"));
    }

    #[test]
    fn every_rule_explains_itself() {
        // An alert that does not say what it wants is an alert people end up ignoring,
        // and an ignored alert protects nothing.
        for r in regles_par_defaut() {
            assert!(!r.explication.is_empty(), "{} sans explication", r.nom);
            assert!(
                r.explication.len() > 15,
                "{} : explication trop courte pour agir",
                r.nom
            );
            assert!(!r.requete.is_empty(), "{} has no query", r.nom);
        }
    }

    #[test]
    fn a_disk_alert_leaves_room_to_act() {
        // 🔴 Alerting at 95 % amounts to not alerting: PostgreSQL and restic then have
        // no room left to work, and that is precisely when you would want to back up
        // before intervening.
        let r = regles_par_defaut();
        let d = r.iter().find(|x| x.nom == "disque-plein").expect("rule");
        assert!(d.seuil <= 0.85, "seuil trop tardif : {}", d.seuil);
    }
}
