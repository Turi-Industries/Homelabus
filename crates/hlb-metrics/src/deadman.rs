//! The deadman switch.
//!
//! ## 🔴 The problem nothing else solves
//!
//! Every alert rule shares one fatal flaw: **it runs on the controller**. If the
//! controller dies, freezes, loses its network or fills its disk, it emits no alert at
//! all - and silence is indistinguishable from everything being fine. The dashboard
//! stays green, the phone stays quiet, and you learn about the outage by trying to use
//! a service, sometimes weeks later.
//!
//! A deadman switch inverts the burden of proof. Instead of waiting for a message
//! saying "something is wrong", you wait for one saying "all is well" - and it is
//! **its absence** that raises the alert. Silence becomes a signal.
//!
//! ## 🔴 Three rules, each of which voids the whole thing if forgotten
//!
//! **1. The watchdog does NOT run on the machine it watches.** That is the entire
//! idea. A deadman hosted by the controller dies with it, and you have built elaborate
//! machinery that detects nothing. The NAS is the natural watchdog: it is already the
//! backup target, therefore already another machine, already always on.
//!
//! **2. The watchdog's alert does NOT go through the watched system.** If the NAS
//! notices the silence and then asks the controller to notify, there is no alert - the
//! controller is precisely what died. The watchdog needs its own way out (its own ntfy
//! credentials), and [`script_veilleur`] gives it one.
//!
//! **3. The heartbeat is NOT a timer.** This is the easiest point to miss. A heartbeat
//! emitted by a plain time loop proves only that a thread is still alive: the
//! controller can have a stuck reconciliation loop, an unreachable Docker and an
//! unreadable database, and keep beating happily. The beat must be **conditional on a
//! successful check** - see [`Battement::emettre_si`].
//!
//! ## What this does not solve, and is better known
//!
//! The watchdog can die in turn, and nobody watches its silence. So the single point
//! of failure is not removed: it is **moved** from a complex system (the controller,
//! which orchestrates, backs up, updates) to a trivial script that does one thing.
//! That is a real gain, and it is not a guarantee. Saying so is more useful than
//! letting anyone believe in a proof.

use std::fmt::Write as _;

/// Recommended interval between two heartbeats.
///
/// Five minutes: short enough for an outage to show within the hour, long enough that
/// a service restart does not raise a false alert.
pub const INTERVALLE_BATTEMENT_S: u64 = 300;

/// Beyond this much silence, the watchdog alerts.
///
/// 🔴 Three missed beats, not one. A single missed beat is normal behaviour on a home
/// network: a reboot, an update, Wi-Fi hiccupping. An alert on every hiccup is an alert
/// people eventually turn off - and a turned-off deadman protects nothing.
pub const SILENCE_MAX_S: u64 = INTERVALLE_BATTEMENT_S * 3 + 60;

/// What must be true for a heartbeat to go out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sante {
    /// The state database answers.
    pub etat_lisible: bool,
    /// The orchestrator answers.
    pub orchestrateur_joignable: bool,
    /// The last reconciliation loop ran to completion.
    pub reconciliation_recente: bool,
}

impl Sante {
    /// Is the system in a state to claim it is fine?
    pub fn est_saine(&self) -> bool {
        self.etat_lisible && self.orchestrateur_joignable && self.reconciliation_recente
    }

    /// Ce qui cloche, pour les journaux.
    pub fn manquements(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if !self.etat_lisible {
            v.push("unreadable state database");
        }
        if !self.orchestrateur_joignable {
            v.push("orchestrateur injoignable");
        }
        if !self.reconciliation_recente {
            v.push("reconciliation stuck");
        }
        v
    }
}

/// The heartbeat emitted by the watched system.
pub struct Battement {
    /// Where to push the heartbeat. On the NAS, outside the watched system.
    pub url: String,
}

/// Ce qu'il faut faire d'un battement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emission {
    /// To be sent.
    Envoyer,
    /// 🔴 To be **withheld**. Silence is the signal: staying quiet will trigger the
    /// watchdog's alert, which is exactly what is wanted when the system is unwell.
    Taire { manquements: Vec<&'static str> },
}

impl Battement {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// Decides whether to emit or to stay quiet.
    ///
    /// 🔴 **The heartbeat is conditional, never periodic.** A beat emitted by a plain
    /// timer proves a thread is alive and nothing more: the controller can have a stuck
    /// reconciliation loop, an unreachable Docker and an unreadable database, and keep
    /// beating imperturbably. The deadman would stay green over an unusable system,
    /// which is worse than no deadman at all - because it is trusted.
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

/// The state the watchdog observes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veille {
    /// Battement frais.
    Vivant { depuis_s: u64 },
    /// 🔴 Prolonged silence: the watched system is probably dead.
    Silencieux { depuis_s: u64 },
    /// 🔴 **No heartbeat has EVER been received.**
    ///
    /// Distinct from `Silencieux`, for the same reason `NeverSucceeded` is distinct
    /// from `Stale` in the UI: a deadman that was never armed has never protected
    /// anything. Confusing it with a recent silence would suggest a fresh outage, when
    /// the mechanism simply never worked - the installation was wrong from day one, and
    /// nobody knew.
    JamaisArme,
}

impl Veille {
    /// Judges the freshness of the last heartbeat.
    ///
    /// `dernier_s` is `None` when no heartbeat has ever been received.
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

    /// The message to push, or `None` when all is well.
    pub fn message(&self) -> Option<String> {
        match self {
            Self::Vivant { .. } => None,

            Self::Silencieux { depuis_s } => Some(format!(
                "🔴 Homelabus has shown no sign of life for {} minutes.\n\n\
                 The controller is probably stopped, frozen, or cut off from the \
                 network. While it is, NO other alert can go out: not a missed backup, \
                 not a downed app, not a full disk. This silence is therefore the only \
                 signal available.",
                depuis_s / 60
            )),

            Self::JamaisArme => Some(
                "🔴 The deadman switch has NEVER received a heartbeat.\n\n\
                 This is not a recent outage: the mechanism never worked, so it has \
                 never protected anything. Check that the controller knows the \
                 watchdog's URL, and that it can reach it."
                    .into(),
            ),
        }
    }
}

/// The script to install on the NAS.
///
/// 🔴 Deliberately trivial: `curl`, `date`, a comparison. This script is the last link,
/// the one nobody watches - every line added to it is a line that can make it fail
/// silently. Its stupidity is a property, not a limitation.
///
/// ⚠️ It pushes to ntfy **directly**, not through Homelabus: asking the watched system
/// to relay the alert about its own death cannot work.
///
/// 🔴 **And if ntfy is unreachable?** Found by actually running the script: a failing
/// `curl` is swallowed by the redirection, and the alert disappears without a trace -
/// the watchdog cannot report that it could not report. Hence the fallback to
/// **stderr**, which cron mails out: a second path sharing neither the network nor the
/// service of the first, for one line of shell.
pub fn script_veilleur(fichier_battement: &str, ntfy_url: &str, sujet: &str) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "#!/bin/sh");
    let _ = writeln!(s, "# Homelabus watchdog - to be run by cron on the NAS.");
    let _ = writeln!(s, "#");
    let _ = writeln!(s, "# 🔴 This script MUST NOT run on the machine it");
    let _ = writeln!(s, "#    watches: it would die with it and detect nothing.");
    let _ = writeln!(s, "#");
    let _ = writeln!(
        s,
        "# 🔴 It pushes to ntfy DIRECTLY. Going through Homelabus to"
    );
    let _ = writeln!(s, "#    report that Homelabus is dead cannot work.");
    let _ = writeln!(s, "#");
    let _ = writeln!(s, "# Install it in cron every 5 minutes:");
    let _ = writeln!(s, "#   */5 * * * * /path/watchdog.sh");
    let _ = writeln!(s);
    let _ = writeln!(s, "set -u");
    let _ = writeln!(s, "BATTEMENT='{fichier_battement}'");
    let _ = writeln!(s, "SILENCE_MAX={SILENCE_MAX_S}");
    let _ = writeln!(s);
    let _ = writeln!(s, "if [ ! -f \"$BATTEMENT\" ]; then");
    let _ = writeln!(
        s,
        "  # Never armed: distinct from a recent silence. The mechanism"
    );
    let _ = writeln!(s, "  # never worked, so it never protected anything.");
    let _ = writeln!(
        s,
        "  curl -fsS -H 'Priority: urgent' -H 'Title: {sujet} never armed' \\"
    );
    let _ = writeln!(
        s,
        "    -d 'No heartbeat received, ever. The deadman protects nothing.' \\"
    );
    let _ = writeln!(s, "    '{ntfy_url}' >/dev/null 2>&1 \\");
    let _ = writeln!(
        s,
        "    || echo 'WATCHDOG: ntfy unreachable, alert LOST' >&2"
    );
    let _ = writeln!(s, "  exit 1");
    let _ = writeln!(s, "fi");
    let _ = writeln!(s);
    let _ = writeln!(s, "MAINTENANT=$(date +%s)");
    let _ = writeln!(s, "DERNIER=$(cat \"$BATTEMENT\" 2>/dev/null || echo 0)");
    let _ = writeln!(s, "AGE=$((MAINTENANT - DERNIER))");
    let _ = writeln!(s);
    let _ = writeln!(s, "if [ \"$AGE\" -gt \"$SILENCE_MAX\" ]; then");
    let _ = writeln!(
        s,
        "  curl -fsS -H 'Priority: urgent' -H 'Title: {sujet} silent' \\"
    );
    let _ = writeln!(s, "    -d \"No sign of life for $((AGE / 60)) minutes. \\");
    let _ = writeln!(
        s,
        "While this silence lasts, NO other alert can go out.\" \\"
    );
    let _ = writeln!(s, "    '{ntfy_url}' >/dev/null 2>&1 \\");
    let _ = writeln!(
        s,
        "    || echo 'WATCHDOG: ntfy unreachable, alert LOST' >&2"
    );
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
        // 🔴 THE point of this module. A periodic beat proves a thread is alive, not
        // that the system works: the controller can have a stuck reconciliation and an
        // unreachable Docker, and beat imperturbably. The deadman would stay green over
        // an unusable system - worse than no deadman, because it is trusted.
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
                "a broken system must NOT beat: {s:?}"
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
        // 🔴 Same distinction as `NeverSucceeded` / `Stale` in the UI. A deadman that
        // was never armed never protected anything: confusing it with a fresh outage
        // would send you looking for a recent incident, when the installation was wrong
        // from day one.
        assert_eq!(Veille::juger(None, 1_000_000), Veille::JamaisArme);

        let silencieux = Veille::juger(Some(0), SILENCE_MAX_S + 100);
        assert!(matches!(silencieux, Veille::Silencieux { .. }));
        assert_ne!(silencieux, Veille::JamaisArme);

        // And the two messages must differ, not only the variants.
        let m_jamais = Veille::JamaisArme.message().expect("message");
        let m_silence = silencieux.message().expect("message");
        assert!(m_jamais.contains("NEVER"), "{m_jamais}");
        assert!(m_jamais.contains("never protected anything"), "{m_jamais}");
        assert_ne!(m_jamais, m_silence);
    }

    #[test]
    fn one_missed_beat_is_not_an_alert() {
        // 🔴 An alert on every Wi-Fi hiccup is an alert people eventually turn off. A
        // turned-off deadman protects nothing.
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
        // A NAS resyncing its clock can return a "future" heartbeat. An overflowing
        // subtraction would crash the watchdog - so no monitoring at all, silently.
        let v = Veille::juger(Some(2000), 1000);
        assert_eq!(v, Veille::Vivant { depuis_s: 0 });
    }

    #[test]
    fn the_watcher_never_routes_through_the_watched_system() {
        // 🔴 Asking the watched system to report its own death cannot work. The
        // watchdog must push to ntfy directly.
        let s = script_veilleur(
            "/var/lib/hlb/battement",
            "https://ntfy.sh/mon-sujet",
            "Homelabus",
        );

        assert!(s.contains("https://ntfy.sh/mon-sujet"), "{s}");
        assert!(
            !s.contains("hlb ") && !s.contains("localhost"),
            "the watchdog must depend on nothing from the watched system: {s}"
        );
        assert!(s.contains("MUST NOT run on the machine"), "{s}");
    }

    #[test]
    fn the_watcher_distinguishes_never_armed_too() {
        // The distinction must survive into the script, or it is worthless: the
        // script is what speaks to the human.
        let s = script_veilleur("/b", "https://ntfy.sh/x", "Homelabus");
        assert!(s.contains("never armed"), "{s}");
        assert!(
            s.contains("if [ ! -f"),
            "il doit tester l'absence du fichier : {s}"
        );
    }

    #[test]
    fn a_lost_alert_leaves_a_trace() {
        // 🔴 Found by actually running the script: `curl ... >/dev/null 2>&1` swallows
        // its own failure. If ntfy is unreachable - network outage, deleted topic,
        // service down - the alert disappears without a trace, and the watchdog cannot
        // report that it could not report.
        //
        // stderr is the fallback: cron mails it out, and that path shares neither the
        // network nor the service with ntfy.
        let s = script_veilleur("/b", "https://ntfy.sh/x", "Homelabus");
        assert_eq!(
            s.matches("alert LOST").count(),
            2,
            "BOTH alert paths must have their fallback: {s}"
        );
        assert!(
            s.contains(">&2"),
            "the fallback must go through stderr: {s}"
        );
    }

    #[test]
    fn the_watcher_stays_trivial() {
        // 🔴 This is the last link, the one nobody watches. Every added line is a line
        // that can make it fail silently. Its stupidity is a property.
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
        assert!(s.starts_with("#!/bin/sh"), "no dependency on bash");
    }
}
