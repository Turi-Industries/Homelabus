//! Fenêtres de maintenance (§7 du plan).
//!
//! Une mise à jour automatique se fait quand tu dors, pas au milieu d'une visio. La
//! fenêtre est déclarée au manifest sous une forme lisible :
//!
//! ```text
//! window: "sun 03:00-05:00"      un jour précis
//! window: "daily 03:00-05:00"    tous les jours
//! window: "sat,sun 02:00-06:00"  plusieurs jours
//! ```
//!
//! Le cas piégeux est la fenêtre qui **franchit minuit** (`23:00-02:00`) : elle est
//! courante pour la maintenance nocturne et se traite à part.

use chrono::{Datelike, NaiveTime, Timelike, Weekday};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("fenêtre « {0} » : format attendu « <jours> HH:MM-HH:MM »")]
    Shape(String),

    #[error("fenêtre « {input} » : jour « {day} » inconnu")]
    Day { input: String, day: String },

    #[error("fenêtre « {input} » : heure « {time} » invalide")]
    Time { input: String, time: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceWindow {
    /// Vide = tous les jours.
    days: Vec<Weekday>,
    start: NaiveTime,
    end: NaiveTime,
}

impl MaintenanceWindow {
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let s = s.trim();
        let (days_part, range) = s
            .rsplit_once(' ')
            .ok_or_else(|| ParseError::Shape(s.to_string()))?;

        let (from, to) = range
            .split_once('-')
            .ok_or_else(|| ParseError::Shape(s.to_string()))?;

        let start = parse_time(from.trim(), s)?;
        let end = parse_time(to.trim(), s)?;

        let days_part = days_part.trim();
        let days = if matches!(days_part, "daily" | "*" | "every") {
            Vec::new()
        } else {
            days_part
                .split(',')
                .map(|d| parse_day(d.trim(), s))
                .collect::<Result<Vec<_>, _>>()?
        };

        Ok(Self { days, start, end })
    }

    /// La fenêtre franchit-elle minuit ?
    fn wraps_midnight(&self) -> bool {
        self.end <= self.start
    }

    /// `now` tombe-t-il dans la fenêtre ?
    pub fn is_open_at<T: Datelike + Timelike>(&self, now: &T) -> bool {
        let t = NaiveTime::from_hms_opt(now.hour(), now.minute(), 0).unwrap_or_default();
        let today = weekday_of(now);

        if !self.wraps_midnight() {
            return self.day_matches(today) && t >= self.start && t < self.end;
        }

        // Fenêtre à cheval sur minuit : la partie avant minuit appartient au jour
        // déclaré, la partie après minuit appartient au **lendemain** de ce jour.
        if self.day_matches(today) && t >= self.start {
            return true;
        }
        let yesterday = today.pred();
        self.day_matches(yesterday) && t < self.end
    }

    fn day_matches(&self, d: Weekday) -> bool {
        self.days.is_empty() || self.days.contains(&d)
    }
}

fn weekday_of<T: Datelike>(d: &T) -> Weekday {
    d.weekday()
}

fn parse_time(s: &str, input: &str) -> Result<NaiveTime, ParseError> {
    NaiveTime::parse_from_str(s, "%H:%M").map_err(|_| ParseError::Time {
        input: input.to_string(),
        time: s.to_string(),
    })
}

fn parse_day(s: &str, input: &str) -> Result<Weekday, ParseError> {
    // On accepte l'anglais court, usuel dans les crontabs, et le français court.
    let w = match s.to_lowercase().as_str() {
        "mon" | "lun" => Weekday::Mon,
        "tue" | "mar" => Weekday::Tue,
        "wed" | "mer" => Weekday::Wed,
        "thu" | "jeu" => Weekday::Thu,
        "fri" | "ven" => Weekday::Fri,
        "sat" | "sam" => Weekday::Sat,
        "sun" | "dim" => Weekday::Sun,
        _ => {
            return Err(ParseError::Day {
                input: input.to_string(),
                day: s.to_string(),
            })
        }
    };
    Ok(w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    /// 2026-08-05 est un mercredi.
    fn at(day: u32, h: u32, m: u32) -> chrono::NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 8, day)
            .expect("date valide")
            .and_hms_opt(h, m, 0)
            .expect("heure valide")
    }

    #[test]
    fn parses_a_single_day() {
        let w = MaintenanceWindow::parse("sun 03:00-05:00").expect("analysable");
        assert_eq!(w.days, vec![Weekday::Sun]);
        assert_eq!(w.start, NaiveTime::from_hms_opt(3, 0, 0).unwrap());
    }

    #[test]
    fn parses_several_days() {
        let w = MaintenanceWindow::parse("sat,sun 02:00-06:00").expect("analysable");
        assert_eq!(w.days, vec![Weekday::Sat, Weekday::Sun]);
    }

    #[test]
    fn daily_matches_every_day() {
        for form in ["daily 03:00-05:00", "* 03:00-05:00", "every 03:00-05:00"] {
            let w = MaintenanceWindow::parse(form).expect("analysable");
            assert!(w.days.is_empty(), "{form}");
        }
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in ["", "sun", "sun 03:00", "sun 25:00-26:00", "xyz 03:00-05:00"] {
            assert!(MaintenanceWindow::parse(bad).is_err(), "« {bad} » devrait échouer");
        }
    }

    #[test]
    fn opens_only_inside_the_range() {
        // 9 août 2026 = dimanche.
        let w = MaintenanceWindow::parse("sun 03:00-05:00").expect("analysable");

        assert!(!w.is_open_at(&at(9, 2, 59)));
        assert!(w.is_open_at(&at(9, 3, 0)), "la borne basse est incluse");
        assert!(w.is_open_at(&at(9, 4, 30)));
        assert!(
            !w.is_open_at(&at(9, 5, 0)),
            "la borne haute est exclue, sinon deux fenêtres se chevaucheraient"
        );
    }

    #[test]
    fn stays_closed_on_other_days() {
        let w = MaintenanceWindow::parse("sun 03:00-05:00").expect("analysable");
        // 5 août = mercredi.
        assert!(!w.is_open_at(&at(5, 4, 0)));
    }

    #[test]
    fn a_window_crossing_midnight_spans_two_days() {
        // Cas courant et piégeux : 23:00 dimanche → 02:00 lundi.
        let w = MaintenanceWindow::parse("sun 23:00-02:00").expect("analysable");

        // Dimanche 9 août, après 23:00.
        assert!(w.is_open_at(&at(9, 23, 30)));
        // Lundi 10 août, avant 02:00 : toujours la fenêtre du dimanche.
        assert!(w.is_open_at(&at(10, 1, 0)));
        // Lundi 10 août, après 02:00 : fermée.
        assert!(!w.is_open_at(&at(10, 2, 30)));
        // Dimanche 9 août, avant 23:00 : pas encore ouverte.
        assert!(!w.is_open_at(&at(9, 22, 0)));
    }

    #[test]
    fn a_daily_window_crossing_midnight_is_always_reachable() {
        let w = MaintenanceWindow::parse("daily 23:00-02:00").expect("analysable");
        assert!(w.is_open_at(&at(5, 23, 30)));
        assert!(w.is_open_at(&at(6, 0, 30)));
        assert!(!w.is_open_at(&at(6, 12, 0)));
    }

    #[test]
    fn french_day_names_work_too() {
        let w = MaintenanceWindow::parse("dim 03:00-05:00").expect("analysable");
        assert_eq!(w.days, vec![Weekday::Sun]);
    }
}
