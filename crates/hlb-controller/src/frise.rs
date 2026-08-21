//! La frise chronologique unifiée (lot 9.5).
//!
//! ## 🔴 Ce que seule une frise permet
//!
//! « L'app est tombée à 3 h 12 » et « mise à jour appliquée à 3 h 10 » sont deux faits
//! rangés dans deux tableaux différents. Les rapprocher demande d'ouvrir deux écrans et
//! de comparer des heures à la main — et c'est exactement ce qu'on fait, mal, au moment
//! où l'on est pressé.
//!
//! ## ⚠️ Une source muette n'est pas une source vide
//!
//! Si le journal d'audit ne se relit pas, la frise n'affiche pas « rien ne s'est
//! passé » : elle perd une source sans le dire, et l'on conclurait qu'aucune action
//! humaine n'a précédé la panne. Les erreurs de lecture sont donc portées dans la frise
//! elle-même, comme des événements.

use hlb_api::{Attention, Evenement, GenreEvenement};
use hlb_state::State;

/// Convertit un horodatage SQLite (`YYYY-MM-DD HH:MM:SS`, UTC) en secondes.
///
/// ⚠️ SQLite écrit sans fuseau ni `T`. `chrono` refuserait ce format en RFC 3339 : on le
/// lit à la main plutôt que de rendre `None` sur toutes les lignes, ce qui donnerait
/// une frise vide sur des données parfaitement saines.
fn horodatage(s: &str) -> Option<i64> {
    let (date, heure) = s.split_once(['T', ' '])?;
    let mut d = date.split('-');
    let (a, m, j): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let mut h = heure.trim_end_matches('Z').split(':');
    let (hh, mm, ss): (i64, i64, f64) = (
        h.next()?.parse().ok()?,
        h.next()?.parse().ok()?,
        h.next().unwrap_or("0").parse().ok()?,
    );

    // Jours depuis l'époque, algorithme des jours civils (Howard Hinnant).
    let a = if m <= 2 { a - 1 } else { a };
    let ere = if a >= 0 { a } else { a - 399 } / 400;
    let aoe = a - ere * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + j - 1;
    let doe = aoe * 365 + aoe / 4 - aoe / 100 + doy;
    let jours = ere * 146_097 + doe - 719_468;

    Some(jours * 86_400 + hh * 3_600 + mm * 60 + ss as i64)
}

/// Les événements récents, toutes sources confondues, du plus récent au plus ancien.
pub async fn evenements(state: &State, limite: usize) -> Vec<Evenement> {
    let mut out = Vec::new();

    // --- Les sauvegardes ------------------------------------------------------
    match state.backup_history_all(limite).await {
        Ok(runs) => {
            for r in runs {
                let echec = r.status != "ok";
                out.push(Evenement {
                    quand: horodatage(&r.finished_at).unwrap_or(0),
                    genre: GenreEvenement::Sauvegarde,
                    cible: r.app.clone(),
                    quoi: match (&r.destination, &r.error) {
                        (Some(d), Some(e)) => format!("{} vers {d} : {e}", r.kind),
                        (Some(d), None) => format!("{} vers {d}", r.kind),
                        (None, Some(e)) => format!("{} : {e}", r.kind),
                        (None, None) => r.kind.clone(),
                    },
                    attention: if echec {
                        Attention::Critical
                    } else {
                        Attention::Ok
                    },
                });
            }
        }
        Err(e) => out.push(source_muette("sauvegardes", &e.to_string())),
    }

    // --- Le journal d'audit ---------------------------------------------------
    match state.audit_trail(limite).await {
        Ok(entrees) => {
            for a in entrees {
                out.push(Evenement {
                    quand: horodatage(&a.at).unwrap_or(0),
                    genre: GenreEvenement::Action,
                    cible: a.target.clone(),
                    quoi: format!("{} par {} ({})", a.action, a.actor, a.outcome),
                    attention: match a.outcome.as_str() {
                        "failed" => Attention::Critical,
                        // 🔴 Un refus n'est PAS un échec : c'est le système qui a
                        // protégé. Les peindre pareil ferait chercher une panne là où
                        // une garde a fonctionné.
                        "refused" => Attention::Notice,
                        _ => Attention::Ok,
                    },
                });
            }
        }
        Err(e) => out.push(source_muette("journal d'audit", &e.to_string())),
    }

    // Du plus récent au plus ancien : c'est ce qui vient de se passer qu'on cherche.
    out.sort_by_key(|e| std::cmp::Reverse(e.quand));
    out.truncate(limite);
    out
}

/// Une source qu'on n'a pas pu lire, portée DANS la frise.
///
/// 🔴 La taire ferait conclure « rien ne s'est passé » alors qu'on ne sait rien — et
/// c'est au milieu d'une panne qu'on lit cet écran.
fn source_muette(quoi: &str, detail: &str) -> Evenement {
    Evenement {
        quand: crate::auth::maintenant(),
        genre: GenreEvenement::Alerte,
        cible: quoi.to_string(),
        quoi: format!("cette source n'a pas pu être lue : {detail}"),
        attention: Attention::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sqlite_timestamp_is_read_without_a_timezone() {
        // ⚠️ SQLite écrit « 2026-08-19 07:12:00 » : ni « T », ni « Z ». Le refuser comme
        // du RFC 3339 rendrait `None` sur TOUTES les lignes, et la frise serait vide sur
        // des données parfaitement saines.
        assert_eq!(horodatage("1970-01-01 00:00:00"), Some(0));
        assert_eq!(horodatage("2000-01-01 00:00:00"), Some(946_684_800));
        assert_eq!(horodatage("2026-08-19 07:12:00"), Some(1_787_123_520));
        // Et la forme RFC 3339 passe aussi : les deux coexistent dans la base.
        assert_eq!(horodatage("2000-01-01T00:00:00Z"), Some(946_684_800));
    }

    #[test]
    fn an_unreadable_source_appears_instead_of_vanishing() {
        // 🔴 Le cœur : perdre une source en silence ferait conclure « aucune action
        // humaine n'a précédé la panne ».
        let e = source_muette("journal d'audit", "base verrouillée");
        assert_eq!(e.attention, Attention::Critical);
        assert!(e.quoi.contains("n'a pas pu être lue"));
    }

    #[tokio::test]
    async fn the_river_is_sorted_newest_first_across_sources() {
        let s = State::in_memory().await.expect("état");
        s.record_backup_to("gitea", "volume", "nas", Some("a"), None)
            .await
            .expect("sauvegarde");
        s.audit(
            "remy",
            hlb_types::Role::Admin,
            "install",
            "gitea",
            "ok",
            None,
        )
        .await
        .expect("audit");

        let f = evenements(&s, 50).await;
        assert!(f.len() >= 2, "{f:#?}");
        // Les deux sources sont présentes dans la MÊME liste : c'est tout le propos.
        assert!(f.iter().any(|e| e.genre == GenreEvenement::Sauvegarde));
        assert!(f.iter().any(|e| e.genre == GenreEvenement::Action));
        // Et l'ordre est décroissant.
        for w in f.windows(2) {
            assert!(w[0].quand >= w[1].quand, "{f:#?}");
        }
    }

    #[tokio::test]
    async fn a_refusal_is_never_painted_like_a_failure() {
        // Un refus est une garde qui a fonctionné ; un échec est une panne. Les peindre
        // pareil ferait chercher un problème là où il n'y en a pas.
        let s = State::in_memory().await.expect("état");
        s.audit(
            "viewer",
            hlb_types::Role::Viewer,
            "remove",
            "gitea",
            "refused",
            None,
        )
        .await
        .expect("audit");
        s.audit(
            "remy",
            hlb_types::Role::Admin,
            "backup",
            "immich",
            "failed",
            None,
        )
        .await
        .expect("audit");

        let f = evenements(&s, 50).await;
        let refus = f
            .iter()
            .find(|e| e.quoi.contains("refused"))
            .expect("refus");
        let echec = f.iter().find(|e| e.quoi.contains("failed")).expect("échec");
        assert_eq!(refus.attention, Attention::Notice);
        assert_eq!(echec.attention, Attention::Critical);
    }
}
