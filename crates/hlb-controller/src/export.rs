//! L'export CSV des vues tabulaires (lot 11.5).
//!
//! ## Pourquoi le CSV et pas le JSON
//!
//! Le JSON est déjà là : chaque route d'API le rend. Ce qui manque, c'est ce qu'on
//! ouvre dans un tableur pour trier, filtrer et donner à quelqu'un — un journal
//! d'audit à relire après un incident, un inventaire de comptes à comparer.
//!
//! ## 🔴 Aucune valeur de secret n'est exportable
//!
//! L'export porte les mêmes types que l'API, et ces types n'ont aucun champ pour une
//! valeur de secret. La garantie n'est pas dans ce fichier : elle est dans les types,
//! et elle traverse l'export sans qu'on ait à y penser.

/// Échappe un champ CSV (RFC 4180).
///
/// 🔴 Un champ contenant une virgule, un guillemet ou un saut de ligne DÉCALE toutes
/// les colonnes suivantes s'il n'est pas cité. Le journal d'audit contient des détails
/// écrits par des humains : virgules et guillemets y sont la norme, pas l'exception.
pub fn champ(v: &str) -> String {
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

/// Une ligne CSV.
pub fn ligne(champs: &[&str]) -> String {
    let mut s = champs
        .iter()
        .map(|c| champ(c))
        .collect::<Vec<_>>()
        .join(",");
    // ⚠️ CRLF, comme le veut la RFC : Excel sous Windows fusionne les lignes sinon.
    s.push_str("\r\n");
    s
}

/// Le journal d'audit, en CSV.
pub fn audit(entrees: &[hlb_state::AuditRecord]) -> String {
    let mut s = ligne(&["quand", "acteur", "role", "action", "cible", "issue", "detail"]);
    for e in entrees {
        s.push_str(&ligne(&[
            &e.at,
            &e.actor,
            &e.role,
            &e.action,
            &e.target,
            &e.outcome,
            e.detail.as_deref().unwrap_or(""),
        ]));
    }
    s
}

/// Les sauvegardes, en CSV.
pub fn sauvegardes(runs: &[hlb_state::BackupRun]) -> String {
    let mut s = ligne(&[
        "quand",
        "app",
        "type",
        "destination",
        "instantane",
        "issue",
        "erreur",
    ]);
    for r in runs {
        s.push_str(&ligne(&[
            &r.finished_at,
            &r.app,
            &r.kind,
            r.destination.as_deref().unwrap_or(""),
            r.snapshot_id.as_deref().unwrap_or(""),
            &r.status,
            r.error.as_deref().unwrap_or(""),
        ]));
    }
    s
}

/// Les comptes, en CSV.
pub fn comptes(comptes: &[hlb_api::CompteSummary]) -> String {
    let mut s = ligne(&[
        "nom",
        "role",
        "profil",
        "coherence",
        "boites",
        "aliases_actifs",
        // 🔴 La colonne qui compte : des aliases expirés qui reçoivent ENCORE. Un
        // export qui l'omettrait ferait relire un inventaire rassurant.
        "promesses_rompues",
        "sessions",
    ]);
    for c in comptes {
        let boites: Vec<&str> = c.boites.iter().map(|b| b.adresse.as_str()).collect();
        s.push_str(&ligne(&[
            &c.nom,
            &c.role,
            &c.profil,
            &format!("{:?}", c.coherence),
            &boites.join(" "),
            &c.aliases_actifs.to_string(),
            &c.promesses_rompues.to_string(),
            &c.sessions.to_string(),
        ]));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_with_a_comma_never_shifts_the_columns() {
        // 🔴 Le journal d'audit contient des détails écrits par des humains : virgules
        // et guillemets y sont la norme. Un champ non cité décale TOUTES les colonnes
        // suivantes, et le tableau devient faux sans avoir l'air cassé.
        assert_eq!(champ("simple"), "simple");
        assert_eq!(champ("un, deux"), "\"un, deux\"");
        assert_eq!(champ("il a dit \"non\""), "\"il a dit \"\"non\"\"\"");
        assert_eq!(champ("deux\nlignes"), "\"deux\nlignes\"");
    }

    #[test]
    fn the_line_ending_is_crlf_as_the_standard_demands() {
        // ⚠️ Excel sous Windows fusionne les lignes séparées par un simple LF.
        assert!(ligne(&["a", "b"]).ends_with("\r\n"));
        assert_eq!(ligne(&["a", "b"]), "a,b\r\n");
    }

    #[test]
    fn an_empty_table_still_carries_its_header() {
        // Un fichier vide se lit « l'export a échoué ». Un fichier avec seulement
        // l'en-tête se lit « il n'y avait rien », ce qui est une information.
        let csv = audit(&[]);
        assert!(csv.starts_with("quand,acteur,role"));
        assert_eq!(csv.lines().count(), 1);
    }

    #[test]
    fn nothing_in_the_exported_types_can_carry_a_secret_value() {
        // 🔴 La garantie vit dans les TYPES de l'API, pas dans cet exporteur : ils n'ont
        // aucun champ pour une valeur. Ce test le rappelle là où l'on serait tenté
        // d'ajouter une colonne « pratique ».
        let entete = audit(&[]);
        for interdit in ["valeur", "secret", "password", "token"] {
            assert!(!entete.contains(interdit), "colonne « {interdit} »");
        }
    }
}
