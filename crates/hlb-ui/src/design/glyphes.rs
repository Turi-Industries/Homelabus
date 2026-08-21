//! 🔴 Ne jamais afficher un carré vide.
//!
//! ## Le problème, tel qu'il s'est présenté
//!
//! egui n'embarque pas tous les glyphes. « ● », le sélecteur de variante de « ⚠️ » et
//! « ⚑ » s'affichent en **tofu** — un rectangle vide. Et un tofu ressemble assez à une
//! icône pour passer inaperçu en relecture : on croit voir une puce, il n'y a rien.
//!
//! Un test scanne déjà tous les littéraux de l'interface. Mais il ne peut rien contre
//! le **contenu écrit par les utilisateurs** : le titre d'une annonce, le nom d'un
//! dossier Sieve, la description d'un alias venue de Bitwarden. Un emoji glissé là
//! traverse tout et s'affiche en carré vide.
//!
//! ## Ce qu'on fait à la place
//!
//! Remplacer par un caractère de remplacement **visible et sans ambiguïté**, et pouvoir
//! dire lequel a été remplacé. Un texte amputé en silence serait le même piège d'un
//! cran plus loin : « Réunion 📅 lundi » deviendrait « Réunion  lundi », et personne ne
//! saurait qu'il manque quelque chose.

/// Le caractère affiché à la place d'un glyphe absent.
///
/// U+00A4 (¤) : présent dans toutes les polices latines, ne ressemble à aucune lettre,
/// et n'a aucun sens propre en français — donc on ne le confond pas avec du contenu.
pub const REMPLACEMENT: char = '¤';

/// Ce caractère est-il sûr à afficher ?
///
/// Même règle que le test `no_displayed_text_needs_a_glyph_egui_might_not_have` de
/// l'interface : latin étendu et ponctuation générale, rien au-delà.
pub fn sur(c: char) -> bool {
    let n = c as u32;
    // Latin de base, supplément, étendu A/B, IPA : tout ce qu'une police latine porte.
    n < 0x2C0
        // Ponctuation générale : tirets cadratins, guillemets courbes, points de
        // suspension, puce. Ce sont des caractères de TEXTE, pas des icônes.
        || (0x2000..=0x206F).contains(&n)
}

/// Le texte, débarrassé de ce qui s'afficherait en carré vide.
pub fn sans_tofu(s: &str) -> String {
    s.chars().map(|c| if sur(c) { c } else { REMPLACEMENT }).collect()
}

/// Les caractères qui ont été (ou seraient) remplacés, dédoublonnés et dans l'ordre.
///
/// Sert à l'infobulle : « 1 caractère non affichable : U+1F4C5 ». Dire QUOI a été
/// remplacé est ce qui distingue une protection d'une mutilation.
pub fn absents(s: &str) -> Vec<char> {
    let mut v: Vec<char> = s.chars().filter(|c| !sur(*c)).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Y a-t-il quelque chose à remplacer ?
pub fn contient_du_tofu(s: &str) -> bool {
    s.chars().any(|c| !sur(c))
}

/// La description des caractères remplacés, pour une infobulle.
pub fn explication(s: &str) -> Option<String> {
    let a = absents(s);
    if a.is_empty() {
        return None;
    }
    let liste: Vec<String> = a.iter().take(5).map(|c| format!("U+{:04X}", *c as u32)).collect();
    // ⚠️ Pas de « (s) » : c'est le tic que le reste de l'interface s'interdit, et une
    // infobulle n'y échappe pas.
    Some(format!(
        "{} que la police ne peut pas afficher : {}{}",
        hlb_api::pluriel(a.len() as u64, "caractère", "caractères"),
        liste.join(", "),
        if a.len() > 5 { "…" } else { "" }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn french_text_passes_through_untouched() {
        // Si les accents, les guillemets ou les tirets cadratins étaient remplacés,
        // toute l'interface deviendrait illisible — le projet est en français.
        for s in [
            "Créer le compte administrateur",
            "« sauvegardé il y a 3 h »",
            "Réconciliation — 4 apps examinées…",
            "Æquo, ÿ, ñ, ß, œuf",
            "50 % · 3/4",
        ] {
            assert_eq!(sans_tofu(s), s, "{s}");
            assert!(!contient_du_tofu(s), "{s}");
        }
    }

    #[test]
    fn an_emoji_becomes_visible_not_invisible() {
        // 🔴 Le vrai piège : le supprimer ferait disparaître du texte en silence.
        // « Réunion 📅 lundi » deviendrait « Réunion  lundi » et personne ne saurait.
        let s = "Réunion 📅 lundi";
        let out = sans_tofu(s);
        assert!(contient_du_tofu(s));
        assert!(out.contains(REMPLACEMENT), "{out}");
        assert_eq!(out.chars().count(), s.chars().count(), "rien n'est retiré");
        assert!(out.contains("Réunion") && out.contains("lundi"));
    }

    #[test]
    fn the_glyphs_named_in_the_project_notes_are_caught() {
        // Les trois cités dans le CLAUDE.md, constatés en tofu.
        for c in ['\u{25CF}', '\u{2691}', '\u{FE0F}'] {
            assert!(!sur(c), "U+{:04X} devrait être remplacé", c as u32);
        }
    }

    #[test]
    fn the_replacement_is_never_itself_replaced() {
        // Sinon la substitution boucherait à chaque passage, et un texte déjà nettoyé
        // se dégraderait un peu plus à chaque affichage.
        assert!(sur(REMPLACEMENT));
        let une = sans_tofu("a📅b");
        assert_eq!(sans_tofu(&une), une);
    }

    #[test]
    fn the_explanation_names_the_codepoints() {
        // Dire QUOI a été remplacé est ce qui distingue une protection d'une
        // mutilation : sans ça, on croit à un bug d'affichage.
        let e = explication("📅 réunion").expect("un caractère absent");
        assert!(e.contains("U+1F4C5"), "{e}");
        // ⚠️ Le motif est ASSEMBLÉ, pas écrit : l'écrire ferait échouer le test qui
        // interdit les pluriels entre parenthèses dans ce fichier. Même astuce que le
        // test qui interdit `Instant::now()` sans se déclencher lui-même.
        let tic = format!("({})", "s");
        assert!(!e.contains(&tic), "pas de pluriel entre parenthèses : {e}");
        assert!(explication("réunion").is_none());
    }

    #[test]
    fn many_missing_glyphs_do_not_produce_an_endless_tooltip() {
        let s: String = "📅📆📈📉📊📋📌📍".chars().collect();
        let e = explication(&s).expect("des caractères absents");
        assert!(e.ends_with('…'), "{e}");
        assert!(e.len() < 200, "infobulle trop longue : {e}");
    }

    #[test]
    fn missing_glyphs_are_listed_once_each() {
        assert_eq!(absents("📅📅📅"), vec!['📅']);
    }
}
