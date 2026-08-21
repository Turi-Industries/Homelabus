//! Les briques visuelles, partagées par tous les écrans.
//!
//! ## 🔴 Les formes d'état sont PEINTES, jamais écrites
//!
//! « ● », « ▲ », « ■ » s'affichent en carré vide avec les polices d'egui, et un tofu
//! ressemble assez à une icône pour passer inaperçu en relecture. Toutes les formes de
//! ce module sont donc tracées au `Painter` — elles ne dépendent d'aucune police, ne
//! peuvent pas manquer, et restent nettes à toute taille.
//!
//! ## Trois canaux, jamais un seul
//!
//! Un état se lit par sa **forme**, son **mot** et sa **couleur**. Environ 8 % des
//! hommes distinguent mal le rouge du vert ; une pastille colorée sans mot ne leur dit
//! rien, et un thème à contraste élevé ne rattraperait pas ça.

use egui::{Align, Color32, Layout, Rect, RichText, Sense, Shape, Stroke, Ui, Vec2};
use hlb_api::Attention;

use super::palette::Palette;
use super::theme::{melanger, mesures};

/// La palette courante.
///
/// Rangée dans la mémoire d'egui par [`super::theme::appliquer`] plutôt que passée en
/// argument à chaque fonction : vingt écrans qui se transmettent un `&Palette` de main
/// en main finissent par en avoir deux, et une moitié de l'interface reste dans
/// l'ancien thème après un changement.
pub fn palette(ui: &Ui) -> Palette {
    ui.ctx()
        .data(|d| d.get_temp::<Palette>(egui::Id::new("hlb_palette")))
        .unwrap_or_else(|| super::Theme::turi_sombre().palette)
}

/// Range la palette pour que [`palette`] la retrouve.
pub fn poser_palette(ctx: &egui::Context, p: Palette) {
    ctx.data_mut(|d| d.insert_temp(egui::Id::new("hlb_palette"), p));
}

// ---------------------------------------------------------------------------
// Texte
// ---------------------------------------------------------------------------

/// L'échelle typographique. Cinq niveaux, pas douze.
pub mod taille {
    pub const TITRE: f32 = 21.0;
    pub const SOUS_TITRE: f32 = 16.0;
    pub const CORPS: f32 = 13.5;
    pub const LEGENDE: f32 = 11.5;
}

/// Du texte venu d'un utilisateur, affiché sans risque de carré vide.
///
/// 🔴 À utiliser pour **tout** ce qui n'est pas un littéral du code : titres d'annonces,
/// noms de dossiers Sieve, descriptions d'aliases. Voir `super::glyphes`.
pub fn texte_libre(ui: &mut Ui, s: &str) -> egui::Response {
    let propre = super::glyphes::sans_tofu(s);
    let r = ui.label(RichText::new(&propre).size(taille::CORPS));
    match super::glyphes::explication(s) {
        Some(e) => r.on_hover_text(e),
        None => r,
    }
}

pub fn titre(ui: &mut Ui, s: &str) {
    let p = palette(ui);
    ui.label(RichText::new(s).size(taille::TITRE).strong().color(p.texte));
}

pub fn sous_titre(ui: &mut Ui, s: &str) {
    let p = palette(ui);
    ui.label(RichText::new(s).size(taille::SOUS_TITRE).strong().color(p.texte));
}

/// Une légende : du texte secondaire, qui se replie proprement.
///
/// ⚠️ `Label::wrap()` explicite. Sans lui, egui coupe une phrase longue là où il peut
/// — souvent au milieu, en laissant un trou visible avant la fin de la ligne. Le défaut
/// dépend de la largeur disponible, donc il n'apparaît que sur certaines fenêtres :
/// invisible en test, évident à l'écran.
pub fn legende(ui: &mut Ui, s: &str) {
    let p = palette(ui);
    ui.add(
        egui::Label::new(
            RichText::new(super::glyphes::sans_tofu(s))
                .size(taille::LEGENDE)
                .color(p.texte_faible),
        )
        .wrap(),
    );
}

pub fn mono(ui: &mut Ui, s: &str) {
    let p = palette(ui);
    ui.label(
        RichText::new(s)
            .monospace()
            .size(taille::LEGENDE)
            .color(p.texte_faible),
    );
}

// ---------------------------------------------------------------------------
// États
// ---------------------------------------------------------------------------

/// Le mot d'un niveau d'attention.
///
/// 🔴 La couleur ne porte jamais l'information seule.
pub fn mot(a: Attention) -> &'static str {
    match a {
        Attention::Ok => "ok",
        Attention::Notice => "à voir",
        Attention::Critical => "ACTION",
    }
}

/// La pastille d'état : une forme **peinte**, distincte par sa géométrie.
///
/// Rond, triangle, carré : reconnaissables même en niveaux de gris, même petits, même
/// pour qui ne distingue pas le rouge du vert.
pub fn pastille(ui: &mut Ui, a: Attention) {
    pastille_taille(ui, a, 11.0);
}

pub fn pastille_taille(ui: &mut Ui, a: Attention, taille: f32) {
    let c = palette(ui).attention_de(a);
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(taille), Sense::hover());
    let centre = rect.center();
    let p = ui.painter();

    match a {
        Attention::Ok => {
            p.circle_filled(centre, taille * 0.38, c);
        }
        Attention::Notice => {
            let r = taille * 0.46;
            p.add(Shape::convex_polygon(
                vec![
                    centre + Vec2::new(0.0, -r),
                    centre + Vec2::new(r * 0.92, r * 0.72),
                    centre + Vec2::new(-r * 0.92, r * 0.72),
                ],
                c,
                Stroke::NONE,
            ));
        }
        Attention::Critical => {
            let r = taille * 0.34;
            p.rect_filled(Rect::from_center_size(centre, Vec2::splat(r * 2.0)), 1.0, c);
        }
    }
}

/// Forme + mot + couleur, d'un bloc.
pub fn etat(ui: &mut Ui, a: Attention) {
    let c = palette(ui).attention_de(a);
    ui.horizontal(|ui| {
        pastille(ui, a);
        ui.label(RichText::new(mot(a)).size(taille::LEGENDE).color(c).strong());
    });
}

/// Une étiquette colorée : catégorie, tier, classe de volume.
pub fn badge(ui: &mut Ui, s: &str, teinte: Color32) -> egui::Response {
    let p = palette(ui);
    let fond = melanger(p.surface_haute, teinte, 0.22);
    egui::Frame::new()
        .fill(fond)
        .corner_radius(mesures::RAYON_PETIT as u8)
        .inner_margin(egui::Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.label(
                RichText::new(super::glyphes::sans_tofu(s))
                    .size(taille::LEGENDE)
                    .color(teinte),
            );
        })
        .response
}

// ---------------------------------------------------------------------------
// Conteneurs
// ---------------------------------------------------------------------------

/// Une carte : le conteneur de base de tous les écrans.
///
/// ⚠️ **Pleine largeur, toujours.** Sans `set_width`, chaque carte prend la largeur de
/// son contenu : une liste de cartes devient un escalier dont le bord droit suit la
/// longueur du texte. C'est le premier défaut qu'on voit à l'écran, et il ne se voit
/// pas du tout dans le code.
pub fn carte<R>(ui: &mut Ui, contenu: impl FnOnce(&mut Ui) -> R) -> R {
    let p = palette(ui);
    egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0_f32, p.bordure))
        .corner_radius(mesures::RAYON as u8)
        .inner_margin(egui::Margin::same(mesures::MARGE as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            contenu(ui)
        })
        .inner
}

/// Une carte dont la bordure porte un niveau d'attention.
///
/// ⚠️ Seule la bordure change, jamais le fond : un fond rouge sur une carte fait
/// hurler tout l'écran, et « rien de vert n'a besoin d'être grand » (§11bis) suppose
/// que le calme soit le défaut.
pub fn carte_attention<R>(
    ui: &mut Ui,
    a: Attention,
    contenu: impl FnOnce(&mut Ui) -> R,
) -> egui::Response {
    let p = palette(ui);
    let bord = match a {
        Attention::Ok => p.bordure,
        _ => p.attention_de(a),
    };
    egui::Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(if a == Attention::Ok { 1.0_f32 } else { 1.5_f32 }, bord))
        .corner_radius(mesures::RAYON as u8)
        .inner_margin(egui::Margin::same(mesures::MARGE as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            contenu(ui);
        })
        .response
}

/// Un bandeau pleine largeur : péremption des données, mode démonstration, incident.
pub fn bandeau(ui: &mut Ui, teinte: Color32, message: &str, detail: Option<&str>) {
    let p = palette(ui);
    egui::Frame::new()
        .fill(melanger(p.surface, teinte, 0.16))
        .stroke(Stroke::new(1.0_f32, teinte))
        .corner_radius(mesures::RAYON_PETIT as u8)
        .inner_margin(egui::Margin::same(mesures::ESPACE as i8))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(super::glyphes::sans_tofu(message))
                        .size(taille::CORPS)
                        .strong()
                        .color(teinte),
                );
                if let Some(d) = detail {
                    ui.label(
                        RichText::new(super::glyphes::sans_tofu(d))
                            .size(taille::LEGENDE)
                            .color(p.texte_faible),
                    );
                }
            });
        });
}

/// Un écran vide qui dit **quoi faire**, pas juste qu'il est vide.
pub fn etat_vide(ui: &mut Ui, message: &str, commande: Option<&str>) {
    let p = palette(ui);
    ui.add_space(mesures::ESPACE_LARGE);
    ui.vertical_centered(|ui| {
        ui.label(RichText::new(message).size(taille::CORPS).color(p.texte_faible));
        if let Some(c) = commande {
            ui.add_space(mesures::ESPACE_SERRE);
            ui.label(
                RichText::new(c)
                    .monospace()
                    .size(taille::LEGENDE)
                    .color(p.accent),
            );
        }
    });
    ui.add_space(mesures::ESPACE_LARGE);
}

// ---------------------------------------------------------------------------
// Chiffres
// ---------------------------------------------------------------------------

/// Une tuile de statistique : un grand chiffre, son libellé, un complément.
pub fn tuile_stat(ui: &mut Ui, libelle: &str, valeur: &str, sous_texte: Option<&str>, teinte: Color32) {
    let p = palette(ui);
    ui.vertical(|ui| {
        ui.label(
            RichText::new(libelle.to_uppercase())
                .size(taille::LEGENDE)
                .color(p.texte_faible),
        );
        ui.label(RichText::new(valeur).size(taille::TITRE).strong().color(teinte));
        if let Some(s) = sous_texte {
            ui.label(RichText::new(s).size(taille::LEGENDE).color(p.texte_faible));
        }
    });
}

/// Une jauge horizontale, peinte.
///
/// `fraction` est bornée à [0, 1] : une valeur hors bornes déborderait du cadre et
/// donnerait l'impression d'un défaut d'affichage plutôt que d'une donnée aberrante.
pub fn jauge(ui: &mut Ui, fraction: f32, teinte: Color32, largeur: f32) {
    let p = palette(ui);
    let hauteur = 6.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(largeur, hauteur), Sense::hover());
    let pe = ui.painter();
    pe.rect_filled(rect, hauteur / 2.0, p.surface_haute);

    let f = fraction.clamp(0.0, 1.0);
    if f > 0.0 {
        let remplie = Rect::from_min_size(rect.min, Vec2::new(rect.width() * f, hauteur));
        pe.rect_filled(remplie, hauteur / 2.0, teinte);
    }
}

/// Une courbe minuscule, peinte.
///
/// 🔴 Une série **vide** ne dessine rien et le dit : une ligne plate à zéro se lit
/// « tout est calme », ce qui est exactement le contraire de « je n'ai pas de données ».
pub fn sparkline(ui: &mut Ui, points: &[f64], teinte: Color32, taille_px: Vec2) {
    let p = palette(ui);
    let (rect, _) = ui.allocate_exact_size(taille_px, Sense::hover());

    if points.len() < 2 {
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "pas de mesure",
            egui::FontId::proportional(taille::LEGENDE - 1.0),
            p.texte_faible,
        );
        return;
    }

    let min = points.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = points.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    // Une série constante n'a pas d'amplitude : la centrer vaut mieux que diviser par
    // zéro, ou que l'écraser en bas du cadre comme si elle valait le minimum.
    let etendue = if (max - min).abs() < f64::EPSILON { 1.0 } else { max - min };

    let pas = rect.width() / (points.len() - 1) as f32;
    let sommets: Vec<egui::Pos2> = points
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let x = rect.min.x + i as f32 * pas;
            let y = rect.max.y - (((v - min) / etendue) as f32) * rect.height();
            egui::pos2(x, y)
        })
        .collect();

    ui.painter()
        .add(Shape::line(sommets, Stroke::new(1.5_f32, teinte)));
}

/// Les initiales d'un nom, pour un monogramme.
///
/// Une ou deux lettres : au-delà, c'est illisible dans un carré de 32 px. Un nom vide
/// rend « ? » plutôt qu'une chaîne vide — un carré sans lettre se prendrait pour une
/// image cassée.
pub fn initiales(nom: &str) -> String {
    let i: String = nom
        .split(['-', '_', ' '])
        .filter(|m| !m.is_empty())
        .take(2)
        .filter_map(|m| m.chars().next())
        .collect::<String>()
        .to_uppercase();
    if i.is_empty() {
        "?".to_string()
    } else {
        i
    }
}

/// Un monogramme peint : les initiales dans un carré à la couleur de la marque.
///
/// Sert d'icône par défaut aux apps et aux comptes. Peint plutôt que dessiné à partir
/// d'un fichier : aucune ressource à charger, aucune requête réseau, et jamais de carré
/// gris à la place d'une image absente.
pub fn monogramme(ui: &mut Ui, nom: &str, teinte: Color32, cote: f32) {
    let p = palette(ui);
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(cote), Sense::hover());
    let pe = ui.painter();
    pe.rect_filled(rect, mesures::RAYON_PETIT, melanger(p.surface_haute, teinte, 0.30));

    pe.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        super::glyphes::sans_tofu(&initiales(nom)),
        egui::FontId::proportional(cote * 0.42),
        teinte,
    );
}

/// Une ligne étiquette / valeur, alignée : le motif le plus fréquent des écrans de
/// détail.
pub fn ligne(ui: &mut Ui, etiquette: &str, valeur: &str) {
    let p = palette(ui);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(etiquette)
                .size(taille::CORPS)
                .color(p.texte_faible),
        );
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new(super::glyphes::sans_tofu(valeur))
                    .size(taille::CORPS)
                    .color(p.texte),
            );
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les littéraux de chaîne d'une ligne de code.
    ///
    /// Analyse volontairement grossière — on ne réimplémente pas un analyseur Rust :
    /// il s'agit de distinguer « du texte affiché » de « du code », pas de tout
    /// comprendre.
    fn chaines_de(code: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut courant = String::new();
        let mut dedans = false;
        let mut echappe = false;

        for c in code.chars() {
            if echappe {
                echappe = false;
                continue;
            }
            match c {
                '\\' if dedans => echappe = true,
                '"' => {
                    if dedans {
                        out.push(std::mem::take(&mut courant));
                    }
                    dedans = !dedans;
                }
                _ if dedans => courant.push(c),
                _ => {}
            }
        }
        out
    }

    #[test]
    fn the_string_extractor_ignores_rust_patterns() {
        // Le garde-fou du garde-fou : un motif Rust n'est pas du texte affiché.
        //
        // ⚠️ L'exemple est ASSEMBLÉ, pas écrit : l'écrire ferait échouer le test voisin
        // qui interdit les pluriels entre parenthèses dans ce fichier. Même astuce que
        // le test qui interdit `Instant::now()` sans se déclencher lui-même.
        let motif = format!("Some({}) if *s > 0 => x,", "s");
        assert!(chaines_de(&motif).is_empty());
        // Assemblé pour la même raison : ce fichier s'interdit le motif qu'il teste.
        let tic = format!("nœud({})", "s");
        let ligne = format!(r#"format!("{{}} {tic}", n)"#);
        assert_eq!(chaines_de(&ligne), vec![format!("{{}} {tic}")]);
    }

    #[test]
    fn no_displayed_string_carries_a_collapsed_line_continuation() {
        // 🔴 Le piège documenté du projet : un `\` en fin de ligne Rust mange la
        // newline ET l'indentation de la ligne suivante. Sans le `\` de continuation,
        // c'est l'inverse — l'indentation reste DANS la chaîne, et le texte s'affiche
        // avec un trou au milieu.
        //
        // Constaté à l'écran : « enregistré côté serveur,        pas dans ce
        // navigateur. » Invisible en lisant le code, évident dès qu'on regarde.
        let fichiers: &[(&str, &str)] = &[
            ("reglages.rs", include_str!("../ecrans/reglages.rs")),
            ("portail.rs", include_str!("../ecrans/portail.rs")),
            ("comptes.rs", include_str!("../ecrans/comptes.rs")),
            ("annonces.rs", include_str!("../ecrans/annonces.rs")),
            ("inscription.rs", include_str!("../ecrans/inscription.rs")),
            ("statut.rs", include_str!("../ecrans/statut.rs")),
            ("sauvegardes.rs", include_str!("../ecrans/sauvegardes.rs")),
            ("noeuds.rs", include_str!("../ecrans/noeuds.rs")),
            ("alertes.rs", include_str!("../ecrans/alertes.rs")),
            ("topologie.rs", include_str!("../ecrans/topologie.rs")),
            ("tableau_bord.rs", include_str!("../ecrans/tableau_bord.rs")),
            ("app_detail.rs", include_str!("../ecrans/app_detail.rs")),
            ("action.rs", include_str!("../ecrans/action.rs")),
        ];

        for (nom, src) in fichiers {
            for (n, ligne) in src.lines().enumerate() {
                let code = ligne.split("//").next().unwrap_or("");
                for chaine in chaines_de(code) {
                    // Deux espaces consécutifs AU MILIEU d'une phrase : ni en tête (une
                    // chaîne peut légitimement commencer par un espace), ni dans du
                    // texte monospace où l'alignement est voulu.
                    let milieu = chaine.trim();
                    assert!(
                        !milieu.contains("  "),
                        "{nom} ligne {} : espaces multiples dans « {milieu} » — \
                         continuation de ligne oubliée ?",
                        n + 1
                    );
                }
            }
        }
    }

    #[test]
    fn no_screen_displays_a_parenthesised_plural() {
        // 🔴 « 3 application(s) » est le tic qui trahit un texte fabriqué. Le projet
        // est en français et soigné partout ailleurs ; `hlb_api::pluriel` existe pour
        // ça, et ce test empêche la facilité de revenir par la porte de service.
        //
        // ⚠️ Les COMMENTAIRES sont exclus : on doit pouvoir écrire « action(s) » en
        // expliquant précisément qu'on ne l'affiche pas.
        let fichiers: &[(&str, &str)] = &[
            ("apps.rs", include_str!("../ecrans/apps.rs")),
            ("tableau_bord.rs", include_str!("../ecrans/tableau_bord.rs")),
            ("noeuds.rs", include_str!("../ecrans/noeuds.rs")),
            ("alertes.rs", include_str!("../ecrans/alertes.rs")),
            ("sauvegardes.rs", include_str!("../ecrans/sauvegardes.rs")),
            ("topologie.rs", include_str!("../ecrans/topologie.rs")),
            ("a_faire.rs", include_str!("../ecrans/a_faire.rs")),
            ("reglages.rs", include_str!("../ecrans/reglages.rs")),
            ("app_detail.rs", include_str!("../ecrans/app_detail.rs")),
            ("action.rs", include_str!("../ecrans/action.rs")),
            ("comptes.rs", include_str!("../ecrans/comptes.rs")),
            // Le module de design lui-même : une infobulle est du texte affiché comme
            // un autre, et le tic s'y était glissé.
            ("glyphes.rs", include_str!("glyphes.rs")),
            ("composants.rs", include_str!("composants.rs")),
        ];

        // ⚠️ Le motif est ASSEMBLÉ à l'exécution : l'écrire ici ferait échouer ce test
        // sur son propre source, qui figure dans la liste. C'est la même astuce que le
        // test qui interdit `Instant::now()` sans se déclencher lui-même.
        let tic = format!("({})", "s");

        for (nom, src) in fichiers {
            for (n, ligne) in src.lines().enumerate() {
                let code = ligne.split("//").next().unwrap_or("");
                // ⚠️ Uniquement dans les CHAÎNES affichées : `Some(s)` contient
                // « (s) » et n'a rien à voir. Scanner le code brut donnerait des faux
                // positifs, on désactiverait le test, et il ne protégerait plus rien.
                for chaine in chaines_de(code) {
                    assert!(
                        !chaine.contains(&tic),
                        "{nom} ligne {} : pluriel entre parenthèses dans « {chaine} » — \
                         utilise hlb_api::pluriel",
                        n + 1
                    );
                }
            }
        }
    }

    #[test]
    fn every_level_has_a_word_not_just_a_colour() {
        // 🔴 Environ 8 % des hommes distinguent mal le rouge du vert. Une pastille
        // colorée sans mot ne leur dit rien.
        let mots: Vec<&str> = [Attention::Ok, Attention::Notice, Attention::Critical]
            .into_iter()
            .map(mot)
            .collect();
        assert_eq!(mots.len(), 3);
        for m in &mots {
            assert!(!m.is_empty());
        }
        let mut uniques = mots.clone();
        uniques.sort_unstable();
        uniques.dedup();
        assert_eq!(uniques.len(), 3, "deux niveaux portent le même mot");
    }

    #[test]
    fn no_displayed_text_needs_a_glyph_egui_might_not_have() {
        // 🔴 Scanne les littéraux de CE fichier. Un « ● » recopié ici s'afficherait en
        // carré vide, et un tofu ressemble assez à une icône pour passer la relecture.
        let src = include_str!("composants.rs");
        for (n, ligne) in src.lines().enumerate() {
            let sans_commentaire = ligne.split("//").next().unwrap_or("");
            for c in sans_commentaire.chars() {
                assert!(
                    super::super::glyphes::sur(c),
                    "ligne {} : U+{:04X} pourrait s'afficher en carré vide",
                    n + 1,
                    c as u32
                );
            }
        }
    }

    #[test]
    fn the_state_shapes_are_painted_not_written() {
        // Les trois formes viennent du `Painter` : aucune n'est un caractère. Un test
        // qui vérifierait la sortie graphique serait fragile ; celui-ci vérifie ce qui
        // compte vraiment — qu'aucun glyphe de forme ne soit écrit dans le source.
        // ⚠️ Hors commentaires : la documentation du module NOMME ces glyphes pour
        // expliquer pourquoi on ne les écrit pas. Les lui interdire rendrait
        // l'explication impossible à écrire.
        let src: String = include_str!("composants.rs")
            .lines()
            .filter_map(|l| l.split("//").next())
            .collect::<Vec<_>>()
            .join("\n");
        for interdit in ['\u{25CF}', '\u{25B2}', '\u{25A0}', '\u{2691}'] {
            assert!(
                !src.contains(interdit),
                "U+{:04X} écrit au lieu d'être peint",
                interdit as u32
            );
        }
        assert!(src.contains("circle_filled"), "le rond doit être peint");
        assert!(src.contains("convex_polygon"), "le triangle doit être peint");
        assert!(src.contains("rect_filled"), "le carré doit être peint");
    }

    #[test]
    fn every_container_takes_the_full_width() {
        // 🔴 Constaté à l'écran : sans `set_width`, chaque carte prend la largeur de
        // son contenu, et une liste de cartes devient un escalier. Le défaut est
        // invisible dans le code et saute aux yeux dès qu'on regarde l'interface.
        let src = include_str!("composants.rs");
        let conteneurs = ["pub fn carte<R>", "pub fn carte_attention<R>", "pub fn bandeau"];
        for c in conteneurs {
            let debut = src.find(c).unwrap_or_else(|| panic!("{c} introuvable"));
            // Le corps de la fonction, jusqu'à la suivante.
            let fin = src[debut + c.len()..]
                .find("\npub fn ")
                .map(|i| debut + c.len() + i)
                .unwrap_or(src.len());
            assert!(
                src[debut..fin].contains("set_width"),
                "{c} ne force pas sa largeur : ses instances formeront un escalier"
            );
        }
    }

    #[test]
    fn a_monogram_never_shows_more_than_two_letters() {
        // Trois lettres dans un carré de 32 px sont illisibles ; zéro laisserait un
        // carré vide qu'on prendrait pour une image cassée.
        assert_eq!(initiales("gitea"), "G");
        assert_eq!(initiales("immich-machine-learning"), "IM");
        assert_eq!(initiales("n8n"), "N");
        assert_eq!(initiales("Turi Industries"), "TI");
        assert_eq!(initiales(""), "?", "jamais un carré sans lettre");
        assert_eq!(initiales("---"), "?");
    }
}
