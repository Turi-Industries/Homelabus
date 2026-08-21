//! Le QR code, **peint** (lot 11.2).
//!
//! ## 🔴 Pourquoi peint, et pas rendu en image
//!
//! Aucune police n'intervient, donc aucun tofu possible — c'est le même raisonnement
//! que les pastilles d'état. Et aucun décodeur d'image n'est embarqué : le QR est une
//! grille de booléens, et egui sait peindre des carrés.
//!
//! ## ⚠️ Un QR de jeton est un SECRET affiché à l'écran
//!
//! Il se photographie de loin, par-dessus l'épaule, et se retrouve dans une capture
//! d'écran partagée sans y penser. Il est donc montré **une fois**, avec sa mise en
//! garde, et n'est jamais réaffichable — exactement comme la valeur du jeton qu'il
//! encode.

use egui::{Color32, Rect, Sense, Vec2};

/// La marge silencieuse exigée par la norme, en modules.
///
/// 🔴 Sans elle, beaucoup de lecteurs échouent : ils ne trouvent pas les motifs de
/// détection collés au bord. Un QR qui « ne marche pas sur certains téléphones » est
/// presque toujours un QR sans marge.
const MARGE: usize = 4;

/// Peint un QR code encodant `donnee`, et rend sa largeur en pixels.
///
/// Rend `None` si la donnée ne tient pas dans un QR — trop longue, essentiellement.
/// ⚠️ Le dire plutôt que de peindre un carré vide : un QR illisible ressemble à un QR.
pub fn peindre(ui: &mut egui::Ui, donnee: &str, taille: f32) -> Option<f32> {
    let code = qrcode::QrCode::new(donnee.as_bytes()).ok()?;
    let modules = code.to_colors();
    let cote = code.width();
    let (px, largeur) = geometrie(cote, taille);

    let (rect, _) = ui.allocate_exact_size(Vec2::splat(largeur), Sense::hover());
    let p = ui.painter();

    // Le fond CLAIR est obligatoire, y compris en thème sombre : un lecteur attend des
    // modules sombres sur fond clair, et l'inverse n'est pas garanti d'être reconnu.
    p.rect_filled(rect, 0.0, Color32::WHITE);

    for y in 0..cote {
        for x in 0..cote {
            if modules[y * cote + x] == qrcode::Color::Dark {
                let coin = rect.min
                    + Vec2::new(
                        (x + MARGE) as f32 * px,
                        (y + MARGE) as f32 * px,
                    );
                p.rect_filled(
                    Rect::from_min_size(coin, Vec2::splat(px)),
                    0.0,
                    Color32::BLACK,
                );
            }
        }
    }

    Some(largeur)
}

/// La taille d'un module et la largeur totale, en pixels.
///
/// 🔴 Le module est un nombre ENTIER de pixels. Un module fractionnaire fait tomber les
/// bords sur des demi-pixels : egui les lisse, les carrés voisins se mélangent, et le
/// code devient illisible pour un lecteur alors qu'il paraît net à l'œil.
fn geometrie(cote: usize, taille: f32) -> (f32, f32) {
    let total = cote + 2 * MARGE;
    // ⚠️ Au moins 1 pixel par module : à 0, le QR disparaîtrait sans erreur.
    let px = (taille / total as f32).floor().max(1.0);
    (px, px * total as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_module_is_always_a_whole_number_of_pixels() {
        // 🔴 Un module fractionnaire fait tomber les bords sur des demi-pixels : egui
        // les lisse, les carrés voisins se mélangent, et le code devient illisible pour
        // un lecteur alors qu'il paraît net à l'œil.
        for taille in [80.0, 137.0, 180.0, 512.0] {
            let (px, largeur) = geometrie(25, taille);
            assert_eq!(px, px.floor(), "module fractionnaire à {taille}");
            assert!(largeur <= taille, "le QR déborde de la place allouée");
            // Et la largeur est exactement un multiple du module.
            assert_eq!(largeur % px, 0.0);
        }
    }

    #[test]
    fn a_tiny_allocation_still_paints_one_pixel_per_module() {
        // ⚠️ À zéro pixel par module, le QR disparaîtrait sans la moindre erreur — et
        // l'on chercherait du côté des données.
        let (px, _) = geometrie(45, 10.0);
        assert!(px >= 1.0);
    }

    #[test]
    fn the_quiet_zone_is_included_in_the_width() {
        // La marge fait partie du code : l'oublier dans le calcul dessinerait les
        // modules par-dessus, et le QR ne serait pas lisible.
        let cote = 21;
        let (px, largeur) = geometrie(cote, 290.0);
        assert_eq!(largeur, px * (cote + 2 * MARGE) as f32);
    }

    #[test]
    fn a_short_payload_produces_a_square_grid() {
        // Le calcul de taille est le seul endroit où l'on peut se tromper sans que ça
        // se voie : une grille non carrée ou décalée donne un QR illisible.
        let code = qrcode::QrCode::new(b"https://hlb.turi.fr/#invitation=ABCDEF").expect("qr");
        let cote = code.width();
        assert_eq!(code.to_colors().len(), cote * cote);
    }

    #[test]
    fn the_quiet_zone_is_four_modules_as_the_standard_demands() {
        // 🔴 Sans marge, beaucoup de lecteurs échouent : ils ne trouvent pas les motifs
        // de détection collés au bord. C'est la cause la plus fréquente d'un QR qui
        // « ne marche que sur certains téléphones ».
        assert_eq!(MARGE, 4);
    }

    #[test]
    fn a_payload_too_long_is_refused_rather_than_drawn_wrong() {
        // ⚠️ Un QR tronqué ressemble à un QR : on le scanne, on obtient autre chose, et
        // rien ne dit que c'est le rendu qui a échoué.
        let trop = "x".repeat(10_000);
        assert!(qrcode::QrCode::new(trop.as_bytes()).is_err());
    }

    #[test]
    fn the_same_payload_always_gives_the_same_grid() {
        // Un QR qui change d'un rendu à l'autre ferait douter de ce qu'on a scanné.
        let a = qrcode::QrCode::new(b"invitation=ABC").expect("qr");
        let b = qrcode::QrCode::new(b"invitation=ABC").expect("qr");
        assert_eq!(a.to_colors(), b.to_colors());
    }
}
