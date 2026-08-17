//! Le tableau de bord, exposé en bibliothèque autant qu'en binaire.
//!
//! Les tests d'intégration doivent pouvoir exercer le client — et surtout la détection
//! de péremption — sans lancer de fenêtre graphique.

pub mod app;
pub mod client;

/// Récupère le jeton d'accès, en navigateur.
///
/// ## 🔴 Le fragment d'URL, et surtout pas la chaîne de requête
///
/// Un jeton passé en `?token=…` est envoyé au serveur : il finit dans les journaux
/// d'accès, dans les en-têtes `Referer` vers des sites tiers, et dans tout proxy sur
/// le chemin. Un secret qui traverse une infrastructure de journalisation n'est plus
/// un secret.
///
/// Le **fragment** (`#token=…`) n'est jamais transmis au serveur : il reste dans le
/// navigateur. On le lit une fois, on le range dans `localStorage`, et on **l'efface
/// de la barre d'adresse** pour qu'il ne parte pas dans un copier-coller.
///
/// ⚠️ Il reste dans l'historique du navigateur. C'est un compromis assumé :
/// l'alternative — une saisie au clavier — est le point faible d'egui sur téléphone,
/// et un jeton de 52 caractères tapé à la main serait pire à tout point de vue.
#[cfg(target_arch = "wasm32")]
fn jeton_web() -> Option<String> {
    let w = web_sys::window()?;

    // 1. Un fragment fraîchement fourni l'emporte : c'est ainsi qu'on change de jeton.
    let fragment = w.location().hash().ok().unwrap_or_default();
    if let Some(v) = fragment.trim_start_matches('#').strip_prefix("token=") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            if let Ok(Some(s)) = w.local_storage() {
                let _ = s.set_item("hlb_token", &v);
            }
            // Effacé de la barre d'adresse : un lien copié ne doit pas emporter le
            // jeton avec lui.
            let _ = w.location().set_hash("");
            return Some(v);
        }
    }

    // 2. Sinon, celui rangé au précédent passage.
    w.local_storage()
        .ok()
        .flatten()
        .and_then(|s| s.get_item("hlb_token").ok().flatten())
        .filter(|v| !v.is_empty())
}

/// Le point d'entrée web.
///
/// ⚠️ Le canevas est cherché par identifiant : eframe 0.33 ne prend plus une balise
/// arbitraire, il lui faut un `<canvas id="hlb">`. Sans lui, la page reste blanche
/// **sans erreur en console** — le mode d'échec le plus déroutant du portage web.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn demarrer_web() {
    use wasm_bindgen::JsCast as _;

    // Sans ça, une panique Rust se solde par un onglet figé et une console muette.
    console_error_panic_hook::set_once();

    let document = web_sys::window()
        .and_then(|w| w.document())
        .expect("pas de document");
    let canevas = document
        .get_element_by_id("hlb")
        .and_then(|e| e.dyn_into::<web_sys::HtmlCanvasElement>().ok())
        .expect("il faut un <canvas id=\"hlb\"> dans la page");

    // L'URL du controller vient de la page qui sert l'UI : en web, on est servi PAR
    // le controller, donc son adresse est celle de l'origine courante.
    let origine = web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_else(|| "http://localhost:8420".to_string());

    let jeton = jeton_web();

    wasm_bindgen_futures::spawn_local(async move {
        let partage = std::sync::Arc::new(client::Shared::default());
        let poller = client::Poller::new(&origine, jeton, 5.0, partage.clone());

        let _ = eframe::WebRunner::new()
            .start(
                canevas,
                eframe::WebOptions::default(),
                Box::new(move |_cc| {
                    Ok(Box::new(app::Dashboard::new(
                        partage,
                        poller,
                        app::Onglet::default(),
                    )))
                }),
            )
            .await;
    });
}
