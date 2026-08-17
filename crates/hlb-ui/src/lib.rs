//! Le tableau de bord, exposé en bibliothèque autant qu'en binaire.
//!
//! Les tests d'intégration doivent pouvoir exercer le client — et surtout la détection
//! de péremption — sans lancer de fenêtre graphique.

pub mod app;
pub mod client;

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

    wasm_bindgen_futures::spawn_local(async move {
        let partage = std::sync::Arc::new(client::Shared::default());
        let poller = client::Poller::new(&origine, None, 5.0, partage.clone());

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
