//! Le tableau de bord, exposé en bibliothèque autant qu'en binaire.
//!
//! Les tests d'intégration doivent pouvoir exercer le client — et surtout la détection
//! de péremption — sans lancer de fenêtre graphique.

pub mod kiosque;
pub mod client;
pub mod design;
pub mod ecrans;
pub mod route;
pub mod shell;

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

/// Récupère le jeton d'INVITATION, en navigateur.
///
/// ## 🔴 Pourquoi il n'est PAS rangé dans le stockage local
///
/// Contrairement au jeton d'accès, une invitation sert **une fois** et ne doit pas
/// survivre à la fermeture de l'onglet. La garder ferait qu'un navigateur partagé
/// proposerait l'inscription à la personne suivante, avec le lien de la précédente —
/// et le compte créé porterait le rôle prévu pour quelqu'un d'autre.
///
/// Comme le jeton d'accès, elle est effacée de la barre d'adresse immédiatement : un
/// lien recopié ne doit pas emporter l'invitation avec lui.
#[cfg(target_arch = "wasm32")]
fn invitation_web() -> Option<String> {
    let w = web_sys::window()?;
    let fragment = w.location().hash().ok().unwrap_or_default();
    let v = fragment
        .trim_start_matches('#')
        .strip_prefix("invitation=")?
        .trim()
        .to_string();

    if v.is_empty() {
        return None;
    }
    let _ = w.location().set_hash("");
    Some(v)
}

/// Écrit la route dans le fragment d'URL, sans empiler d'entrée d'historique.
///
/// ⚠️ `replace_state` et non `set_hash` : ce dernier ajoute une entrée à l'historique à
/// chaque clic, si bien que le bouton « précédent » remonte clic par clic au lieu de
/// revenir là d'où l'on vient.
#[cfg(target_arch = "wasm32")]
pub fn ecrire_fragment(route: &str) {
    if let Some(w) = web_sys::window() {
        let _ = w
            .history()
            .map(|h| h.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&format!("#{route}"))));
    }
}

/// Le point d'entrée web.
///
/// ⚠️ Le canevas est cherché par identifiant : eframe 0.33 ne prend plus une balise
/// arbitraire, il lui faut un `<canvas id="hlb">`. Sans lui, la page reste blanche
/// **sans erreur en console** — le mode d'échec le plus déroutant du portage web.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn demarrer_web() {
    // Sans ça, une panique Rust se solde par un onglet figé et une console muette.
    console_error_panic_hook::set_once();

    // ⚠️ Le canevas est cherché dans `demarrer`, pas ici : les deux chemins d'entrée
    // (avec et sans invitation) doivent partager exactement le même démarrage.

    // L'URL du controller vient de la page qui sert l'UI : en web, on est servi PAR
    // le controller, donc son adresse est celle de l'origine courante.
    let origine = web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_else(|| "http://localhost:8420".to_string());

    // 🔴 L'ORDRE compte : les secrets du fragment sont consommés et EFFACÉS d'abord, la
    // route est lue ensuite. L'inverse les laisserait dans la barre d'adresse le temps
    // d'une frame — assez pour partir dans un copier-coller ou une capture.
    let jeton = jeton_web();
    let invitation = invitation_web();

    // Une invitation ouvre directement l'écran d'inscription : la personne n'a pas de
    // compte, et le tableau de bord lui répondrait 403.
    if invitation.is_some() {
        let route = route::Route::Inscription;
        return demarrer(origine, jeton, invitation, route);
    }

    let route: route::Route = web_sys::window()
        .and_then(|w| w.location().hash().ok())
        .and_then(|h| h.parse().ok())
        .unwrap_or_default();

    demarrer(origine, jeton, invitation, route);
}

/// Lance l'interface.
///
/// Extrait pour que le chemin « une invitation ouvre l'inscription » et le chemin
/// normal partagent exactement le même démarrage — deux copies finiraient par diverger
/// sur un détail de configuration.
#[cfg(target_arch = "wasm32")]
fn demarrer(
    origine: String,
    jeton: Option<String>,
    invitation: Option<String>,
    route: route::Route,
) {
    use wasm_bindgen::JsCast as _;

    let document = match web_sys::window().and_then(|w| w.document()) {
        Some(d) => d,
        None => return,
    };
    let canevas = match document
        .get_element_by_id("hlb")
        .and_then(|e| e.dyn_into::<web_sys::HtmlCanvasElement>().ok())
    {
        Some(c) => c,
        None => return,
    };

    wasm_bindgen_futures::spawn_local(async move {
        let partage = std::sync::Arc::new(client::Shared::default());
        let poller = client::Poller::new(&origine, jeton, 5.0, partage.clone());

        let _ = eframe::WebRunner::new()
            .start(
                canevas,
                eframe::WebOptions::default(),
                Box::new(move |_cc| {
                    let mut app = shell::Application::new(partage, poller, route);
                    app.avec_invitation(invitation);
                    Ok(Box::new(app))
                }),
            )
            .await;
    });
}

#[cfg(test)]
mod tests_pwa {
    /// 🔴 L'invariant du lot 11.3, et le seul de ce fichier.
    ///
    /// Un service worker qui met l'API en cache ressusciterait exactement le mensonge
    /// que `Freshness` existe pour empêcher : des applications affichées en vert,
    /// servies depuis le cache, pendant que le cluster brûle. La coquille se met en
    /// cache ; les données, jamais.
    #[test]
    fn the_service_worker_never_caches_the_api() {
        let sw = include_str!("../web/sw.js");

        // La liste des ressources mises en cache, telle qu'elle est écrite.
        let debut = sw.find("const COQUILLE = [").expect("la liste de coquille");
        let fin = sw[debut..].find("];").expect("fin de liste") + debut;
        let coquille = &sw[debut..fin];

        for interdit in ["/api/", "/auth/", "/metrics"] {
            assert!(
                !coquille.contains(interdit),
                "« {interdit} » est mis en cache : une donnée périmée deviendrait \
                 indiscernable d'une donnée fraîche"
            );
        }

        // Et le gestionnaire de requêtes doit laisser passer ces chemins au réseau.
        for chemin in ["/api/", "/auth/", "/metrics"] {
            assert!(
                sw.contains(chemin),
                "sw.js ne mentionne pas « {chemin} » : rien ne garantit qu'il l'exclut"
            );
        }
    }

    #[test]
    fn the_build_script_enforces_a_size_budget() {
        // 🔴 Le lot 12.2. Un bundle qui double en silence rend l'interface « lente »
        // sans que rien ne désigne la cause. Le budget vit dans le script de build
        // parce que c'est là qu'on peut mesurer le fichier final — mais un test vérifie
        // qu'il n'a pas été retiré, ce qui est le genre de chose qu'on fait « juste
        // pour débloquer » et qu'on n'annule jamais.
        let sh = include_str!("../build-web.sh");
        assert!(sh.contains("BUDGET_MO"), "le budget de taille a disparu");
        // Et le dépassement doit ARRÊTER le build : un avertissement se lit une fois.
        assert!(
            sh.contains("exit 1"),
            "le dépassement de budget doit être une erreur, pas un avertissement"
        );
    }

    #[test]
    fn the_manifest_declares_a_scope_that_matches_the_start_url() {
        // ⚠️ Un `scope` plus étroit que `start_url` fait que le navigateur ouvre l'app
        // dans un onglet ordinaire au lieu du mode autonome, sans le moindre message.
        let m = include_str!("../web/manifest.json");
        assert!(m.contains("\"start_url\": \"./\""), "{m}");
        assert!(m.contains("\"scope\": \"./\""), "{m}");
        assert!(m.contains("\"display\": \"standalone\""), "{m}");
    }

    #[test]
    fn the_icon_needs_no_font_and_no_raster_decoder() {
        // Le monogramme est peint en SVG : aucune police n'intervient (donc aucun tofu
        // possible), et aucun décodeur d'image n'est embarqué dans le wasm.
        let i = include_str!("../web/icone.svg");
        assert!(i.contains("<path"), "l'icône doit être un tracé, pas du texte");
        assert!(!i.contains("<text"), "un <text> dépendrait d'une police du système");
    }

    #[test]
    fn the_page_registers_the_worker_without_shouting_when_it_cannot() {
        // Sans service worker, l'interface marche exactement pareil : elle n'est
        // simplement pas installable. Une erreur affichée ferait chercher un défaut
        // inexistant — le navigateur refuse par exemple en HTTP simple.
        let h = include_str!("../web/index.html");
        assert!(h.contains("serviceWorker"), "{h}");
        assert!(h.contains(".catch("), "l'échec d'enregistrement doit être avalé");
        assert!(h.contains("rel=\"manifest\""));
    }
}
