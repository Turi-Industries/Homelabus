//! `hlb-ui` — le tableau de bord.
//!
//! ## Pourquoi egui plutôt qu'une UI web
//!
//! Le plan prévoyait SvelteKit, donc un OpenAPI, une génération de types TypeScript,
//! et un pipeline npm. Trois représentations des mêmes données et un outillage entier
//! à maintenir.
//!
//! En Rust, il n'en reste qu'une : `hlb-api` définit les types, le controller les
//! sérialise, l'UI les désérialise, et **le compilateur refuse tout désaccord**. Un
//! champ renommé côté serveur casse la compilation ici, au lieu de produire un
//! `undefined` à l'exécution dans un écran que personne ne regardait.
//!
//! ## Ce que cette UI ne fait pas
//!
//! 🔴 **Lecture seule**, comme l'API (§11bis phase 2.5). Aucune mutation, donc aucune
//! surface d'attaque et aucun risque de casser quoi que ce soit depuis un écran. Les
//! actions passent par `hlb`, qui demande une confirmation explicite pour tout ce qui
//! est irréversible.
//!
//! ⚠️ Et elle n'est **pas** un substitut au CLI : si l'UI est cassée, `hlb` continue
//! de tout faire. C'est le principe du §11bis, et c'est ce qui permet de déboguer le
//! jour où l'interface ne démarre plus.

mod app;

use hlb_ui::client;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

#[derive(Parser)]
#[command(name = "hlb-ui", version, about = "Tableau de bord HomelabUS")]
struct Cli {
    /// URL de l'API du controller.
    #[arg(long, default_value = "http://localhost:8420", env = "HLB_CONTROLLER_URL")]
    url: String,

    /// Jeton, si le controller en exige un.
    #[arg(long, env = "HLB_METRICS_TOKEN")]
    token: Option<String>,

    /// Onglet d'ouverture : apps, todo, journal, secrets.
    ///
    /// Utile pour épingler l'écran qui t'intéresse — la liste des actions en attente,
    /// par exemple — sans avoir à cliquer à chaque lancement.
    #[arg(long, default_value = "apps")]
    tab: String,

    /// Intervalle de rafraîchissement, en secondes.
    ///
    /// ⚠️ Descendre trop bas ne rend pas le tableau de bord plus juste : les données
    /// qu'il affiche (âge des sauvegardes, actions en attente) bougent à l'échelle de
    /// la minute. Ça ne fait qu'ajouter de la charge au controller.
    #[arg(long, default_value = "5")]
    refresh_secs: u64,
}

fn main() -> eframe::Result<()> {
    let cli = Cli::parse();

    let onglet: app::Onglet = match cli.tab.parse() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let shared = Arc::new(client::Shared::default());
    let c = client::Client::new(&cli.url, cli.token.clone());

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 700.0])
            .with_min_inner_size([700.0, 400.0])
            .with_title("HomelabUS"),
        ..Default::default()
    };

    let url = cli.url.clone();
    let partage = shared.clone();
    let intervalle = Duration::from_secs(cli.refresh_secs.max(1));

    eframe::run_native(
        "HomelabUS",
        options,
        Box::new(move |cc| {
            // Le contexte egui n'existe qu'ici : c'est lui qui permet au sondeur de
            // réveiller l'interface quand des données arrivent. Sans ça, l'écran ne
            // se redessine qu'au prochain mouvement de souris et paraît figé.
            let ctx = cc.egui_ctx.clone();
            client::spawn_poller(c, partage.clone(), intervalle, move || {
                ctx.request_repaint();
            });

            Ok(Box::new(app::Dashboard::new(partage, url, onglet)))
        }),
    )
}
