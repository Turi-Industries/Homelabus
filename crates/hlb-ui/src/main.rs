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

use hlb_ui::{client, route, shell};

use std::sync::Arc;

use clap::Parser;

#[derive(Parser)]
#[command(name = "hlb-ui", version, about = "Tableau de bord Homelabus")]
struct Cli {
    /// URL de l'API du controller.
    #[arg(long, default_value = "http://localhost:8420", env = "HLB_CONTROLLER_URL")]
    url: String,

    /// Jeton, si le controller en exige un.
    #[arg(long, env = "HLB_METRICS_TOKEN")]
    token: Option<String>,

    /// Largeur de la fenêtre, en points. Utile pour vérifier la disposition étroite.
    #[arg(long, default_value = "1100")]
    width: f32,

    /// Hauteur de la fenêtre, en points.
    #[arg(long, default_value = "700")]
    height: f32,

    /// Écran d'ouverture, sous la même forme que le fragment d'URL du web :
    /// `/`, `/apps`, `/a-faire`, `/journal`, `/secrets`, `/reglages`.
    ///
    /// Utile pour épingler l'écran qui t'intéresse — la liste des actions en attente,
    /// par exemple — sans avoir à cliquer à chaque lancement. La même valeur marche
    /// dans le navigateur, après un `#`.
    #[arg(long, default_value = "/")]
    route: String,

    /// Intervalle de rafraîchissement, en secondes.
    ///
    /// ⚠️ Descendre trop bas ne rend pas le tableau de bord plus juste : les données
    /// qu'il affiche (âge des sauvegardes, actions en attente) bougent à l'échelle de
    /// la minute. Ça ne fait qu'ajouter de la charge au controller.
    #[arg(long, default_value = "5")]
    refresh_secs: u64,

    /// Mode kiosque : rotation automatique des écrans, aucune interaction.
    ///
    /// 🔴 Pour un écran mural. Les écrans qui portent des secrets, des comptes, des
    /// jetons ou le journal d'audit en sont exclus par construction — un mur est
    /// visible par quiconque passe dans la pièce. Utilise un jeton `viewer` dédié.
    #[arg(long)]
    kiosque: bool,
}

fn main() -> eframe::Result<()> {
    let cli = Cli::parse();

    let route: route::Route = match cli.route.parse() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let kiosque = cli.kiosque;
    let shared = Arc::new(client::Shared::default());

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([cli.width, cli.height])
            // 320 pt : la largeur d'un téléphone ancien. En dessous, plus rien n'est
            // lisible, mais au-dessus la disposition étroite doit tenir.
            .with_min_inner_size([320.0, 300.0])
            // ⚠️ Le titre définitif vient de la marque, servie par le controller.
            // Celui-ci n'est visible que le temps du premier sondage.
            .with_title("Homelabus"),
        ..Default::default()
    };

    let partage = shared.clone();
    let poller = client::Poller::new(
        &cli.url,
        cli.token.clone(),
        cli.refresh_secs as f64,
        partage.clone(),
    );

    eframe::run_native(
        "Homelabus",
        options,
        Box::new(move |_cc| {
            let app = shell::Application::new(partage, poller, route);
            let app = if kiosque { app.en_kiosque() } else { app };
            Ok(Box::new(app))
        }),
    )
}
