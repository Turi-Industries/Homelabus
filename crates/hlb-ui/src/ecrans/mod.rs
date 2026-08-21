//! Les écrans, un module par écran.
//!
//! Chacun reçoit un `&mut Ui` déjà stylé par la coquille et n'a **rien** à savoir du
//! thème : il compose des briques de `crate::design::composants`. Un écran qui poserait
//! une couleur à la main serait le seul à ne pas changer avec le thème, et l'interface
//! aurait l'air cassée sans qu'on sache pourquoi.

pub mod a_faire;
pub mod action;
pub mod alertes;
pub mod app_detail;
pub mod annonces;
pub mod apps;
pub mod comptes;
pub mod inscription;
pub mod journal;
pub mod noeuds;
pub mod portail;
pub mod reglages;
pub mod sauvegardes;
pub mod secrets;
pub mod statut;
pub mod derive;
pub mod frise;
pub mod plans;
pub mod securite;
pub mod topologie;
pub mod tableau_bord;

use crate::client::{Ressources, Snapshot};
use crate::design::composants as c;
use crate::route::Route;

/// Ce qu'un écran a besoin de savoir.
///
/// Regroupé plutôt que passé en six arguments : ajouter une ressource ne doit pas
/// obliger à toucher la signature de chaque écran.
pub struct Contexte<'a> {
    pub data: &'a Snapshot,
    pub ressources: &'a Ressources,
    /// L'horloge d'egui, pour les âges et les sourdines.
    pub maintenant: f64,
    /// L'horloge murale, pour ce qui se compare à des horodatages du serveur.
    ///
    /// ⚠️ Distincte de la précédente : l'horloge d'egui compte depuis le démarrage de
    /// l'interface, pas depuis 1970. Les confondre daterait toutes les sourdines de
    /// 1970 et les afficherait comme expirées.
    pub epoch: i64,
    pub etroit: bool,
    /// De quoi relancer une requête hors du cycle normal.
    pub acces: &'a crate::client::Acces,
    /// Réveille la boucle de rendu quand une réponse arrive.
    pub reveil: std::sync::Arc<dyn Fn() + Send + Sync>,
    /// Le jeton d'invitation, s'il y en avait un dans l'URL.
    pub invitation: Option<&'a str>,
}

/// Rend un écran SANS aucune donnée, pour les tests de rendu (lot 12.1).
///
/// 🔴 C'est l'état réel au premier affichage — avant toute réponse du controller — et
/// celui qu'on voit quand le controller tombe. C'est aussi celui que personne ne
/// regarde en développant, parce qu'on a toujours le mode démonstration sous la main.
///
/// ⚠️ Passe par le dispatcher RÉEL : appeler les fonctions d'écran une par une laisserait
/// hors couverture un écran qu'on aurait oublié d'ajouter à la liste du test.
pub fn rendu_a_vide(ui: &mut egui::Ui, route: &Route) {
    let ressources = crate::client::Ressources::default();
    let acces = crate::client::Acces::new("http://127.0.0.1:1", None);
    let data = Snapshot::default();

    let ctx = Contexte {
        data: &data,
        ressources: &ressources,
        maintenant: 0.0,
        epoch: 0,
        etroit: ui.available_width() < 600.0,
        acces: &acces,
        reveil: std::sync::Arc::new(|| {}),
        invitation: None,
    };

    let _ = afficher(ui, route, &ctx);
}

/// Reconstruit la requête à appliquer, à partir de l'aperçu lui-même.
///
/// 🔴 Depuis l'APERÇU, jamais depuis un état gardé à côté : deux sources finiraient par
/// diverger, et l'on appliquerait une action différente de celle qu'on a lue. La
/// commande CLI, qui figure dans l'aperçu, porte tout ce qu'il faut.
fn rejouer(a: &hlb_api::ResultatAction) -> (&'static str, String, String) {
    let cli = &a.commande_cli;
    let mot = |n: usize| cli.split_whitespace().nth(n).unwrap_or("").to_string();

    // La confirmation vient du serveur, jamais fabriquée ici.
    let corps = match &a.confirmation_requise {
        Some(cible) => format!(r#"{{"confirme":"{cible}"}}"#),
        None => "{}".to_string(),
    };

    if cli.starts_with("hlb install") {
        return ("POST", format!("/api/apps/{}/install", mot(2)), corps);
    }
    if cli.starts_with("hlb backup run") {
        // « hlb backup run --app gitea --apply »
        let app = cli
            .split_whitespace()
            .skip_while(|m| *m != "--app")
            .nth(1)
            .unwrap_or("");
        return ("POST", format!("/api/apps/{app}/backup"), corps);
    }
    if cli.starts_with("hlb backup dest add") {
        return ("PUT", format!("/api/backup/destinations/{}", mot(4)), corps);
    }
    if cli.starts_with("hlb scale") {
        return (
            "POST",
            format!("/api/apps/{}/scale", mot(2)),
            format!(r#"{{"replicas":{}}}"#, mot(3)),
        );
    }
    if cli.starts_with("hlb remove") {
        return ("DELETE", format!("/api/apps/{}", mot(2)), corps);
    }
    if cli.starts_with("hlb guide verify") {
        return ("POST", format!("/api/todo/{}/{}", mot(3), mot(4)), corps);
    }
    if cli.starts_with("hlb user invite revoke") {
        return ("DELETE", format!("/api/invitations/{}", mot(4)), corps);
    }
    if cli.starts_with("hlb user invite") {
        return ("POST", "/api/invitations".to_string(), corps);
    }
    if cli.starts_with("hlb user role") {
        return (
            "POST",
            format!("/api/comptes/{}/role/{}", mot(3), mot(4)),
            corps,
        );
    }
    if cli.starts_with("hlb annonce publier") {
        // ⚠️ Le corps complet ne tient pas dans une commande CLI : c'est le seul cas où
        // l'aperçu ne suffit pas à rejouer. On garde donc la demande d'origine, que le
        // dispatcher relance telle quelle.
        return ("POST", "/api/annonces".to_string(), corps);
    }
    if cli.starts_with("hlb annonce suivre") {
        return ("POST", format!("/api/annonces/{}/suivi", mot(3)), corps);
    }
    if cli.starts_with("hlb annonce retirer") {
        return ("DELETE", format!("/api/annonces/{}", mot(3)), corps);
    }
    if cli.starts_with("hlb user add") {
        return ("POST", "/api/inscription".to_string(), corps);
    }
    // ⚠️ Aucun repli « au hasard » : une action qu'on ne sait pas rejouer ne doit pas
    // en déclencher une autre. La route inexistante rendra 404, ce qui est visible.
    ("POST", "/api/action-inconnue".to_string(), corps)
}

fn mesures_espace() -> f32 {
    crate::design::mesures::ESPACE
}

/// Dispatche vers l'écran de la route.
///
/// Rend la route demandée par l'écran, s'il y en a une — c'est ainsi qu'un onglet
/// d'app change l'URL sans que chaque écran ait besoin d'un accès mutable à la
/// navigation.
pub fn afficher(ui: &mut egui::Ui, route: &Route, ctx: &Contexte) -> Option<Route> {
    // ⚠️ Sauf l'inscription, qui intègre son propre affichage : le panneau générique
    // y montrerait un second aperçu par-dessus le formulaire.
    if !matches!(route, Route::Inscription) {
        if let Some(r) = panneau_global(ui, ctx) {
            return r;
        }
    }

    dispatcher(ui, route, ctx)
}

/// Le panneau d'action, commun à tous les écrans sauf l'inscription.
///
/// Rend `Some(_)` quand il a pris la main — auquel cas l'écran n'est pas affiché.
fn panneau_global(ui: &mut egui::Ui, ctx: &Contexte) -> Option<Option<Route>> {
    // 🔴 Le panneau d'action AVANT tout écran, et pour TOUS les écrans.
    //
    // Il vivait dans le détail d'app, si bien qu'un aperçu déclenché depuis l'écran des
    // comptes partait sans que rien ne s'affiche : le clic paraissait sans effet. Une
    // action est globale — un seul endroit la montre, quel que soit l'écran d'où elle
    // vient.
    if let Some(dec) = action::panneau(ui, &ctx.ressources.action) {
        ui.add_space(mesures_espace());
        match dec {
            action::Decision::Fermer => ctx.ressources.action.fermer(),
            action::Decision::Enregistrer(nom) => {
                if let Some(ap) = ctx.ressources.action.lire_apercu() {
                    // 🔴 On range le plan TEL QU'IL A ÉTÉ PRÉVISUALISÉ : la requête est
                    // reconstruite depuis l'aperçu, jamais depuis un état gardé à côté.
                    // Deux sources finiraient par diverger, et l'on exécuterait plus
                    // tard autre chose que ce qu'on vient de lire.
                    let (m, c, corps) = rejouer(&ap);
                    let payload = format!(
                        r#"{{"nom":{},"methode":{},"chemin":{},"corps":{},"resume":{}}}"#,
                        json_chaine(&nom),
                        json_chaine(m),
                        json_chaine(&c),
                        json_chaine(&corps),
                        json_chaine(&ap.resume)
                    );
                    let reveil = ctx.reveil.clone();
                    ctx.ressources.action.lancer(
                        ctx.acces,
                        "POST",
                        "/api/plans",
                        &payload,
                        true,
                        move || reveil(),
                    );
                }
            }
            action::Decision::Appliquer => {
                if let Some(ap) = ctx.ressources.action.lire_apercu() {
                    let reveil = ctx.reveil.clone();
                    let (m, c, corps) = rejouer(&ap);
                    ctx.ressources
                        .action
                        .lancer(ctx.acces, m, &c, &corps, true, move || reveil());
                    // Après une action, tout est périmé : le rafraîchir évite
                    // d'afficher l'ancien état comme s'il était à jour.
                    ctx.ressources.invalider_tout();
                }
            }
        }
        // ⚠️ On rend la main : afficher l'écran sous le panneau ferait défiler pour
        // retrouver le bouton qu'on vient de demander.
        return Some(None);
    }
    None
}

/// Une chaîne JSON correctement échappée.
///
/// 🔴 Le corps d'un plan contient du JSON (`{"domaine":"git.turi.fr"}`) qu'on imbrique
/// dans un autre JSON. Le coller tel quel produirait un document invalide, et le
/// serveur rendrait un 400 sans dire lequel des cinq champs est en cause.
fn json_chaine(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn dispatcher(ui: &mut egui::Ui, route: &Route, ctx: &Contexte) -> Option<Route> {
    let (data, etroit) = (ctx.data, ctx.etroit);
    match route {
        Route::TableauDeBord => tableau_bord::afficher(ui, data, etroit),
        Route::Apps => {
            if let Some(nom) = apps::afficher(ui, data, etroit) {
                return Some(Route::App {
                    nom,
                    onglet: crate::route::OngletApp::default(),
                });
            }
        }
        Route::AFaire => {
            let (sante, _) = ctx.ressources.sante.lire(ctx.maintenant);
            a_faire::afficher(ui, &data.todo, sante.as_ref(), etroit);
        }
        Route::Journal => journal::afficher(ui, &data.audit, etroit),
        Route::Secrets => {
            let (r, _) = ctx.ressources.rotation.lire(ctx.maintenant);
            secrets::afficher(ui, &data.secrets, r.as_ref());
        }
        Route::Reglages => {
            let (prefs, _) = ctx.ressources.preferences.lire(ctx.maintenant);
            if let Some(reglages::Demande::Theme(t)) = reglages::afficher(ui, prefs.as_ref()) {
                let corps = match &t {
                    Some(nom) => format!(r#"{{"theme":"{nom}"}}"#),
                    None => r#"{"theme":null}"#.to_string(),
                };
                let reveil = ctx.reveil.clone();
                // ⚠️ Pas d'aperçu : le changement est immédiat et réversible d'un clic.
                ctx.ressources.action.lancer(
                    ctx.acces,
                    "PUT",
                    "/api/preferences/theme",
                    &corps,
                    true,
                    move || reveil(),
                );
                // Le thème s'applique au tour suivant, quand la préférence est relue.
                ctx.ressources.preferences.invalider();
            }
        }
        Route::Noeuds => {
            let (n, f) = ctx.ressources.noeuds.lire(ctx.maintenant);
            noeuds::afficher(ui, n.as_ref(), &f, etroit);
        }
        Route::Alertes => {
            let (a, f) = ctx.ressources.alertes.lire(ctx.maintenant);
            alertes::afficher(ui, a.as_ref(), &f, ctx.epoch);
        }
        Route::Inscription => {
            let action = &ctx.ressources.action;
            let apercu = action.lire_apercu();
            let resultat = action.lire_resultat();
            // ⚠️ Le lien d'enrôlement ne vit que dans la réponse : il n'est ni stocké
            // ni réaffichable, et c'est voulu.
            let lien = action.lire_lien();

            if let Some(d) = inscription::afficher(
                ui,
                ctx.invitation,
                apercu.as_ref(),
                resultat.as_ref(),
                lien.as_deref(),
                action.occupee(),
            ) {
                let (nom, applique) = match d {
                    inscription::Demande::Verifier { nom } => (nom, false),
                    inscription::Demande::Creer { nom } => (nom, true),
                };
                let corps = format!(
                    r#"{{"invitation":"{}","nom":"{nom}"}}"#,
                    ctx.invitation.unwrap_or_default()
                );
                let reveil = ctx.reveil.clone();
                if !applique {
                    // Un nouvel aperçu remplace le précédent : garder l'ancien
                    // afficherait « disponible » pour un nom qu'on vient de changer.
                    action.fermer();
                }
                action.lancer(
                    ctx.acces,
                    "POST",
                    "/api/inscription",
                    &corps,
                    applique,
                    move || reveil(),
                );
            }
            // 🔴 On rend la main : le panneau d'action générique afficherait un second
            // aperçu par-dessus celui que cet écran intègre déjà.
            return None;
        }
        Route::Statut => {
            let (v, f) = ctx.ressources.statut.lire(ctx.maintenant);
            statut::afficher(ui, v.as_ref(), &f);
        }
        Route::Annonces => {
            let (v, f) = ctx.ressources.annonces.lire(ctx.maintenant);
            if let Some(d) = annonces::afficher(ui, v.as_ref(), &f) {
                let reveil = ctx.reveil.clone();
                let (methode, chemin, corps) = match d {
                    annonces::Demande::Publier {
                        titre,
                        corps,
                        niveau,
                        audience,
                        epinglee,
                    } => (
                        "POST",
                        "/api/annonces".to_string(),
                        serde_json::json!({
                            "titre": titre,
                            "corps": corps,
                            "niveau": niveau,
                            "audience": audience,
                            "epinglee": epinglee,
                        })
                        .to_string(),
                    ),
                    annonces::Demande::Suivre { id, corps } => (
                        "POST",
                        format!("/api/annonces/{id}/suivi"),
                        serde_json::json!({ "corps": corps }).to_string(),
                    ),
                    annonces::Demande::Retirer(id) => {
                        ("DELETE", format!("/api/annonces/{id}"), "{}".to_string())
                    }
                };
                ctx.ressources.action.fermer();
                ctx.ressources
                    .action
                    .lancer(ctx.acces, methode, &chemin, &corps, false, move || reveil());
            }
        }
        Route::Portail => {
            let (v, f) = ctx.ressources.portail.lire(ctx.maintenant);
            portail::afficher(ui, v.as_ref(), &f, etroit);
        }
        Route::Comptes => {
            let (cp, f) = ctx.ressources.comptes.lire(ctx.maintenant);
            let (inv, _) = ctx.ressources.invitations.lire(ctx.maintenant);
            if let Some(d) = comptes::afficher(ui, cp.as_ref(), inv.as_ref(), &f, etroit) {
                let reveil = ctx.reveil.clone();
                let (methode, chemin, corps) = match d {
                    comptes::Demande::Inviter {
                        duree_s,
                        usages,
                        role,
                    } => (
                        "POST",
                        "/api/invitations".to_string(),
                        format!(
                            r#"{{"profil":"standard","role":"{role}","duree_s":{duree_s},"usages_max":{usages}}}"#
                        ),
                    ),
                    comptes::Demande::Revoquer(r) => {
                        ("DELETE", format!("/api/invitations/{r}"), "{}".to_string())
                    }
                    comptes::Demande::Role(compte, role) => (
                        "POST",
                        format!("/api/comptes/{compte}/role/{role}"),
                        "{}".to_string(),
                    ),
                };
                // Un aperçu d'abord, comme partout : c'est le panneau qui propose
                // ensuite d'appliquer, une fois le plan lu.
                ctx.ressources.action.fermer();
                ctx.ressources
                    .action
                    .lancer(ctx.acces, methode, &chemin, &corps, false, move || reveil());
            }
        }
        Route::Topologie => {
            let (t, f) = ctx.ressources.topologie.lire(ctx.maintenant);
            topologie::afficher(ui, t.as_ref(), &f, etroit);
        }
        Route::Securite => {
            let (e, f) = ctx.ressources.exposition.lire(ctx.maintenant);
            let (sec, _) = ctx.ressources.secours.lire(ctx.maintenant);
            if let Some(securite::Demande::Attester(id)) =
                securite::afficher(ui, e.as_ref(), sec.as_ref(), &f)
            {
                let reveil = ctx.reveil.clone();
                // ⚠️ Pas d'aperçu : attester est une déclaration, réversible et sans
                // effet sur l'infrastructure.
                ctx.ressources.action.lancer(
                    ctx.acces,
                    "POST",
                    &format!("/api/secours/{id}"),
                    "",
                    true,
                    move || reveil(),
                );
                ctx.ressources.secours.invalider();
            }
        }
        Route::Chronologie => {
            let (e, f) = ctx.ressources.frise.lire(ctx.maintenant);
            frise::afficher(ui, e.as_ref(), ctx.epoch, &f);
        }
        Route::Plans => {
            let (pl, f) = ctx.ressources.plans.lire(ctx.maintenant);
            if let Some(plans::Demande::Rejouer(p)) = plans::afficher(ui, pl.as_ref(), &f) {
                let reveil = ctx.reveil.clone();
                // ⚠️ L'APERÇU, jamais l'exécution : le plan a pu être écrit pour un
                // cluster qui a changé, et c'est le nouvel aperçu qui le dira.
                ctx.ressources.action.lancer(
                    ctx.acces,
                    &p.methode,
                    &p.chemin,
                    "",
                    false,
                    move || reveil(),
                );
            }
        }
        Route::Derive => {
            let (e, f) = ctx.ressources.ecarts.lire(ctx.maintenant);
            derive::afficher(ui, e.as_ref(), &f);
        }
        Route::Sauvegardes => {
            let (cv, f) = ctx.ressources.couverture.lire(ctx.maintenant);
            let (h, _) = ctx.ressources.sauvegardes.lire(ctx.maintenant);
            sauvegardes::afficher(ui, cv.as_ref(), h.as_ref(), &f, etroit);
        }
        Route::App { nom, onglet } => {
            let reveil = ctx.reveil.clone();
            let (d, f) = ctx.ressources.detail_app(
                nom,
                ctx.acces,
                ctx.maintenant,
                move || reveil(),
            );
            let reveil2 = ctx.reveil.clone();
            let versions =
                ctx.ressources
                    .versions_app(nom, ctx.acces, ctx.maintenant, move || reveil2());
            match app_detail::afficher(
                ui,
                nom,
                *onglet,
                app_detail::Vue {
                    detail: d.as_ref(),
                    fraicheur: &f,
                    action: &ctx.ressources.action,
                    versions: versions.as_ref(),
                    etroit,
                },
            ) {
                Some(app_detail::Demande::Onglet(o)) => {
                    return Some(Route::App {
                        nom: nom.clone(),
                        onglet: o,
                    })
                }
                Some(app_detail::Demande::Action {
                    methode,
                    chemin,
                    corps,
                    applique,
                }) => {
                    // Un nouvel aperçu remplace le précédent : garder l'ancien
                    // afficherait le plan d'une autre action que celle demandée.
                    if !applique {
                        ctx.ressources.action.fermer();
                    }
                    let reveil = ctx.reveil.clone();
                    ctx.ressources.action.lancer(
                        ctx.acces,
                        methode,
                        &chemin,
                        &corps,
                        applique,
                        move || reveil(),
                    );
                    // ⚠️ Après une action appliquée, le détail est périmé : le
                    // rafraîchir tout de suite évite d'afficher l'ancien état comme
                    // s'il était à jour.
                    if applique {
                        ctx.ressources.invalider_tout();
                    }
                }
                Some(app_detail::Demande::Fermer) => ctx.ressources.action.fermer(),
                None => {}
            }
        }
        // 🔴 Le cas ne devrait pas se produire : la navigation ne propose que les
        // écrans écrits. S'il se produit — un lien collé vers un écran non encore
        // livré — on le DIT, plutôt que d'afficher une page blanche qu'on prendrait
        // pour une panne.
        autre => {
            c::titre(ui, autre.libelle());
            c::etat_vide(
                ui,
                "Cet écran n'est pas encore écrit. Le lien est valide, l'écran viendra.",
                None,
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apercu(cli: &str, confirme: Option<&str>) -> hlb_api::ResultatAction {
        hlb_api::ResultatAction {
            applique: false,
            resume: "x".into(),
            etapes: Vec::new(),
            commande_cli: cli.into(),
            blocages: Vec::new(),
            avertissements: Vec::new(),
            confirmation_requise: confirme.map(str::to_string),
        }
    }

    #[test]
    fn every_action_can_be_replayed_from_its_own_preview() {
        // 🔴 Reconstruire depuis l'aperçu, et non depuis un état gardé à côté : deux
        // sources finiraient par diverger, et l'on appliquerait une action différente
        // de celle qu'on vient de lire à l'écran.
        let cas: &[(&str, &str, &str)] = &[
            ("hlb install gitea --domain g.fr --apply", "POST", "/api/apps/gitea/install"),
            ("hlb backup run --app immich --apply", "POST", "/api/apps/immich/backup"),
            ("hlb scale gitea 3 --apply", "POST", "/api/apps/gitea/scale"),
            ("hlb remove vikunja --apply", "DELETE", "/api/apps/vikunja"),
            ("hlb guide verify gitea premier-admin", "POST", "/api/todo/gitea/premier-admin"),
            (
                "hlb backup dest add nas --location /mnt --classes critique --apply",
                "PUT",
                "/api/backup/destinations/nas",
            ),
            ("hlb user invite --profil standard --role viewer --apply", "POST", "/api/invitations"),
            ("hlb user invite revoke a1b2c3d4 --apply", "DELETE", "/api/invitations/a1b2c3d4"),
            ("hlb user role camille operator --apply", "POST", "/api/comptes/camille/role/operator"),
        ];

        for (cli, methode, chemin) in cas {
            let (m, c, _) = rejouer(&apercu(cli, None));
            assert_eq!(m, *methode, "méthode pour « {cli} »");
            assert_eq!(c, *chemin, "chemin pour « {cli} »");
        }
    }

    #[test]
    fn scaling_carries_the_number_from_the_preview() {
        // Le nombre affiché et le nombre appliqué doivent être le même : les séparer
        // ferait redimensionner à une valeur qu'on n'a pas vue.
        let (_, _, corps) = rejouer(&apercu("hlb scale gitea 3 --apply", None));
        assert_eq!(corps, r#"{"replicas":3}"#);
    }

    #[test]
    fn the_confirmation_comes_from_the_server_not_the_interface() {
        // 🔴 C'est le serveur qui dit quelle cible doit être confirmée ; l'interface se
        // contente de la répéter après que l'utilisateur a lu ce que ça détruit.
        let (_, _, corps) = rejouer(&apercu("hlb remove vikunja --apply", Some("vikunja")));
        assert_eq!(corps, r#"{"confirme":"vikunja"}"#);
    }

    #[test]
    fn an_unknown_action_never_falls_back_onto_another_one() {
        // ⚠️ Un repli « au hasard » déclencherait une action différente de celle
        // demandée. Une route inexistante rend 404, ce qui se voit.
        let (_, chemin, _) = rejouer(&apercu("hlb quelque-chose-de-nouveau --apply", None));
        assert!(chemin.contains("inconnue"), "{chemin}");
    }

    #[test]
    fn invite_and_invite_revoke_are_not_confused() {
        // Les deux commencent par « hlb user invite » : l'ordre des tests compte, et
        // une inversion révoquerait au lieu d'inviter.
        let (m1, c1, _) = rejouer(&apercu("hlb user invite revoke abcd1234 --apply", None));
        assert_eq!((m1, c1.as_str()), ("DELETE", "/api/invitations/abcd1234"));

        let (m2, c2, _) = rejouer(&apercu("hlb user invite --role viewer --apply", None));
        assert_eq!((m2, c2.as_str()), ("POST", "/api/invitations"));
    }
}
