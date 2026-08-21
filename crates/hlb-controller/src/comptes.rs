//! Les comptes humains, les invitations et l'inscription (lot 6).
//!
//! ## 🔴 Un compte à moitié créé paraît fonctionnel
//!
//! C'est le piège central de ce module. Créer un compte, c'est trois opérations sur
//! trois systèmes : une identité PocketID, une boîte Stalwart, une ligne en base. Si la
//! deuxième échoue, la personne se connecte partout et son adresse ne reçoit rien —
//! découvert au premier courriel perdu, souvent une réinitialisation de mot de passe.
//!
//! D'où : l'état est **nommé** (`Coherence`), la création est **reprenable**, et
//! l'écran de gestion montre les moitiés en rouge.
//!
//! ## Et l'invitation ne laisse pas choisir son rôle
//!
//! Le profil et le rôle sont fixés **à l'invitation**, pas par l'invité. Sinon
//! n'importe qui s'inscrirait administrateur.

use std::sync::Arc;

use axum::extract::{Path, Query, State as AxumState};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use hlb_api::{EtapeAction, EtatEtape, ResultatAction};

use crate::actions::ActionQuery;
use crate::api::AppState;
use crate::auth::{Autorise, PeutGererComptes, PeutLire};

/// Durée de vie par défaut d'une invitation : sept jours.
///
/// ⚠️ Paramétrable, contrairement au `"12h"` codé en dur du lien PocketID : sept jours
/// laissent le temps de transmettre le lien et d'attendre que la personne s'en occupe,
/// sans qu'il traîne indéfiniment dans une conversation.
pub const DUREE_INVITATION_S: i64 = 7 * 86_400;

/// Au-delà, le nombre d'usages est signalé dans l'aperçu.
///
/// 🔴 Pas un refus — inviter une équipe de dix est légitime. Mais un lien à dix entrées
/// qui fuite fait entrer dix personnes, et ça doit être lu avant d'être créé.
pub const USAGES_A_SIGNALER: i64 = 3;

/// La liste des comptes, avec leur état de cohérence.
pub async fn liste(
    _auth: Autorise<PeutGererComptes>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::CompteSummary>> {
    Json(resumes(&s).await)
}

/// Les comptes, tels que l'API les présente.
///
/// ⚠️ Extrait du gestionnaire parce que l'export CSV en a besoin lui aussi : deux
/// assemblages du même compte finiraient par afficher un état de cohérence à l'écran et
/// un autre dans le fichier qu'on donne à quelqu'un.
pub async fn resumes(s: &AppState) -> Vec<hlb_api::CompteSummary> {
    let maintenant = crate::auth::maintenant();
    let roles = s.state.users_with_roles().await.unwrap_or_default();

    let mut out = Vec::new();
    for (nom, role, _, _) in roles {
        let Ok(compte) = s.state.compte(&nom).await else {
            continue;
        };

        let coherence = match compte.coherence() {
            hlb_users::Coherence::Complet => hlb_api::EtatCompte::Complet,
            hlb_users::Coherence::SansBoite => hlb_api::EtatCompte::SansBoite,
            hlb_users::Coherence::SansIdentite => hlb_api::EtatCompte::SansIdentite,
            hlb_users::Coherence::Vide => hlb_api::EtatCompte::Vide,
        };

        let usage = compte.usage(maintenant);
        out.push(hlb_api::CompteSummary {
            explication: compte.coherence().describe().to_string(),
            coherence,
            nom: nom.clone(),
            profil: compte.profil.clone(),
            role: role.as_str().to_string(),
            pocket_id: compte.pocket_id.clone(),
            boites: compte
                .boites
                .iter()
                .map(|b| hlb_api::BoiteBreve {
                    adresse: b.adresse(),
                    par_defaut: b.par_defaut,
                })
                .collect(),
            aliases_actifs: (usage.aliases_permanents + usage.aliases_temporaires) as usize,
            // 🔴 Les aliases expirés qui reçoivent ENCORE : la purge n'a pas tourné, et
            // l'adresse qu'on croit fermée reste ouverte. C'est le seul état qui trahit
            // une promesse faite à l'utilisateur.
            promesses_rompues: compte.promesses_rompues(maintenant).len(),
            sessions: s
                .state
                .sessions_of(&nom, maintenant)
                .await
                .map(|v| v.len())
                .unwrap_or(0),
        });
    }

    // Les comptes cassés d'abord : sur vingt comptes, une moitié créée se perdrait au
    // milieu d'un tri alphabétique.
    out.sort_by(|a, b| {
        b.coherence
            .attention()
            .cmp(&a.coherence.attention())
            .then_with(|| a.nom.cmp(&b.nom))
    });
    out
}

/// Les invitations en cours.
pub async fn invitations(
    _auth: Autorise<PeutGererComptes>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::InvitationSummary>> {
    Json(
        s.state
            .invitations(crate::auth::maintenant())
            .await
            .unwrap_or_default(),
    )
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct DemandeInvitation {
    #[serde(default)]
    pub profil: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    /// Durée de vie en secondes.
    #[serde(default)]
    pub duree_s: Option<i64>,
    /// Combien de personnes peuvent s'en servir. **1 par défaut**, le cas sûr.
    #[serde(default)]
    pub usages_max: Option<i64>,
}

/// La réponse à la création d'une invitation.
///
/// 🔴 Le seul endroit du système où la valeur d'un lien d'invitation apparaît. Elle
/// n'est pas stockée, pas journalisée, et ne sera jamais réaffichable.
#[derive(Debug, serde::Serialize)]
pub struct InvitationCreee {
    /// ⚠️ APLATI : toutes les routes d'action rendent la même forme, avec `applique`,
    /// `etapes` et `blocages` à la RACINE. Un enveloppement particulier obligerait
    /// l'interface à traiter deux formats — et le test qui vérifie l'aperçu par défaut
    /// ne verrait pas cette route.
    #[serde(flatten)]
    pub resultat: ResultatAction,
    /// Le lien complet, affiché **une seule fois**.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lien: Option<String>,
}

/// Crée une invitation.
pub async fn creer_invitation(
    auth: Autorise<PeutGererComptes>,
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<ActionQuery>,
    corps: Option<Json<DemandeInvitation>>,
) -> Response {
    let d = corps.map(|Json(d)| d).unwrap_or_default();
    let mut blocages = Vec::new();

    let profil = d.profil.clone().unwrap_or_else(|| "standard".into());
    if hlb_users::Profil::par_nom(&profil).is_none() {
        blocages.push(format!(
            "profil « {profil} » inconnu — attendu « standard », « invite » ou « illimite »"
        ));
    }

    let role_texte = d.role.clone().unwrap_or_else(|| "utilisateur".into());
    let Some(role) = hlb_types::Role::parse(&role_texte) else {
        blocages.push(format!("rôle « {role_texte} » inconnu"));
        return rendre(
            &s,
            auth.identite(),
            "invitation",
            "-",
            ResultatAction {
                applique: false,
                resume: "créer une invitation".into(),
                etapes: Vec::new(),
                commande_cli: "hlb user invite --role utilisateur --apply".into(),
                blocages,
                avertissements: Vec::new(),
                confirmation_requise: None,
            },
            None,
        )
        .await;
    };

    // 🔴 Ces deux-là AVERTISSENT, ils n'empêchent pas. Inviter un second administrateur
    // ou une équipe de cinq sont des choix légitimes ; les ranger parmi les blocages
    // les rendrait impossibles.
    let mut avertissements = Vec::new();
    if role == hlb_types::Role::Admin {
        avertissements.push(
            "cette invitation donnera le rôle ADMIN : la personne pourra accorder des \
             rôles et détruire des données"
                .to_string(),
        );
    }

    // ⚠️ Bornée des DEUX côtés. Une heure au minimum : en dessous, le lien expire
    // avant d'avoir été lu. Trente jours au maximum : un lien qui traîne un trimestre
    // est une porte d'entrée qu'on a oubliée.
    let duree = d.duree_s.unwrap_or(DUREE_INVITATION_S).clamp(3_600, 30 * 86_400);

    // 🔴 Le nombre d'usages, borné lui aussi. Au-delà de cinquante, ce n'est plus une
    // invitation, c'est une inscription ouverte — et ça se décide autrement que par un
    // champ numérique.
    let usages = d.usages_max.unwrap_or(1).clamp(1, 50);
    if usages > USAGES_A_SIGNALER {
        avertissements.push(format!(
            "ce lien laissera entrer {} : s'il fuite, ce sont autant de comptes créés",
            hlb_api::pluriel(usages as u64, "personne", "personnes")
        ));
    }

    let applique = q.apply && blocages.is_empty();

    let mut etape = EtapeAction {
        description: format!(
            "créer une invitation « {profil} » / « {} », valable {}, pour {}",
            role.as_str(),
            hlb_api::humanise(duree),
            hlb_api::pluriel(usages as u64, "personne", "personnes")
        ),
        etat: EtatEtape::Prevue,
        erreur: None,
    };

    let mut lien = None;
    if applique {
        let mut brut = [0u8; 32];
        hlb_secrets::fill_random(&mut brut);
        let valeur = hlb_types::token::base32(&brut);

        match s
            .state
            .creer_invitation(
                &valeur,
                auth.acteur().nom(),
                &profil,
                role,
                None,
                crate::auth::maintenant(),
                duree,
                usages,
                d.note.as_deref(),
            )
            .await
        {
            Ok(()) => {
                etape.etat = EtatEtape::Faite;
                // 🔴 Le FRAGMENT, jamais la chaîne de requête : un `?invitation=` part
                // dans les journaux d'accès, les en-têtes `Referer` et tout proxy sur
                // le chemin. Le fragment reste dans le navigateur.
                lien = Some(format!("/#invitation={valeur}"));
            }
            Err(e) => {
                etape.etat = EtatEtape::Echouee;
                etape.erreur = Some(e.to_string());
            }
        }
    }

    let r = ResultatAction {
        applique,
        resume: "créer une invitation".into(),
        etapes: vec![etape],
        commande_cli: format!(
            "hlb user invite --profil {profil} --role {} --usages {usages} --apply",
            role.as_str()
        ),
        blocages,
        avertissements,
        confirmation_requise: None,
    };

    rendre(&s, auth.identite(), "invitation", "-", r, lien).await
}

/// Révoque une invitation en attente.
pub async fn revoquer_invitation(
    auth: Autorise<PeutGererComptes>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(reference): Path<String>,
    Query(q): Query<ActionQuery>,
) -> Response {
    let applique = q.apply;
    let mut etape = EtapeAction {
        description: format!("révoquer l'invitation « {reference} »"),
        etat: EtatEtape::Prevue,
        erreur: None,
    };
    let mut blocages = Vec::new();

    if applique {
        match s.state.revoquer_invitation(&reference).await {
            Ok(true) => etape.etat = EtatEtape::Faite,
            Ok(false) => {
                etape.etat = EtatEtape::Echouee;
                // ⚠️ Une invitation UTILISÉE ne s'efface pas : la supprimer effacerait
                // la trace de qui a créé quel compte.
                etape.erreur = Some(
                    "aucune invitation en attente sous cette référence — une invitation \
                     déjà utilisée reste au registre, c'est l'historique"
                        .into(),
                );
            }
            Err(e) => {
                etape.etat = EtatEtape::Echouee;
                etape.erreur = Some(e.to_string());
            }
        }
    } else {
        blocages.clear();
    }

    let r = ResultatAction {
        applique,
        resume: format!("révoquer l'invitation « {reference} »"),
        etapes: vec![etape],
        commande_cli: format!("hlb user invite revoke {reference} --apply"),
        blocages,
        avertissements: Vec::new(),
        confirmation_requise: None,
    };

    rendre(&s, auth.identite(), "invitation-revoke", &reference, r, None).await
}

/// Change le rôle d'une personne.
pub async fn changer_role(
    auth: Autorise<PeutGererComptes>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path((compte, role_texte)): Path<(String, String)>,
    Query(q): Query<ActionQuery>,
) -> Response {
    let mut blocages = Vec::new();

    let Some(role) = hlb_types::Role::parse(&role_texte) else {
        blocages.push(format!(
            "rôle « {role_texte} » inconnu — {}",
            hlb_types::Role::tous()
                .iter()
                .map(|r| r.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        return rendre(
            &s,
            auth.identite(),
            "user-role",
            &compte,
            ResultatAction {
                applique: false,
                resume: format!("changer le rôle de {compte}"),
                etapes: Vec::new(),
                commande_cli: format!("hlb user role {compte} <rôle> --apply"),
                blocages,
                avertissements: Vec::new(),
                confirmation_requise: None,
            },
            None,
        )
        .await;
    };

    let actuel = s.state.user_role(&compte).await.unwrap_or_default();

    // 🔴 Rétrograder le dernier administrateur laisserait un système où plus personne
    // ne peut accorder de droits : il ne se réparerait qu'en éditant SQLite à la main.
    if actuel == hlb_types::Role::Admin
        && role != hlb_types::Role::Admin
        && !s.state.has_other_admin(&compte).await.unwrap_or(true)
    {
        blocages.push(format!(
            "{compte} est le SEUL administrateur — nomme quelqu'un d'autre d'abord, \
             sinon plus personne ne pourra accorder de droits"
        ));
    }

    let applique = q.apply && blocages.is_empty();
    let mut etape = EtapeAction {
        description: format!(
            "{compte} : « {} » vers « {} »{}",
            actuel.as_str(),
            role.as_str(),
            if role > actuel {
                " (ÉLÉVATION de privilège)"
            } else {
                ""
            }
        ),
        etat: EtatEtape::Prevue,
        erreur: None,
    };

    if applique {
        match s
            .state
            .set_user_role(&compte, role, Some(auth.acteur().nom()))
            .await
        {
            Ok(()) => etape.etat = EtatEtape::Faite,
            Err(e) => {
                etape.etat = EtatEtape::Echouee;
                etape.erreur = Some(e.to_string());
            }
        }
    }

    let r = ResultatAction {
        applique,
        resume: format!("{compte} : rôle « {} »", role.as_str()),
        etapes: vec![etape],
        commande_cli: format!("hlb user role {compte} {} --apply", role.as_str()),
        blocages,
        avertissements: Vec::new(),
        confirmation_requise: None,
    };

    rendre(&s, auth.identite(), "user-role", &compte, r, None).await
}

// ---------------------------------------------------------------------------
// Inscription libre-service (lot 6.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, serde::Deserialize)]
pub struct DemandeInscription {
    /// Le jeton d'invitation, tel qu'il arrive du fragment d'URL.
    #[serde(default)]
    pub invitation: String,
    /// Le nom de compte souhaité.
    #[serde(default)]
    pub nom: String,
    #[serde(default)]
    pub nom_affiche: Option<String>,
}

/// Ce que rend une inscription réussie.
#[derive(Debug, serde::Serialize)]
pub struct Inscrit {
    #[serde(flatten)]
    pub resultat: ResultatAction,
    /// 🔴 Le lien d'enrôlement PocketID, à usage unique et affiché UNE fois.
    ///
    /// PocketID n'a pas de mot de passe : on ne transmet donc pas un secret initial
    /// mais ce jeton, qui sert à enregistrer une clé d'accès. Il n'est ni stocké ni
    /// journalisé.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lien_enrolement: Option<String>,
}

/// Crée un compte à partir d'une invitation.
///
/// ## 🔴 L'ordre des trois opérations, et pourquoi il compte
///
/// 1. **Consommer l'invitation** — d'abord, et dans une transaction : deux inscriptions
///    simultanées avec le même lien ne doivent pas passer toutes les deux.
/// 2. **Créer le compte en base** — c'est ce qui rend l'état visible même si la suite
///    échoue.
/// 3. **Identité PocketID, puis boîte** — chacune peut échouer, et chaque échec laisse
///    un état NOMMÉ (`SansIdentite`, `SansBoite`) que l'écran de gestion montre en
///    rouge, et qu'une relance répare.
///
/// L'inverse — tout créer ailleurs avant d'enregistrer — laisserait des identités
/// orphelines dont Homelabus ignorerait l'existence.
///
/// ⚠️ **Sans authentification** : c'est la personne invitée qui appelle, et elle n'a
/// pas encore de compte. L'invitation EST l'autorisation.
pub async fn inscrire(
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<ActionQuery>,
    corps: Option<Json<DemandeInscription>>,
) -> Response {
    let d = corps.map(|Json(d)| d).unwrap_or_default();
    let maintenant = crate::auth::maintenant();
    let mut blocages = Vec::new();

    // Le nom devient à la fois la partie locale de l'adresse ET l'identifiant PocketID.
    if let Err(e) = hlb_users::valider_nom(&d.nom) {
        blocages.push(e.to_string());
    }

    if s
        .state
        .users()
        .await
        .unwrap_or_default()
        .iter()
        .any(|(n, _, _)| n == &d.nom)
    {
        blocages.push(format!("le nom « {} » est déjà pris", d.nom));
    }

    // ⚠️ On ne CONSOMME pas l'invitation en aperçu : il faut pouvoir vérifier son nom
    // sans brûler le lien. La validité est vérifiée sans effet de bord.
    let apercu_seul = !q.apply;

    if apercu_seul {
        let r = ResultatAction {
            applique: false,
            resume: format!("créer le compte « {} »", d.nom),
            etapes: vec![
                etape("créer l'identité PocketID"),
                etape("ouvrir la boîte mail"),
                etape("enregistrer le compte"),
            ],
            commande_cli: format!("hlb user add {} --apply", d.nom),
            blocages,
            avertissements: Vec::new(),
            confirmation_requise: None,
        };
        return (
            StatusCode::OK,
            Json(Inscrit {
                resultat: r,
                lien_enrolement: None,
            }),
        )
            .into_response();
    }

    if !blocages.is_empty() {
        return refus_inscription(&s, &d.nom, blocages).await;
    }

    // 1. L'invitation, consommée AVANT tout : usage unique garanti par la transaction.
    let Ok(Some((profil, role, _domaine))) = s
        .state
        .consommer_invitation(&d.invitation, &d.nom, maintenant)
        .await
    else {
        // Inconnue, expirée ou déjà utilisée : indistinct à dessein.
        return refus_inscription(
            &s,
            &d.nom,
            vec![
                "invitation invalide, expirée ou déjà utilisée — demande un nouveau lien"
                    .to_string(),
            ],
        )
        .await;
    };

    let mut etapes = Vec::new();

    // 2. Le compte en base, tout de suite : c'est ce qui rend l'état visible même si la
    // suite échoue.
    let mut e = etape("enregistrer le compte");
    match s.state.upsert_user(&d.nom, &profil, None).await {
        Ok(()) => e.etat = EtatEtape::Faite,
        Err(err) => {
            e.etat = EtatEtape::Echouee;
            e.erreur = Some(err.to_string());
            etapes.push(e);
            return terminer_inscription(&s, &d.nom, etapes, None).await;
        }
    }
    etapes.push(e);
    let _ = s.state.set_user_role(&d.nom, role, Some("invitation")).await;

    // 3. L'identité PocketID.
    //
    // ⚠️ Elle vient AVANT la boîte : une identité sans boîte laisse la personne se
    // connecter et ne rien recevoir ; une boîte sans identité laisse du courrier que
    // personne ne peut lire. Le premier état est le moins mauvais des deux — on peut
    // au moins joindre la personne autrement.
    let mut e = etape("créer l'identité PocketID");
    let mut lien_enrolement = None;

    match &s.identite {
        Some(pid) => {
            let affiche = d.nom_affiche.clone().unwrap_or_else(|| d.nom.clone());
            let adresse = format!("{}@{}", d.nom, s.domaine_mail);
            match pid.create_user(&d.nom, Some(&adresse), &affiche, &[]).await {
                Ok(u) => {
                    e.etat = EtatEtape::Faite;
                    let _ = s.state.upsert_user_pocket_id(&d.nom, &u.id).await;

                    // 🔴 PocketID n'a PAS de mot de passe : authentification par clé
                    // d'accès. On ne transmet donc pas un secret initial mais un jeton
                    // à usage unique, affiché une fois et jamais enregistré.
                    match pid.one_time_token(&u.id, "12h").await {
                        Ok(jeton) => {
                            lien_enrolement = Some(format!("{}/lc/{jeton}", pid.issuer()))
                        }
                        Err(err) => {
                            // Le compte existe mais personne ne peut s'y connecter :
                            // ce n'est pas un échec de création, c'est un lien à
                            // refaire. On le dit sans marquer l'étape en échec.
                            e.erreur = Some(format!(
                                "identité créée, mais le lien d'enrôlement a échoué \
                                 ({err}) — refais-en un avec « hlb user link {} »",
                                d.nom
                            ));
                        }
                    }
                }
                Err(err) => {
                    e.etat = EtatEtape::Echouee;
                    e.erreur = Some(err.to_string());
                }
            }
        }
        None => {
            e.etat = EtatEtape::NonImplementee;
            e.erreur = Some(
                "PocketID non configuré sur ce controller — termine avec « hlb user add \
                 <nom> --apply », qui reprend là où c'est arrêté"
                    .into(),
            );
        }
    }
    etapes.push(e);

    // 4. La boîte mail.
    let mut e = etape("ouvrir la boîte mail");
    match &s.mail {
        Some(mail) => {
            let adresse = format!("{}@{}", d.nom, s.domaine_mail);
            // Le mot de passe IMAP/SMTP est généré et n'est PAS rendu : la personne se
            // sert du webmail, qui passe par le SSO. Un mot de passe affiché serait un
            // secret de plus à transmettre, pour un usage que presque personne n'a.
            let motdepasse =
                hlb_secrets::generate_password(hlb_secrets::DEFAULT_PASSWORD_LEN);
            match mail.ensure_account(&adresse, &motdepasse, &[]).await {
                Ok(_) => {
                    e.etat = EtatEtape::Faite;
                    let _ = s
                        .state
                        .add_mailbox(&d.nom, &d.nom, &s.domaine_mail, true)
                        .await;
                }
                Err(err) => {
                    e.etat = EtatEtape::Echouee;
                    e.erreur = Some(err.to_string());
                }
            }
        }
        None => {
            e.etat = EtatEtape::NonImplementee;
            e.erreur = Some(
                "Stalwart non configuré sur ce controller — la boîte n'existe pas, et \
                 l'adresse ne recevra rien"
                    .into(),
            );
        }
    }
    etapes.push(e);

    terminer_inscription(&s, &d.nom, etapes, lien_enrolement).await
}

fn etape(quoi: &str) -> EtapeAction {
    EtapeAction {
        description: quoi.to_string(),
        etat: EtatEtape::Prevue,
        erreur: None,
    }
}

async fn refus_inscription(s: &AppState, nom: &str, blocages: Vec<String>) -> Response {
    let r = ResultatAction {
        applique: false,
        resume: format!("créer le compte « {nom} »"),
        etapes: Vec::new(),
        commande_cli: format!("hlb user add {nom} --apply"),
        blocages,
        avertissements: Vec::new(),
        confirmation_requise: None,
    };
    let _ = s
        .state
        .audit(
            "inscription",
            hlb_types::Role::Utilisateur,
            "inscription",
            nom,
            "refused",
            Some(&r.blocages.join(" · ")),
        )
        .await;
    (StatusCode::UNPROCESSABLE_ENTITY, Json(Inscrit { resultat: r, lien_enrolement: None }))
        .into_response()
}

async fn terminer_inscription(
    s: &AppState,
    nom: &str,
    etapes: Vec<EtapeAction>,
    lien: Option<String>,
) -> Response {
    let r = ResultatAction {
        applique: true,
        resume: format!("compte « {nom} » créé"),
        etapes,
        commande_cli: format!("hlb user add {nom} --apply"),
        blocages: Vec::new(),
        avertissements: Vec::new(),
        confirmation_requise: None,
    };

    let issue = if r.reussie() { "ok" } else { "failed" };
    let _ = s
        .state
        .audit(
            "inscription",
            hlb_types::Role::Utilisateur,
            "inscription",
            nom,
            issue,
            Some(&r.verdict()),
        )
        .await;

    (
        StatusCode::OK,
        Json(Inscrit {
            resultat: r,
            lien_enrolement: lien,
        }),
    )
        .into_response()
}

/// Journalise et rend la réponse.
async fn rendre(
    s: &AppState,
    identite: &crate::auth::Identite,
    action: &str,
    cible: &str,
    r: ResultatAction,
    lien: Option<String>,
) -> Response {
    let issue = if !r.applique {
        "preview"
    } else if r.reussie() {
        "ok"
    } else {
        "failed"
    };

    let _ = s
        .state
        .audit(
            identite.acteur.nom(),
            identite.role,
            action,
            cible,
            issue,
            Some(&r.verdict()),
        )
        .await;

    (StatusCode::OK, Json(InvitationCreee { resultat: r, lien })).into_response()
}

/// Qui peut lire l'annuaire sans pouvoir le modifier.
///
/// Séparé de [`liste`] : `PeutLire` suffit pour voir qui existe, mais changer un rôle
/// demande `GererComptes`.
pub async fn annuaire(
    _auth: Autorise<PeutLire>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<String>> {
    Json(
        s.state
            .users()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(n, _, _)| n)
            .collect(),
    )
}
