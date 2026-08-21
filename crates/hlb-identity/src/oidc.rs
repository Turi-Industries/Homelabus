//! Connexion des personnes par PocketID (OpenID Connect, code d'autorisation + PKCE).
//!
//! ## Pourquoi ce module existe
//!
//! Jusqu'ici, Homelabus n'authentifiait que des **machines** : un jeton d'API porté par
//! un en-tête `Authorization`. C'est le bon outil pour le CLI, pour Bitwarden et pour un
//! scrape de métriques. C'est le mauvais pour vingt personnes — il faudrait leur faire
//! conserver et coller une valeur de 52 caractères, sans déconnexion possible et sans
//! savoir qui est connecté.
//!
//! Ici, la personne va s'authentifier chez PocketID (par clé d'accès, il n'y a pas de
//! mot de passe), et revient avec un code que le controller échange **lui-même**, de
//! serveur à serveur.
//!
//! ## 🔴 Pourquoi on ne vérifie PAS la signature de l'`id_token`
//!
//! C'est le point qui surprend en relecture, donc il est écrit ici plutôt que d'être
//! découvert dans six mois.
//!
//! L'`id_token` n'arrive **jamais par le navigateur**. Il est récupéré par un appel
//! direct du controller au point de terminaison `token` de PocketID, sur une connexion
//! TLS dont le certificat authentifie déjà l'émetteur. C'est exactement le cas prévu par
//! OpenID Connect Core §3.1.3.7 point 6, qui dispense alors de la validation de
//! signature : le canal fait le travail que ferait la signature.
//!
//! ⚠️ **Ce raisonnement ne tiendrait pas** pour un jeton reçu du navigateur (flux
//! implicite ou hybride), où n'importe qui peut en fabriquer un. Le type
//! [`DemandeEnCours`] est donc conçu pour que la seule façon d'obtenir une [`Identite`]
//! soit de passer par [`Oidc::terminer`], qui fait l'échange lui-même.
//!
//! L'identité elle-même est lue au point de terminaison `userinfo`, également appelé de
//! serveur à serveur. La charge utile de l'`id_token` n'est décodée que pour confronter
//! le `nonce`.
//!
//! ## Ce qui protège réellement l'échange
//!
//! | Attaque | Ce qui l'arrête |
//! |---|---|
//! | Requête forgée depuis un autre site | le paramètre `state`, comparé en temps constant |
//! | Interception du code d'autorisation | PKCE `S256` : le code seul ne suffit pas |
//! | Rejeu d'une réponse ancienne | l'échéance de [`DemandeEnCours`] et le `nonce` |
//! | Serveur d'autorisation usurpé | TLS vers l'émetteur découvert |

use serde::Deserialize;

use crate::{Error, Result};

/// Durée de validité d'une demande de connexion entamée.
///
/// Assez pour enregistrer une clé d'accès sans se presser, trop court pour qu'une URL
/// de retour retrouvée dans un historique serve encore.
pub const DELAI_DEMANDE_S: i64 = 600;

/// Les points de terminaison, découverts plutôt que devinés.
///
/// Les coder en dur marcherait aujourd'hui et casserait le jour où PocketID les
/// déplace, avec un `404` qui ne dirait pas que c'est la découverte qu'il fallait faire.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Endpoints {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

/// Une demande de connexion entamée, en attente du retour du navigateur.
///
/// 🔴 Elle contient le **vérificateur** PKCE, qui est un secret : il ne doit jamais
/// partir vers le navigateur, sans quoi PKCE ne protège plus de rien. C'est pourquoi
/// elle vit côté controller et que seul le `state` circule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemandeEnCours {
    pub state: String,
    verifier: String,
    nonce: String,
    pub cree_a: i64,
    /// Où renvoyer la personne une fois connectée (une route de l'UI, jamais une URL
    /// absolue : cf. [`Self::retour_sur`]).
    pub retour: Option<String>,
}

impl DemandeEnCours {
    pub fn est_expiree(&self, maintenant: i64) -> bool {
        maintenant.saturating_sub(self.cree_a) > DELAI_DEMANDE_S
    }

    /// La destination après connexion, filtrée.
    ///
    /// 🔴 Seul un chemin relatif commençant par `/` est accepté. Sans ce filtre, un lien
    /// `…/auth/connexion?retour=https://ailleurs.example` transformerait l'écran de
    /// connexion en tremplin de redirection — utilisable pour faire croire à un
    /// hameçonnage qu'il vient de chez nous. Un `//` initial est refusé aussi : c'est
    /// une URL absolue déguisée (`//evil.example`).
    pub fn retour_sur(&self) -> &str {
        match self.retour.as_deref() {
            Some(r) if r.starts_with('/') && !r.starts_with("//") => r,
            _ => "/",
        }
    }
}

/// Qui vient de se connecter.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct Identite {
    /// L'identifiant stable chez PocketID. C'est LUI qui fait foi, pas le nom
    /// d'utilisateur : ce dernier peut être renommé, et on perdrait le lien.
    pub sub: String,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// Les groupes PocketID, conservés pour qui préfère l'ancien schéma du §5.9
    /// (`Role::from_groups`). Homelabus ne s'en sert pas par défaut.
    #[serde(default)]
    pub groups: Vec<String>,
}

impl Identite {
    /// Le nom de compte à chercher côté Homelabus.
    ///
    /// `preferred_username` d'abord, `sub` en dernier recours : un identifiant opaque
    /// vaut mieux qu'un compte impossible à rattacher.
    pub fn nom_de_compte(&self) -> &str {
        self.preferred_username.as_deref().unwrap_or(&self.sub)
    }

    pub fn nom_affiche(&self) -> &str {
        self.name.as_deref().unwrap_or_else(|| self.nom_de_compte())
    }
}

#[derive(Debug, Deserialize)]
struct ReponseJeton {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
}

/// Le client OIDC du controller.
#[derive(Debug, Clone)]
pub struct Oidc {
    endpoints: Endpoints,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http: reqwest::Client,
}

impl Oidc {
    /// Découvre les points de terminaison chez l'émetteur.
    pub async fn decouvrir(
        issuer: &str,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|source| Error::Http {
                source,
                context: "construction du client HTTP".into(),
            })?;

        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let r = http.get(&url).send().await.map_err(|source| Error::Http {
            source,
            context: format!("découverte OIDC sur {url}"),
        })?;

        let status = r.status();
        if !status.is_success() {
            return Err(Error::Api {
                status: status.as_u16(),
                detail: format!(
                    "découverte OIDC impossible sur {url} — l'émetteur est-il bien PocketID ?"
                ),
            });
        }

        let endpoints: Endpoints = r.json().await.map_err(|source| Error::Http {
            source,
            context: "découverte OIDC illisible".into(),
        })?;

        Ok(Self {
            endpoints,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http,
        })
    }

    /// Variante pour les tests et pour un émetteur qui ne publie pas sa découverte.
    pub fn avec_endpoints(
        endpoints: Endpoints,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            endpoints,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http: reqwest::Client::new(),
        }
    }

    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// Construit l'URL vers laquelle envoyer le navigateur, et la demande à retenir.
    ///
    /// `alea` fournit l'entropie des trois valeurs (état, vérificateur PKCE, nonce) — en
    /// paramètre plutôt que tiré ici, pour que la fonction soit **pure et testable** :
    /// c'est la même discipline que `Genere::pour` pour les aliases.
    ///
    /// 🔴 96 octets, découpés en trois tiers. Les partager rendrait le `state`
    /// déductible du vérificateur, et réciproquement.
    pub fn demarrer(
        &self,
        alea: &[u8; 96],
        retour: Option<String>,
        maintenant: i64,
    ) -> (String, DemandeEnCours) {
        let state = hlb_types::token::base64url(&alea[0..32]);
        let verifier = hlb_types::token::base64url(&alea[32..64]);
        let nonce = hlb_types::token::base64url(&alea[64..96]);

        let challenge =
            hlb_types::token::base64url(&hlb_types::token::sha256_bytes(verifier.as_bytes()));

        let sep = if self.endpoints.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        let url = format!(
            "{}{sep}response_type=code&client_id={}&redirect_uri={}&scope={}\
             &state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            self.endpoints.authorization_endpoint,
            pourcent(&self.client_id),
            pourcent(&self.redirect_uri),
            pourcent("openid profile email groups"),
            pourcent(&state),
            pourcent(&nonce),
            pourcent(&challenge),
        );

        (
            url,
            DemandeEnCours {
                state,
                verifier,
                nonce,
                cree_a: maintenant,
                retour,
            },
        )
    }

    /// Échange le code contre une identité.
    ///
    /// Vérifie, dans cet ordre : l'état, l'échéance, puis le `nonce` de l'`id_token`.
    /// L'ordre compte — un état qui ne correspond pas signale une requête forgée, et on
    /// ne veut surtout pas avoir déjà appelé le point de terminaison `token` à ce
    /// moment-là.
    pub async fn terminer(
        &self,
        demande: &DemandeEnCours,
        state_recu: &str,
        code: &str,
        maintenant: i64,
    ) -> Result<Identite> {
        if !hlb_types::token::constant_eq(&demande.state, state_recu) {
            return Err(Error::Unexpected(
                "état de connexion invalide : la réponse ne correspond pas à une demande \
                 partie d'ici (requête forgée, ou connexion entamée dans un autre onglet)"
                    .into(),
            ));
        }
        if demande.est_expiree(maintenant) {
            return Err(Error::Unexpected(format!(
                "demande de connexion expirée (au-delà de {DELAI_DEMANDE_S} s) — relance la connexion"
            )));
        }

        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code_verifier", demande.verifier.as_str()),
        ];

        let r = self
            .http
            .post(&self.endpoints.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: "échange du code d'autorisation".into(),
            })?;

        let status = r.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !status.is_success() {
            let detail = r.text().await.unwrap_or_default();
            return Err(Error::Api {
                status: status.as_u16(),
                detail: format!("échange du code refusé : {detail}"),
            });
        }

        let jeton: ReponseJeton = r.json().await.map_err(|source| Error::Http {
            source,
            context: "réponse du point de terminaison token illisible".into(),
        })?;

        // Le nonce, s'il y a un id_token. Voir la note de sécurité en tête de module :
        // la charge utile est lue sans vérifier la signature parce que le jeton vient
        // d'être récupéré directement, sur TLS — jamais du navigateur.
        if let Some(id) = &jeton.id_token {
            match nonce_de(id) {
                Some(n) if hlb_types::token::constant_eq(&demande.nonce, &n) => {}
                Some(_) => {
                    return Err(Error::Unexpected(
                        "le nonce de l'id_token ne correspond pas : réponse rejouée".into(),
                    ))
                }
                // Un id_token sans nonce n'est pas une preuve de rejeu : certains
                // émetteurs ne le répercutent pas. On ne bloque pas là-dessus, mais on
                // le dit, parce qu'une protection absente ne doit pas être silencieuse.
                None => tracing::warn!(
                    "id_token sans nonce : la protection contre le rejeu repose \
                     uniquement sur l'échéance de la demande"
                ),
            }
        }

        let r = self
            .http
            .get(&self.endpoints.userinfo_endpoint)
            .bearer_auth(&jeton.access_token)
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: "lecture de userinfo".into(),
            })?;

        let status = r.status();
        if !status.is_success() {
            let detail = r.text().await.unwrap_or_default();
            return Err(Error::Api {
                status: status.as_u16(),
                detail: format!("userinfo refusé : {detail}"),
            });
        }

        let identite: Identite = r.json().await.map_err(|source| Error::Http {
            source,
            context: "userinfo illisible".into(),
        })?;

        if identite.sub.is_empty() {
            return Err(Error::Unexpected(
                "userinfo sans « sub » : impossible de rattacher un compte à une identité \
                 stable"
                    .into(),
            ));
        }

        Ok(identite)
    }
}

/// Le `nonce` porté par la charge utile d'un JWT.
///
/// Décodage sans vérification de signature : voir la note de sécurité en tête de module.
/// Rend `None` dès que quoi que ce soit ne colle pas — un JWT mal formé n'est pas
/// « presque bon ».
fn nonce_de(jwt: &str) -> Option<String> {
    let charge = jwt.split('.').nth(1)?;
    let brut = hlb_types::token::base64url_decode(charge)?;
    let v: serde_json::Value = serde_json::from_slice(&brut).ok()?;
    v.get("nonce")?.as_str().map(str::to_string)
}

/// Encodage pour-cent d'un paramètre de requête (RFC 3986 §2.3, caractères non
/// réservés).
///
/// Écrit à la main pour la même raison que le base64url : c'est dix lignes contre une
/// dépendance de plus dans un chemin qui manipule des secrets.
fn pourcent(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oidc() -> Oidc {
        Oidc::avec_endpoints(
            Endpoints {
                issuer: "https://id.turi.fr".into(),
                authorization_endpoint: "https://id.turi.fr/authorize".into(),
                token_endpoint: "https://id.turi.fr/api/oidc/token".into(),
                userinfo_endpoint: "https://id.turi.fr/api/oidc/userinfo".into(),
                end_session_endpoint: None,
            },
            "hlb",
            "secret",
            "https://hlb.turi.fr/auth/retour",
        )
    }

    fn alea(graine: u8) -> [u8; 96] {
        let mut a = [0u8; 96];
        for (i, o) in a.iter_mut().enumerate() {
            *o = graine.wrapping_add((i * 31) as u8);
        }
        a
    }

    #[test]
    fn the_verifier_never_leaves_the_controller() {
        // 🔴 Si le vérificateur PKCE partait dans l'URL, PKCE ne protégerait plus rien :
        // qui intercepte le code intercepterait aussi de quoi l'échanger.
        let (url, d) = oidc().demarrer(&alea(1), None, 0);
        assert!(!url.contains(&d.verifier), "le vérificateur est dans l'URL : {url}");
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn the_three_secrets_are_independent() {
        // Les tirer du même tiers d'entropie rendrait l'état déductible du vérificateur.
        let (_, d) = oidc().demarrer(&alea(7), None, 0);
        assert_ne!(d.state, d.verifier);
        assert_ne!(d.state, d.nonce);
        assert_ne!(d.verifier, d.nonce);
    }

    #[test]
    fn two_logins_never_share_a_state() {
        let (_, a) = oidc().demarrer(&alea(1), None, 0);
        let (_, b) = oidc().demarrer(&alea(2), None, 0);
        assert_ne!(a.state, b.state);
    }

    #[tokio::test]
    async fn a_forged_state_is_refused_before_any_network_call() {
        // 🔴 L'ordre compte : on ne veut pas avoir déjà appelé le point de terminaison
        // token quand on découvre que la requête est forgée. Le test le vérifie de fait,
        // puisque l'URL de test n'existe pas — un appel réseau ferait échouer sur une
        // erreur de transport, pas sur le message d'état invalide.
        let d = oidc().demarrer(&alea(3), None, 0).1;
        let e = oidc()
            .terminer(&d, "un-autre-etat", "code", 0)
            .await
            .expect_err("un état différent doit être refusé");
        assert!(format!("{e}").contains("état de connexion invalide"), "{e}");
    }

    #[tokio::test]
    async fn an_expired_request_is_refused_before_any_network_call() {
        let d = oidc().demarrer(&alea(3), None, 0).1;
        let e = oidc()
            .terminer(&d, &d.state, "code", DELAI_DEMANDE_S + 1)
            .await
            .expect_err("une demande périmée doit être refusée");
        assert!(format!("{e}").contains("expirée"), "{e}");
    }

    #[test]
    fn an_absolute_return_url_is_never_honoured() {
        // 🔴 Sans ce filtre, l'écran de connexion devient un tremplin de redirection :
        // un lien d'hameçonnage passerait par notre domaine pour se rendre crédible.
        for mechant in [
            "https://ailleurs.example",
            "//ailleurs.example",
            "javascript:alert(1)",
            "ailleurs.example",
        ] {
            let d = DemandeEnCours {
                state: "s".into(),
                verifier: "v".into(),
                nonce: "n".into(),
                cree_a: 0,
                retour: Some(mechant.to_string()),
            };
            assert_eq!(d.retour_sur(), "/", "aurait suivi {mechant}");
        }
    }

    #[test]
    fn a_relative_return_url_is_honoured() {
        let d = DemandeEnCours {
            state: "s".into(),
            verifier: "v".into(),
            nonce: "n".into(),
            cree_a: 0,
            retour: Some("/apps/gitea".into()),
        };
        assert_eq!(d.retour_sur(), "/apps/gitea");
    }

    #[test]
    fn the_nonce_is_read_from_a_jwt_payload() {
        // Charge utile seule : ni en-tête ni signature ne sont nécessaires pour la lire,
        // et c'est précisément ce que le module assume et documente.
        let charge = hlb_types::token::base64url(br#"{"nonce":"abc","sub":"u1"}"#);
        assert_eq!(nonce_de(&format!("entete.{charge}.signature")), Some("abc".into()));
    }

    #[test]
    fn a_malformed_jwt_yields_nothing_rather_than_a_guess() {
        assert_eq!(nonce_de("pas-un-jwt"), None);
        assert_eq!(nonce_de("a.b.c"), None);
        let sans = hlb_types::token::base64url(br#"{"sub":"u1"}"#);
        assert_eq!(nonce_de(&format!("e.{sans}.s")), None);
    }

    #[test]
    fn query_parameters_are_escaped() {
        // Un `redirect_uri` non échappé couperait l'URL au premier `&`, et le serveur
        // d'autorisation renverrait vers une adresse tronquée.
        assert_eq!(pourcent("https://a/b?c=d&e"), "https%3A%2F%2Fa%2Fb%3Fc%3Dd%26e");
        assert_eq!(pourcent("openid profile"), "openid%20profile");
        assert_eq!(pourcent("aZ0-._~"), "aZ0-._~");
    }

    #[test]
    fn the_authorization_url_carries_everything_the_flow_needs() {
        let (url, d) = oidc().demarrer(&alea(9), None, 0);
        for attendu in [
            "response_type=code",
            "client_id=hlb",
            "scope=openid%20profile%20email%20groups",
            "code_challenge_method=S256",
        ] {
            assert!(url.contains(attendu), "{attendu} manque dans {url}");
        }
        assert!(url.contains(&format!("state={}", pourcent(&d.state))));
    }

    #[test]
    fn the_subject_is_what_identifies_a_person_not_the_username() {
        // Un nom d'utilisateur se renomme ; le `sub` ne bouge pas. Se rattacher au nom
        // perdrait le lien au premier renommage, en silence.
        let i = Identite {
            sub: "abc-123".into(),
            preferred_username: None,
            ..Default::default()
        };
        assert_eq!(i.nom_de_compte(), "abc-123");

        let i = Identite {
            sub: "abc-123".into(),
            preferred_username: Some("remy".into()),
            ..Default::default()
        };
        assert_eq!(i.nom_de_compte(), "remy");
        assert_eq!(i.nom_affiche(), "remy", "à défaut de nom affiché");
    }
}
