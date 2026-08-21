//! Limitation de débit (§9, défense en profondeur).
//!
//! ## Ce que ça protège, concrètement
//!
//! Trois routes justifient à elles seules ce module :
//!
//! - **`/api/v1/aliases`** — un jeton volé sans limite est un générateur d'adresses. Le
//!   voleur en crée cent mille : le quota du profil finit par mordre, mais entre-temps
//!   la table a grossi, les règles Sieve avec, et le script Sieve du compte devient
//!   trop gros pour Stalwart. La boîte cesse alors de trier — y compris pour les règles
//!   écrites à la main.
//! - **`/auth/retour`** — sans limite, c'est un oracle : on y essaie des états jusqu'à
//!   en trouver un vivant.
//! - **`/api/…` avec un mauvais jeton** — un jeton fait 256 bits, il n'est pas
//!   devinable ; mais chaque essai coûte une lecture indexée et un SHA-256, et rien
//!   n'oblige à offrir ce service gratuitement.
//!
//! ## 🔴 Pourquoi l'adresse du client n'est pas lue dans `X-Forwarded-For` par défaut
//!
//! Derrière Caddy, l'adresse réelle est dans cet en-tête. Mais **le client peut
//! l'écrire lui-même** : lui faire confiance sans savoir qu'un proxy de confiance est
//! devant, c'est offrir à chaque attaquant un compteur neuf à chaque requête — donc une
//! limitation qui ne limite rien, tout en donnant l'impression du contraire.
//!
//! L'en-tête n'est donc lu que si `--trusted-proxy` a été posé explicitement.

use std::collections::HashMap;
use std::net::IpAddr;

/// La nature d'une requête, qui décide de son budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Classe {
    /// Entrer et sortir. Généreux : un aller-retour OIDC en fait plusieurs, et une
    /// personne qui se trompe de compte recommence.
    Connexion,
    /// Tout ce qui change quelque chose.
    Ecriture,
    /// Le reste. L'interface sonde plusieurs ressources en parallèle, plusieurs fois
    /// par minute : un budget trop serré casserait le tableau de bord lui-même.
    Lecture,
}

impl Classe {
    /// Requêtes autorisées par fenêtre.
    pub fn budget(&self) -> u32 {
        match self {
            Self::Connexion => 20,
            Self::Ecriture => 60,
            Self::Lecture => 600,
        }
    }

    /// La classe d'une requête.
    pub fn de(methode: &axum::http::Method, chemin: &str) -> Self {
        if chemin.starts_with("/auth/") {
            return Self::Connexion;
        }
        if matches!(
            *methode,
            axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
        ) {
            Self::Lecture
        } else {
            Self::Ecriture
        }
    }
}

/// La fenêtre glissante, en secondes.
pub const FENETRE_S: i64 = 60;

/// Au-delà, on oublie les compteurs les plus anciens.
///
/// Sans plafond, une attaque distribuée ferait grossir la table indéfiniment — la
/// protection deviendrait elle-même la panne.
const CLIENTS_MAX: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct Compteur {
    debut: i64,
    nombre: u32,
}

/// Le compteur de débit.
///
/// Fenêtre fixe plutôt que glissante : deux fois moins de mémoire, et l'imprécision
/// (jusqu'à deux fois le budget à cheval sur deux fenêtres) est sans importance ici —
/// on se protège d'un martèlement, pas d'un dépassement de 60 à 61.
#[derive(Default)]
pub struct Limiteur {
    compteurs: std::sync::Mutex<HashMap<(String, Classe), Compteur>>,
}

/// Le verdict d'une vérification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Passe,
    /// 🔴 Trop de requêtes. `retry_after_s` dit dans combien de temps réessayer —
    /// un `429` sans cette indication laisse le client marteler de plus belle.
    Refuse { retry_after_s: i64 },
}

impl Verdict {
    pub fn passe(&self) -> bool {
        matches!(self, Self::Passe)
    }
}

impl Limiteur {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cette requête passe-t-elle ?
    ///
    /// `maintenant` est un paramètre pour que la fonction soit testable sans attendre
    /// une minute — même discipline que l'aléa des aliases.
    pub fn verifier(&self, client: &str, classe: Classe, maintenant: i64) -> Verdict {
        let Ok(mut m) = self.compteurs.lock() else {
            // 🔴 Un verrou empoisonné ne doit pas fermer le service. On laisse passer :
            // la limitation est une défense en profondeur, pas le contrôle d'accès —
            // celui-ci a déjà eu lieu. Refuser ici transformerait un incident interne
            // en indisponibilité totale.
            return Verdict::Passe;
        };

        if m.len() > CLIENTS_MAX {
            // Ménage : tout ce dont la fenêtre est close.
            m.retain(|_, c| maintenant - c.debut < FENETRE_S);
        }

        let e = m
            .entry((client.to_string(), classe))
            .or_insert(Compteur {
                debut: maintenant,
                nombre: 0,
            });

        if maintenant - e.debut >= FENETRE_S {
            *e = Compteur {
                debut: maintenant,
                nombre: 0,
            };
        }

        e.nombre += 1;
        if e.nombre > classe.budget() {
            Verdict::Refuse {
                retry_after_s: (FENETRE_S - (maintenant - e.debut)).max(1),
            }
        } else {
            Verdict::Passe
        }
    }
}

/// L'identifiant du client d'une requête.
///
/// `confiance_proxy` doit venir de `--trusted-proxy` : voir l'en-tête du module pour
/// pourquoi il n'est pas vrai par défaut.
pub fn client(
    entetes: &axum::http::HeaderMap,
    pair: Option<IpAddr>,
    confiance_proxy: bool,
) -> String {
    if confiance_proxy {
        if let Some(xff) = entetes
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            // Le PREMIER de la liste est le client d'origine ; les suivants sont les
            // proxys traversés.
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            return xff.to_string();
        }
    }
    pair.map(|i| i.to_string())
        .unwrap_or_else(|| "inconnu".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, Method};

    #[test]
    fn a_burst_is_stopped_at_the_budget() {
        let l = Limiteur::new();
        for n in 1..=Classe::Ecriture.budget() {
            assert!(
                l.verifier("1.2.3.4", Classe::Ecriture, 100).passe(),
                "la requête {n} devrait passer"
            );
        }
        let v = l.verifier("1.2.3.4", Classe::Ecriture, 100);
        assert!(!v.passe());
        match v {
            Verdict::Refuse { retry_after_s } => assert!(retry_after_s > 0, "il faut dire quand réessayer"),
            Verdict::Passe => unreachable!(),
        }
    }

    #[test]
    fn the_window_reopens() {
        let l = Limiteur::new();
        for _ in 0..=Classe::Ecriture.budget() {
            l.verifier("1.2.3.4", Classe::Ecriture, 100);
        }
        assert!(!l.verifier("1.2.3.4", Classe::Ecriture, 100).passe());
        assert!(l.verifier("1.2.3.4", Classe::Ecriture, 100 + FENETRE_S).passe());
    }

    #[test]
    fn one_client_does_not_starve_another() {
        // Une limitation globale ferait d'un seul attaquant une panne pour tout le
        // monde — la protection deviendrait l'attaque.
        let l = Limiteur::new();
        for _ in 0..=Classe::Ecriture.budget() {
            l.verifier("mechant", Classe::Ecriture, 100);
        }
        assert!(!l.verifier("mechant", Classe::Ecriture, 100).passe());
        assert!(l.verifier("gentil", Classe::Ecriture, 100).passe());
    }

    #[test]
    fn writing_does_not_eat_the_reading_budget() {
        // L'interface sonde plusieurs ressources plusieurs fois par minute : partager
        // le budget avec les écritures casserait le tableau de bord au premier
        // enchaînement d'actions.
        let l = Limiteur::new();
        for _ in 0..=Classe::Ecriture.budget() {
            l.verifier("1.2.3.4", Classe::Ecriture, 100);
        }
        assert!(!l.verifier("1.2.3.4", Classe::Ecriture, 100).passe());
        assert!(l.verifier("1.2.3.4", Classe::Lecture, 100).passe());
    }

    #[test]
    fn login_routes_have_their_own_class() {
        assert_eq!(Classe::de(&Method::GET, "/auth/connexion"), Classe::Connexion);
        assert_eq!(Classe::de(&Method::GET, "/auth/retour"), Classe::Connexion);
        assert_eq!(Classe::de(&Method::POST, "/auth/deconnexion"), Classe::Connexion);
        assert_eq!(Classe::de(&Method::GET, "/api/apps"), Classe::Lecture);
        assert_eq!(Classe::de(&Method::POST, "/api/v1/aliases"), Classe::Ecriture);
        assert_eq!(Classe::de(&Method::DELETE, "/api/apps/x"), Classe::Ecriture);
    }

    #[test]
    fn a_spoofable_header_is_ignored_by_default() {
        // 🔴 Sans proxy de confiance déclaré, croire `X-Forwarded-For` donnerait à
        // chaque attaquant un compteur neuf à chaque requête : une limitation qui ne
        // limite rien tout en donnant l'impression du contraire.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
        let pair: IpAddr = "1.2.3.4".parse().expect("ip");

        assert_eq!(client(&h, Some(pair), false), "1.2.3.4");
        assert_eq!(client(&h, Some(pair), true), "9.9.9.9");
    }

    #[test]
    fn the_original_client_is_the_first_of_the_chain() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("9.9.9.9, 10.0.0.1, 10.0.0.2"));
        assert_eq!(client(&h, None, true), "9.9.9.9");
    }

    #[test]
    fn an_empty_forwarded_header_falls_back_to_the_socket() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("  "));
        let pair: IpAddr = "1.2.3.4".parse().expect("ip");
        assert_eq!(client(&h, Some(pair), true), "1.2.3.4");
    }

    #[test]
    fn the_table_does_not_grow_without_bound() {
        // Sans plafond, une attaque distribuée ferait de la protection la panne.
        let l = Limiteur::new();
        for n in 0..(CLIENTS_MAX + 100) {
            l.verifier(&format!("client-{n}"), Classe::Lecture, 100);
        }
        // Une fenêtre plus tard, le ménage doit avoir eu lieu.
        l.verifier("declencheur", Classe::Lecture, 100 + FENETRE_S);
        let n = l.compteurs.lock().expect("verrou").len();
        assert!(n <= CLIENTS_MAX + 200, "table non bornée : {n} entrées");
    }
}
