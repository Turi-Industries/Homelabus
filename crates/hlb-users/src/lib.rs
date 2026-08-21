//! Comptes humains : identité, boîtes mail, aliases et quotas (§5bis.3).
//!
//! ## Ce que ce crate ajoute
//!
//! Jusqu'ici HomelabUS ne connaissait que des **applications**. `hlb-identity` créait
//! des clients OIDC, `hlb-mail` créait la boîte d'une app qui en déclarait le besoin —
//! et aucun code ne savait ce qu'était une *personne*. Créer un compte se faisait à la
//! main dans PocketID, sa boîte à la main dans Stalwart, et rien ne reliait les deux :
//! supprimer l'un laissait l'autre en place.
//!
//! Ce crate porte le modèle qui manquait, et surtout ses **règles**. Les clients
//! réseau restent où ils sont : ici, tout est testable sans serveur.
//!
//! ## Les trois pièces
//!
//! - [`profil`] — combien de boîtes et d'aliases un compte a le droit d'ouvrir.
//! - [`alias`] — permanents ou temporaires, et surtout ce qui arrive quand la purge
//!   ne tourne pas.
//! - [`generation`] — les aliases jetables générés par destinataire, façon addy.io.
//!
//! ## 🔴 Un compte à moitié créé est pire qu'un compte absent
//!
//! Créer un utilisateur touche **deux** systèmes : PocketID pour l'identité, Stalwart
//! pour la boîte. Si le second échoue, on obtient quelqu'un qui peut se connecter à
//! toutes les apps et dont l'adresse ne reçoit rien — un état qui paraît fonctionnel
//! jusqu'au premier courriel perdu, souvent une réinitialisation de mot de passe.
//!
//! [`Compte::coherence`] rend cet état **visible et nommé** plutôt que de le laisser
//! se découvrir. Et la création est reprenable : relancer termine ce qui manque, sans
//! jamais recréer ce qui existe.

pub mod alias;
pub mod forwarder;
pub mod generation;
pub mod profil;
pub mod sieve;

pub use alias::{Alias, Duree, Etat as EtatAlias};
pub use forwarder::{AliasCree, CreationDemandee};
pub use generation::Genere;
pub use profil::{Demande, Profil, Refus, Usage};
pub use sieve::Regle as RegleSieve;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Quota(String),

    #[error("« {0} » : identifiant inutilisable — minuscules, chiffres, point, tiret")]
    NomInvalide(String),

    #[error("la boîte par défaut « {0} » ne peut pas être supprimée : c'est l'identité \
             du compte. Change-la d'abord, ou supprime l'utilisateur entier")]
    BoiteParDefaut(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Une boîte mail appartenant à quelqu'un.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Boite {
    /// Partie locale : `remy`, `contact`, `photo`.
    pub local: String,
    pub domaine: String,
    /// 🔴 Celle qui sert d'identité au compte. Une seule par utilisateur.
    pub par_defaut: bool,
    pub aliases: Vec<Alias>,
}

impl Boite {
    pub fn adresse(&self) -> String {
        format!("{}@{}", self.local, self.domaine)
    }

    /// Les aliases dont l'expiration n'a pas été honorée.
    ///
    /// 🔴 Ce sont des adresses que l'utilisateur croit fermées et qui reçoivent encore.
    pub fn promesses_rompues(&self, maintenant: i64) -> Vec<&Alias> {
        self.aliases
            .iter()
            .filter(|a| a.etat(maintenant).trahit_la_promesse())
            .collect()
    }
}

/// Un compte humain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compte {
    /// Identifiant de connexion.
    pub nom: String,
    pub profil: String,
    /// Identifiant PocketID, une fois l'identité créée.
    pub pocket_id: Option<String>,
    pub boites: Vec<Boite>,
}

/// L'état d'un compte vis-à-vis des deux systèmes qu'il traverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coherence {
    /// Identité et boîte par défaut en place.
    Complet,
    /// 🔴 Il peut se connecter, son adresse ne reçoit rien.
    ///
    /// L'état qui paraît fonctionnel jusqu'au premier courriel perdu — souvent une
    /// réinitialisation de mot de passe, c'est-à-dire au pire moment.
    SansBoite,
    /// 🔴 Sa boîte reçoit, il ne peut se connecter à rien.
    SansIdentite,
    /// Rien n'a abouti.
    Vide,
}

impl Coherence {
    pub fn est_complet(&self) -> bool {
        matches!(self, Self::Complet)
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::Complet => "complet",
            // ⚠️ Pas d'emoji dans ces messages : ils sont AFFICHÉS par le CLI *et* par
            // l'interface. Le terminal les rend, egui non — il faudrait les remplacer
            // par un caractère de substitution, qui gâche la phrase. Un texte partagé
            // ne doit pas dépendre de ce qu'un seul de ses consommateurs sait afficher.
            // La gravité est portée par le contenu, et par la couleur de l'appelant.
            Self::SansBoite => {
                "identité créée, AUCUNE boîte — cette personne peut se connecter \
                 partout et son adresse ne reçoit rien. Le premier courriel perdu sera \
                 sans doute une réinitialisation de mot de passe. Relance « hlb user add » \
                 avec les mêmes arguments : la création reprend où elle s'était arrêtée"
            }
            Self::SansIdentite => {
                "boîte créée, AUCUNE identité — le courrier arrive et personne ne \
                 peut le lire. Relance « hlb user add » pour terminer"
            }
            Self::Vide => "aucune identité, aucune boîte",
        }
    }
}

impl Compte {
    pub fn nouveau(nom: impl Into<String>, profil: impl Into<String>) -> Self {
        Self {
            nom: nom.into(),
            profil: profil.into(),
            pocket_id: None,
            boites: Vec::new(),
        }
    }

    /// La boîte qui sert d'identité.
    pub fn boite_par_defaut(&self) -> Option<&Boite> {
        self.boites.iter().find(|b| b.par_defaut)
    }

    /// 🔴 Le compte est-il utilisable, ou à moitié créé ?
    pub fn coherence(&self) -> Coherence {
        match (self.pocket_id.is_some(), self.boite_par_defaut().is_some()) {
            (true, true) => Coherence::Complet,
            (true, false) => Coherence::SansBoite,
            (false, true) => Coherence::SansIdentite,
            (false, false) => Coherence::Vide,
        }
    }

    /// Ce que ce compte consomme de son profil.
    ///
    /// ⚠️ Les aliases temporaires **déjà purgés** ne comptent plus : ils ne coûtent
    /// plus rien au serveur, et les compter empêcherait d'en créer de nouveaux après
    /// une année d'usage normal.
    pub fn usage(&self, maintenant: i64) -> Usage {
        let mut u = Usage {
            boites: self.boites.len() as u32,
            ..Default::default()
        };

        for b in &self.boites {
            for a in &b.aliases {
                match a.duree {
                    Duree::Permanent => u.aliases_permanents += 1,
                    Duree::Temporaire { .. } => {
                        if !matches!(a.etat(maintenant), alias::Etat::Expire) {
                            u.aliases_temporaires += 1;
                        }
                    }
                }
            }
        }
        u
    }

    /// Toutes les promesses d'expiration non tenues, toutes boîtes confondues.
    pub fn promesses_rompues(&self, maintenant: i64) -> Vec<(&Boite, &Alias)> {
        self.boites
            .iter()
            .flat_map(|b| b.promesses_rompues(maintenant).into_iter().map(move |a| (b, a)))
            .collect()
    }

    /// Peut-on supprimer cette boîte ?
    ///
    /// 🔴 La boîte par défaut est l'identité du compte : la supprimer laisserait
    /// quelqu'un capable de se connecter dont l'adresse ne mène nulle part.
    pub fn peut_supprimer_boite(&self, local: &str) -> Result<()> {
        match self.boites.iter().find(|b| b.local == local) {
            Some(b) if b.par_defaut => Err(Error::BoiteParDefaut(b.adresse())),
            _ => Ok(()),
        }
    }
}

/// Un nom d'utilisateur acceptable ?
///
/// ⚠️ Il devient une partie locale d'adresse ET un identifiant PocketID. Strict
/// délibérément : un nom qui passerait ici et serait refusé plus loin laisserait un
/// compte à moitié créé.
pub fn valider_nom(nom: &str) -> Result<()> {
    let ok = !nom.is_empty()
        && nom.len() <= 50
        && nom
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        && !nom.starts_with(['.', '-'])
        && !nom.ends_with(['.', '-']);

    if ok {
        Ok(())
    } else {
        Err(Error::NomInvalide(nom.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_messages_carry_no_glyph_the_ui_cannot_display() {
        // ⚠️ Ces messages sont affichés par le CLI ET par l'interface egui. Le terminal
        // rend les emoji, egui non : il les remplace par un caractère de substitution,
        // ce qui gâche la phrase (« ¤ identité créée, AUCUNE boîte »).
        //
        // Un texte partagé ne doit pas dépendre de ce qu'un seul de ses consommateurs
        // sait afficher.
        for c in [
            Coherence::Complet,
            Coherence::SansBoite,
            Coherence::SansIdentite,
            Coherence::Vide,
        ] {
            for ch in c.describe().chars() {
                let n = ch as u32;
                assert!(
                    n < 0x2C0 || (0x2000..=0x206F).contains(&n),
                    "{:?} contient U+{n:04X}, que l'interface ne sait pas afficher",
                    c
                );
            }
        }
    }

    const T: i64 = 1_700_000_000;

    fn boite(local: &str, par_defaut: bool) -> Boite {
        Boite {
            local: local.into(),
            domaine: "example.fr".into(),
            par_defaut,
            aliases: Vec::new(),
        }
    }

    #[test]
    fn a_half_created_account_is_named_not_hidden() {
        // 🔴 Créer un utilisateur touche DEUX systèmes. Si le second échoue, on obtient
        // quelqu'un qui se connecte partout et dont l'adresse ne reçoit rien — un état
        // qui paraît fonctionnel jusqu'au premier courriel perdu, souvent une
        // réinitialisation de mot de passe, c'est-à-dire au pire moment.
        let mut c = Compte::nouveau("remy", "standard");
        assert_eq!(c.coherence(), Coherence::Vide);

        c.pocket_id = Some("uuid".into());
        assert_eq!(c.coherence(), Coherence::SansBoite);
        assert!(!c.coherence().est_complet());

        let d = c.coherence().describe();
        assert!(d.contains("ne reçoit rien"), "{d}");
        assert!(d.contains("réinitialisation"), "la conséquence concrète : {d}");
        assert!(d.contains("hlb user add"), "la reprise : {d}");

        c.boites.push(boite("remy", true));
        assert_eq!(c.coherence(), Coherence::Complet);
    }

    #[test]
    fn a_mailbox_without_an_identity_is_its_own_problem() {
        // Le courrier arrive et personne ne peut le lire — distinct du cas inverse.
        let mut c = Compte::nouveau("remy", "standard");
        c.boites.push(boite("remy", true));
        assert_eq!(c.coherence(), Coherence::SansIdentite);
    }

    #[test]
    fn the_default_mailbox_cannot_be_deleted() {
        // 🔴 C'est l'identité du compte : la supprimer laisserait quelqu'un capable de
        // se connecter dont l'adresse ne mène nulle part.
        let mut c = Compte::nouveau("remy", "standard");
        c.boites.push(boite("remy", true));
        c.boites.push(boite("photo", false));

        let e = c.peut_supprimer_boite("remy").unwrap_err().to_string();
        assert!(e.contains("remy@example.fr"), "{e}");
        assert!(e.contains("Change-la d'abord"), "la sortie de secours : {e}");

        c.peut_supprimer_boite("photo").expect("une boîte ordinaire se supprime");
    }

    #[test]
    fn purged_temporary_aliases_stop_counting() {
        // ⚠️ Ils ne coûtent plus rien au serveur. Les compter empêcherait d'en créer
        // de nouveaux après une année d'usage normal, sans raison technique.
        let mut b = boite("remy", true);
        let mut vieux = Alias::temporaire("ancien", T - 1000);
        vieux.actif = false; // purgé
        b.aliases.push(vieux);
        b.aliases.push(Alias::temporaire("actuel", T + 1000));
        b.aliases.push(Alias::permanent("contact"));

        let mut c = Compte::nouveau("remy", "standard");
        c.boites.push(b);

        let u = c.usage(T);
        assert_eq!(u.boites, 1);
        assert_eq!(u.aliases_permanents, 1);
        assert_eq!(u.aliases_temporaires, 1, "le purgé ne compte plus");
    }

    #[test]
    fn an_expired_but_still_active_alias_counts_and_is_reported() {
        // 🔴 Il consomme toujours du quota — puisqu'il existe encore chez Stalwart —
        // ET il trahit la promesse faite à l'utilisateur. Les deux à la fois.
        let mut b = boite("remy", true);
        b.aliases.push(Alias::temporaire("oublie", T - 86_400));

        let mut c = Compte::nouveau("remy", "standard");
        c.boites.push(b);

        assert_eq!(c.usage(T).aliases_temporaires, 1, "il existe encore");

        let rompues = c.promesses_rompues(T);
        assert_eq!(rompues.len(), 1);
        assert_eq!(rompues[0].1.local, "oublie");
    }

    #[test]
    fn a_username_that_would_fail_downstream_is_refused_here() {
        // ⚠️ Il devient une partie locale d'adresse ET un identifiant PocketID. Un nom
        // accepté ici et refusé plus loin laisserait un compte à moitié créé.
        valider_nom("remy").expect("simple");
        valider_nom("remy.durand").expect("point");
        valider_nom("remy-2").expect("tiret et chiffre");

        for mauvais in ["", "Remy", "remy@example.fr", ".remy", "remy-", "rémy", "a b"] {
            assert!(valider_nom(mauvais).is_err(), "« {mauvais} » aurait dû être refusé");
        }
    }

    #[test]
    fn quotas_and_the_account_model_agree() {
        // Le compte compte, le profil décide : les deux doivent parler du même chiffre.
        let mut c = Compte::nouveau("invite", "invite");
        c.boites.push(boite("invite", true));

        let p = Profil::invite();
        let e = p
            .autorise(&c.usage(T), Demande::Boite)
            .unwrap_err()
            .raison;
        assert!(e.contains("1/1"), "{e}");
    }
}
