//! Profils : ce qu'un utilisateur a le droit de créer (§5bis.3).
//!
//! ## Pourquoi un axe séparé des rôles d'API
//!
//! `hlb_types::Role` (Viewer / Operator / Admin) décide de ce qu'on peut faire **au
//! cluster** : installer, sauvegarder, détruire. C'est une autre question que « combien
//! de boîtes mail as-tu le droit d'ouvrir ». Un ami à qui l'on donne une adresse n'a
//! aucun accès au cluster ; l'administrateur du cluster n'a pas forcément besoin de
//! vingt boîtes.
//!
//! Confondre les deux obligerait à donner des droits d'exploitation pour accorder une
//! boîte de plus, ce qui est exactement le genre de glissement qui finit par tout
//! ouvrir à tout le monde.
//!
//! ## 🔴 Une limite atteinte doit dire QUI l'a posée
//!
//! « Quota dépassé » envoie chercher du côté du disque ou du serveur de messagerie. La
//! vraie information est : quelle limite, de quel profil, et qui peut la changer. Sans
//! ça, le message coûte une demi-heure à qui le reçoit.

use serde::{Deserialize, Serialize};

/// Ce qu'un profil autorise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profil {
    pub nom: String,
    /// Nombre maximal de boîtes, adresse par défaut **comprise**.
    ///
    /// ⚠️ Comprise, et non « en plus » : sinon `max_boites: 0` donnerait quand même
    /// une boîte, et la limite ne voudrait rien dire.
    pub max_boites: u32,
    /// Aliases permanents par boîte.
    pub max_aliases_permanents: u32,
    /// Aliases temporaires par boîte.
    ///
    /// Séparé des permanents : les jetables se créent au fil de l'eau, souvent par
    /// dizaines, et les compter ensemble ferait atteindre la limite des permanents
    /// sans que personne comprenne pourquoi.
    pub max_aliases_temporaires: u32,
    /// Durée de vie maximale d'un alias temporaire, en secondes.
    ///
    /// 🔴 Sans plafond, « temporaire » peut valoir dix ans, et la notion se vide de
    /// son sens sans que rien ne l'interdise.
    pub duree_max_s: i64,
    /// Quota d'espace par boîte, en octets. `None` = celui du serveur.
    pub quota_octets: Option<u64>,
}

impl Profil {
    /// Le profil d'un compte ordinaire.
    pub fn standard() -> Self {
        Self {
            nom: "standard".into(),
            max_boites: 3,
            max_aliases_permanents: 10,
            // Généreux : c'est l'usage qu'on veut encourager, un alias jetable par
            // marchand plutôt qu'une adresse unique donnée partout.
            max_aliases_temporaires: 50,
            duree_max_s: 365 * 86_400,
            quota_octets: Some(5 * 1024 * 1024 * 1024),
        }
    }

    /// Un invité : une seule boîte, pas d'alias permanent.
    pub fn invite() -> Self {
        Self {
            nom: "invite".into(),
            max_boites: 1,
            max_aliases_permanents: 0,
            max_aliases_temporaires: 5,
            duree_max_s: 30 * 86_400,
            quota_octets: Some(1024 * 1024 * 1024),
        }
    }

    /// Sans limite pratique.
    ///
    /// ⚠️ « Sans limite » reste un nombre : un profil dont les compteurs seraient
    /// vraiment infinis ne pourrait pas être affiché, ni comparé, ni testé.
    pub fn illimite() -> Self {
        Self {
            nom: "illimite".into(),
            max_boites: u32::MAX,
            max_aliases_permanents: u32::MAX,
            max_aliases_temporaires: u32::MAX,
            duree_max_s: i64::MAX,
            quota_octets: None,
        }
    }

    pub fn par_nom(nom: &str) -> Option<Self> {
        match nom.trim().to_lowercase().as_str() {
            "standard" => Some(Self::standard()),
            "invite" | "invité" | "guest" => Some(Self::invite()),
            "illimite" | "illimité" | "unlimited" => Some(Self::illimite()),
            _ => None,
        }
    }
}

/// Ce qu'on cherche à créer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Demande {
    Boite,
    AliasPermanent,
    AliasTemporaire { duree_s: i64 },
}

/// Ce qu'on possède déjà.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub boites: u32,
    pub aliases_permanents: u32,
    pub aliases_temporaires: u32,
}

/// Pourquoi c'est refusé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refus {
    pub raison: String,
}

impl std::fmt::Display for Refus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raison)
    }
}

impl Profil {
    /// Cette demande passe-t-elle ?
    ///
    /// 🔴 Le refus nomme la limite, le profil qui la pose, et la commande qui la
    /// change. « Quota dépassé » enverrait chercher du côté du disque ou du serveur de
    /// messagerie — c'est-à-dire nulle part.
    pub fn autorise(&self, usage: &Usage, demande: Demande) -> Result<(), Refus> {
        match demande {
            Demande::Boite => {
                if usage.boites >= self.max_boites {
                    return Err(Refus {
                        raison: format!(
                            "limite de boîtes atteinte : {}/{} pour le profil « {} ». \
                             Change de profil avec « hlb user profile <nom> --profil <autre> », \
                             ou supprime une boîte",
                            usage.boites, self.max_boites, self.nom
                        ),
                    });
                }
            }

            Demande::AliasPermanent => {
                if usage.aliases_permanents >= self.max_aliases_permanents {
                    return Err(Refus {
                        raison: format!(
                            "limite d'aliases permanents atteinte : {}/{} pour le profil \
                             « {} ». Un alias TEMPORAIRE reste possible ({} au maximum), \
                             et c'est souvent ce qu'on veut",
                            usage.aliases_permanents,
                            self.max_aliases_permanents,
                            self.nom,
                            self.max_aliases_temporaires
                        ),
                    });
                }
            }

            Demande::AliasTemporaire { duree_s } => {
                if usage.aliases_temporaires >= self.max_aliases_temporaires {
                    return Err(Refus {
                        raison: format!(
                            "limite d'aliases temporaires atteinte : {}/{} pour le profil \
                             « {} ». Les expirés déjà purgés ne comptent plus — \
                             « hlb user alias purge » les retire",
                            usage.aliases_temporaires, self.max_aliases_temporaires, self.nom
                        ),
                    });
                }

                if duree_s > self.duree_max_s {
                    return Err(Refus {
                        raison: format!(
                            "durée demandée trop longue : {} j, maximum {} j pour le \
                             profil « {} ». Au-delà, « temporaire » ne veut plus dire \
                             grand-chose — prends un alias permanent si c'est l'intention",
                            duree_s / 86_400,
                            self.duree_max_s / 86_400,
                            self.nom
                        ),
                    });
                }

                if duree_s <= 0 {
                    return Err(Refus {
                        raison: "durée nulle ou négative : l'alias serait expiré avant \
                                 d'exister, et la purge le supprimerait au premier passage"
                            .into(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_mailbox_counts_against_the_limit() {
        // ⚠️ Comprise, et non « en plus » : sinon `max_boites: 0` donnerait quand même
        // une boîte, et la limite ne voudrait rien dire.
        let p = Profil::invite();
        assert_eq!(p.max_boites, 1);

        let usage = Usage {
            boites: 1,
            ..Default::default()
        };
        assert!(
            p.autorise(&usage, Demande::Boite).is_err(),
            "l'invité a déjà sa boîte par défaut : la seconde est refusée"
        );
    }

    #[test]
    fn a_refusal_names_the_limit_the_profile_and_the_way_out() {
        // 🔴 « Quota dépassé » enverrait chercher du côté du disque ou du serveur de
        // messagerie, c'est-à-dire nulle part.
        let p = Profil::invite();
        let usage = Usage {
            boites: 1,
            ..Default::default()
        };
        let e = p.autorise(&usage, Demande::Boite).unwrap_err().raison;

        assert!(e.contains("1/1"), "la limite chiffrée : {e}");
        assert!(e.contains("invite"), "le profil qui la pose : {e}");
        assert!(e.contains("hlb user profile"), "la sortie de secours : {e}");
    }

    #[test]
    fn permanent_and_temporary_aliases_are_counted_apart() {
        // Les jetables se créent par dizaines. Les compter avec les permanents ferait
        // atteindre la limite des permanents sans que personne comprenne pourquoi.
        let p = Profil::standard();
        let usage = Usage {
            boites: 1,
            aliases_permanents: 0,
            aliases_temporaires: 49,
        };
        assert!(p.autorise(&usage, Demande::AliasPermanent).is_ok());
        assert!(p
            .autorise(&usage, Demande::AliasTemporaire { duree_s: 86_400 })
            .is_ok());

        let plein = Usage {
            aliases_temporaires: 50,
            ..usage
        };
        assert!(plein.aliases_temporaires.eq(&p.max_aliases_temporaires));
        assert!(p
            .autorise(&plein, Demande::AliasTemporaire { duree_s: 86_400 })
            .is_err());
        assert!(
            p.autorise(&plein, Demande::AliasPermanent).is_ok(),
            "les permanents ne sont pas touchés par le plafond des temporaires"
        );
    }

    #[test]
    fn a_permanent_refusal_suggests_the_temporary_route() {
        // Refuser sans proposer l'alternative disponible pousse à demander un
        // changement de profil pour un besoin qui n'en réclamait pas.
        let p = Profil::invite();
        let usage = Usage {
            aliases_permanents: 0,
            ..Default::default()
        };
        let e = p
            .autorise(&usage, Demande::AliasPermanent)
            .unwrap_err()
            .raison;
        assert!(e.contains("TEMPORAIRE"), "{e}");
    }

    #[test]
    fn a_temporary_alias_cannot_outlive_the_notion() {
        // 🔴 Sans plafond, « temporaire » peut valoir dix ans, et le mot se vide de son
        // sens sans que rien ne l'interdise.
        let p = Profil::invite();
        let usage = Usage::default();

        assert!(p
            .autorise(
                &usage,
                Demande::AliasTemporaire {
                    duree_s: 30 * 86_400
                }
            )
            .is_ok());

        let e = p
            .autorise(
                &usage,
                Demande::AliasTemporaire {
                    duree_s: 3650 * 86_400,
                },
            )
            .unwrap_err()
            .raison;
        assert!(e.contains("30 j"), "la limite doit être dite : {e}");
        assert!(e.contains("permanent"), "l'alternative honnête : {e}");
    }

    #[test]
    fn a_zero_duration_alias_is_refused_rather_than_created_dead() {
        // Créé puis supprimé au premier passage de la purge : l'utilisateur croirait
        // l'avoir eu, et l'adresse ne marcherait jamais.
        let e = Profil::standard()
            .autorise(&Usage::default(), Demande::AliasTemporaire { duree_s: 0 })
            .unwrap_err()
            .raison;
        assert!(e.contains("expiré avant d'exister"), "{e}");
    }

    #[test]
    fn the_unlimited_profile_still_refuses_nonsense() {
        // « Sans limite » ne veut pas dire « accepte n'importe quoi » : une durée
        // négative reste une erreur de saisie.
        let p = Profil::illimite();
        assert!(p
            .autorise(&Usage::default(), Demande::AliasTemporaire { duree_s: -1 })
            .is_err());
        assert!(p
            .autorise(
                &Usage {
                    boites: 9999,
                    ..Default::default()
                },
                Demande::Boite
            )
            .is_ok());
    }

    #[test]
    fn profiles_are_read_from_several_spellings() {
        assert_eq!(
            Profil::par_nom("standard").map(|p| p.nom),
            Some("standard".into())
        );
        assert_eq!(
            Profil::par_nom("INVITÉ").map(|p| p.nom),
            Some("invite".into())
        );
        assert_eq!(
            Profil::par_nom("unlimited").map(|p| p.nom),
            Some("illimite".into())
        );
        assert!(Profil::par_nom("nimportequoi").is_none());
    }
}
