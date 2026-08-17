//! Aliases de messagerie, permanents ou temporaires (§5bis.3).
//!
//! ## 🔴 Le piège central : Stalwart ne sait pas expirer un alias
//!
//! Un serveur de messagerie n'a aucune notion de durée de vie sur un alias. La
//! propriété `aliases` d'un compte est une simple liste : ce qui y est écrit y reste.
//!
//! Un alias « temporaire » n'est donc temporaire **que si quelque chose vient
//! réellement le supprimer**. Et c'est exactement le genre de promesse qui se rompt en
//! silence : on donne `achat-3f2a@example.fr` à un marchand en se disant qu'elle
//! expirera dans trente jours, la tâche de purge ne tourne pas — parce que le
//! controller est tombé, parce que Stalwart était injoignable ce jour-là — et l'adresse
//! reste vivante pour toujours. On croit avoir refermé une porte qui est restée ouverte.
//!
//! D'où [`Alias::etat`], qui distingue **trois** situations et non deux : encore
//! valide, expiré-et-supprimé, et 🔴 **expiré-mais-toujours-actif**. La troisième est
//! celle qui compte, et elle n'existerait pas si l'on se contentait de comparer une
//! date à l'heure courante.
//!
//! ## Pourquoi les temporaires existent
//!
//! Donner sa vraie adresse à chaque site marchand revient à leur donner un identifiant
//! commun qui les relie entre eux, et une cible permanente en cas de fuite. Un alias
//! jetable par usage coupe les deux : il se supprime sans toucher au compte, et la
//! fuite ne révèle qu'une adresse morte.

use serde::{Deserialize, Serialize};

/// La durée de vie d'un alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Duree {
    /// Ne disparaît que si on le supprime.
    Permanent,
    /// Doit être supprimé à cette date (horodatage Unix).
    ///
    /// ⚠️ « Doit », pas « sera » : c'est une intention que la purge doit honorer.
    Temporaire { expire_le: i64 },
}

/// Un alias tel qu'on le connaît.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alias {
    /// Partie locale seule : `achat-3f2a`, jamais l'adresse complète.
    pub local: String,
    pub duree: Duree,
    /// Est-il encore réellement présent chez Stalwart ?
    ///
    /// 🔴 C'est ce champ qui rend la distinction possible. Sans lui, un alias expiré
    /// et un alias expiré-mais-jamais-supprimé seraient indiscernables.
    pub actif: bool,
    /// À quoi il sert, pour s'en souvenir six mois plus tard.
    pub note: Option<String>,
}

/// L'état réel d'un alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Etat {
    /// Permanent et actif.
    Permanent,
    /// Temporaire, encore valide.
    Valide { restant_s: i64 },
    /// Temporaire, expiré, et **effectivement supprimé**. Le cas nominal.
    Expire,
    /// 🔴 Temporaire, expiré, et **TOUJOURS ACTIF**.
    ///
    /// La purge n'a pas fait son travail. L'adresse qu'on croyait fermée continue de
    /// recevoir — et c'est précisément l'inverse de ce qu'on avait demandé.
    ExpireMaisActif { depuis_s: i64 },
}

impl Alias {
    pub fn permanent(local: impl Into<String>) -> Self {
        Self {
            local: local.into(),
            duree: Duree::Permanent,
            actif: true,
            note: None,
        }
    }

    pub fn temporaire(local: impl Into<String>, expire_le: i64) -> Self {
        Self {
            local: local.into(),
            duree: Duree::Temporaire { expire_le },
            actif: true,
            note: None,
        }
    }

    pub fn avec_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// L'état réel, à l'instant `maintenant`.
    pub fn etat(&self, maintenant: i64) -> Etat {
        match self.duree {
            Duree::Permanent => Etat::Permanent,
            Duree::Temporaire { expire_le } => {
                let depasse = maintenant >= expire_le;
                match (depasse, self.actif) {
                    (false, _) => Etat::Valide {
                        restant_s: expire_le - maintenant,
                    },
                    // 🔴 Le cas qui justifie tout ce module.
                    (true, true) => Etat::ExpireMaisActif {
                        depuis_s: maintenant - expire_le,
                    },
                    (true, false) => Etat::Expire,
                }
            }
        }
    }

    /// Doit-il être supprimé maintenant ?
    pub fn a_purger(&self, maintenant: i64) -> bool {
        matches!(self.etat(maintenant), Etat::ExpireMaisActif { .. })
    }
}

impl Etat {
    /// Une adresse qu'on croyait fermée reçoit-elle encore ?
    pub fn trahit_la_promesse(&self) -> bool {
        matches!(self, Self::ExpireMaisActif { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Permanent => "permanent".into(),
            Self::Valide { restant_s } => format!("expire dans {}", duree_lisible(*restant_s)),
            Self::Expire => "expiré, supprimé".into(),
            Self::ExpireMaisActif { depuis_s } => format!(
                "🔴 EXPIRÉ depuis {} et TOUJOURS ACTIF — la purge n'a pas tourné, \
                 cette adresse reçoit encore",
                duree_lisible(*depuis_s)
            ),
        }
    }
}

fn duree_lisible(s: i64) -> String {
    let s = s.max(0);
    if s < 3600 {
        format!("{} min", s / 60)
    } else if s < 172_800 {
        format!("{} h", s / 3600)
    } else {
        format!("{} j", s / 86400)
    }
}

/// Les aliases à purger, dans l'ordre où on les traitera.
///
/// ⚠️ Les plus anciennement expirés d'abord : si la purge est interrompue à mi-chemin,
/// ce sont les promesses les plus anciennement rompues qu'on aura tenues en premier.
pub fn a_purger(aliases: &[Alias], maintenant: i64) -> Vec<&Alias> {
    let mut v: Vec<&Alias> = aliases.iter().filter(|a| a.a_purger(maintenant)).collect();
    v.sort_by_key(|a| match a.duree {
        Duree::Temporaire { expire_le } => expire_le,
        Duree::Permanent => i64::MAX,
    });
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_700_000_000;

    #[test]
    fn an_expired_alias_that_still_works_is_its_own_state() {
        // 🔴 LE point du module. Un alias temporaire n'est temporaire que si quelque
        // chose vient réellement le supprimer. Si la purge n'a pas tourné, l'adresse
        // qu'on croyait fermée reçoit encore — et c'est l'inverse de ce qu'on avait
        // demandé. Comparer une date à l'heure courante ne suffit PAS à le voir.
        let mut a = Alias::temporaire("achat-3f2a", T);
        a.actif = true;

        let e = a.etat(T + 86_400);
        assert_eq!(e, Etat::ExpireMaisActif { depuis_s: 86_400 });
        assert!(e.trahit_la_promesse());

        // Le même alias, effectivement supprimé : le cas nominal, sans alerte.
        a.actif = false;
        assert_eq!(a.etat(T + 86_400), Etat::Expire);
        assert!(!a.etat(T + 86_400).trahit_la_promesse());
    }

    #[test]
    fn the_message_says_the_address_still_receives() {
        // Dire « expiré » suffirait à rassurer à tort. Il faut dire que ça REÇOIT.
        let a = Alias::temporaire("x", T);
        let m = a.etat(T + 172_800).describe();
        assert!(m.contains("TOUJOURS ACTIF"), "{m}");
        assert!(m.contains("reçoit encore"), "{m}");
        assert!(m.contains("purge"), "la cause doit être nommée : {m}");
    }

    #[test]
    fn a_valid_alias_says_how_long_is_left() {
        let a = Alias::temporaire("x", T + 86_400);
        assert_eq!(a.etat(T), Etat::Valide { restant_s: 86_400 });
        assert!(!a.a_purger(T));
    }

    #[test]
    fn a_permanent_alias_is_never_purged() {
        let a = Alias::permanent("contact");
        assert_eq!(a.etat(T), Etat::Permanent);
        assert!(!a.a_purger(T + 10_000_000_000));
    }

    #[test]
    fn expiry_is_inclusive_of_its_own_instant() {
        // Pile à l'heure dite, l'alias est expiré. Le laisser une seconde de plus
        // serait arbitraire, et « expire à 14 h » doit vouloir dire 14 h.
        let a = Alias::temporaire("x", T);
        assert!(a.a_purger(T));
        assert!(!a.a_purger(T - 1));
    }

    #[test]
    fn the_oldest_broken_promise_is_purged_first() {
        // ⚠️ Si la purge est interrompue à mi-chemin, ce sont les adresses ouvertes
        // depuis le plus longtemps qu'on aura refermées en premier.
        let aliases = vec![
            Alias::temporaire("recent", T - 100),
            Alias::permanent("contact"),
            Alias::temporaire("ancien", T - 100_000),
            Alias::temporaire("futur", T + 100_000),
        ];

        let p = a_purger(&aliases, T);
        assert_eq!(
            p.iter().map(|a| a.local.as_str()).collect::<Vec<_>>(),
            vec!["ancien", "recent"]
        );
    }

    #[test]
    fn an_already_purged_alias_is_not_purged_twice() {
        let mut a = Alias::temporaire("x", T - 1000);
        a.actif = false;
        assert!(!a.a_purger(T), "déjà supprimé chez Stalwart");
    }
}
