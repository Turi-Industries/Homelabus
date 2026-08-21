//! « Si je perds tout maintenant, je récupère quoi, et de quand ? » (lot 9.2)
//!
//! ## Pourquoi ce calcul existe
//!
//! Toutes les pièces de la réponse existaient déjà — âge par destination, nombre de
//! copies à jour, âge de la dernière vérification, fraîcheur des exercices de reprise,
//! fenêtre PITR — mais **dispersées sur quatre écrans**. Personne ne fait la somme de
//! tête, et c'est pourtant la seule question qui compte le jour venu.
//!
//! ## 🔴 Deux chiffres, pas un
//!
//! - **RPO** : combien de données on perdrait. C'est l'âge de la sauvegarde la plus
//!   récente **qui protège vraiment** — donc sur une destination à jour, pas sur celle
//!   qui a échoué douze fois.
//! - **Confiance** : ce qu'on sait de cette sauvegarde. Une copie fraîche jamais
//!   restaurée est une hypothèse, pas une garantie (§8.3).
//!
//! Les confondre donnerait « RPO de 2 h » pour une sauvegarde que personne n'a jamais
//! réussi à relire.

use crate::destination::{Couverture, Etat};
use crate::drill::Readiness;

/// Ce qu'on récupérerait, et avec quelle confiance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restaurabilite {
    pub app: String,
    /// Secondes de données qu'on perdrait. `None` = **rien à restaurer**.
    ///
    /// ⚠️ Distinct d'un RPO très grand : `None` veut dire qu'aucune copie n'existe,
    /// nulle part. Les confondre ferait afficher « RPO : 3 mois » pour une app qui n'a
    /// jamais été sauvegardée.
    pub rpo_s: Option<i64>,
    /// Combien de copies protègent réellement (le chiffre du 3-2-1).
    pub copies: usize,
    /// 🔴 L'âge de la copie périmée la plus RÉCENTE, quand il n'y a aucune copie à jour.
    ///
    /// « Aucune copie à jour » recouvre deux situations opposées : jamais sauvegardée
    /// (rien n'existe, `None`) et sauvegardes périmées (des copies existent, elles
    /// datent). Elles ne se réparent pas pareil — l'une demande de configurer une
    /// destination, l'autre de comprendre pourquoi celle qui existe a cessé de servir.
    pub perimee_depuis_s: Option<i64>,
    /// Âge de la dernière vérification par restauration réelle. `None` = jamais.
    pub verifiee_il_y_a_s: Option<i64>,
    /// Le point de restauration le plus ancien atteignable, via PITR.
    ///
    /// `None` quand l'app n'a pas de journalisation continue : on ne peut alors
    /// restaurer qu'aux instants des sauvegardes, pas entre elles.
    pub pitr_profondeur_s: Option<i64>,
    /// Les exercices de reprise sont-ils à jour ?
    ///
    /// ⚠️ On réutilise `drill::Readiness` plutôt que d'en refaire un jumeau : deux
    /// types portant le même jugement finiraient par répondre différemment à la même
    /// question, et c'est l'écran de sauvegarde qui les afficherait côte à côte.
    pub exercices: Readiness,
}

/// L'état des exercices de restauration (§8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtatExercices {
    AJour {
        jours: i64,
    },
    Du {
        jours: i64,
    },
    Perime {
        jours: i64,
    },
    /// 🔴 Jamais exercé : on ne sait pas si une restauration marche.
    Jamais,
}

/// Le niveau de confiance qu'on peut accorder à la restauration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confiance {
    /// 🔴 Rien à restaurer, ou rien qui ait jamais été relu.
    Aucune,
    /// Des copies existent, mais personne n'a vérifié qu'elles se restaurent.
    Suppose,
    /// Une restauration a réussi, mais il y a longtemps.
    Ancienne,
    /// Restauration vérifiée récemment, plusieurs copies.
    Verifiee,
}

impl Confiance {
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Aucune => "aucune : rien ne prouve qu'on récupérerait quoi que ce soit",
            Self::Suppose => "supposée : des copies existent, aucune n'a jamais été relue",
            Self::Ancienne => "ancienne : la dernière restauration réussie remonte à loin",
            Self::Verifiee => "vérifiée : une restauration a réussi récemment",
        }
    }
}

/// Au-delà, une vérification ne rassure plus (§8.3 : exercice mensuel).
pub const VERIFICATION_PERIMEE_S: i64 = 45 * 86_400;

impl Restaurabilite {
    /// Le calcul, à partir de ce que l'état sait déjà.
    pub fn calculer(
        couverture: &Couverture,
        verifiee_il_y_a_s: Option<i64>,
        pitr_profondeur_s: Option<i64>,
        exercices: Readiness,
    ) -> Self {
        // 🔴 Le RPO se mesure sur les destinations À JOUR uniquement. Prendre la plus
        // récente toutes destinations confondues donnerait le RPO d'une copie périmée
        // — c'est-à-dire un chiffre rassurant tiré d'une sauvegarde qui ne protège
        // plus.
        let rpo_s = couverture
            .par_destination
            .iter()
            .filter_map(|(_, e)| match e {
                Etat::Frais { age_s } => Some(*age_s),
                // Une destination périmée ou jamais servie ne compte pas.
                Etat::Perime { .. } | Etat::Jamais => None,
            })
            .min();

        // La plus récente des périmées : elle ne protège plus, mais son existence
        // change entièrement le diagnostic et le remède.
        let perimee_depuis_s = (rpo_s.is_none())
            .then(|| {
                couverture
                    .par_destination
                    .iter()
                    .filter_map(|(_, e)| match e {
                        Etat::Perime { age_s } => Some(*age_s),
                        Etat::Frais { .. } | Etat::Jamais => None,
                    })
                    .min()
            })
            .flatten();

        Self {
            app: couverture.app.clone(),
            rpo_s,
            perimee_depuis_s,
            copies: couverture.copies_a_jour(),
            verifiee_il_y_a_s,
            pitr_profondeur_s,
            exercices,
        }
    }

    /// La confiance qu'on peut y accorder.
    pub fn confiance(&self) -> Confiance {
        // Rien à restaurer : la question de la confiance ne se pose même pas.
        if self.rpo_s.is_none() || self.copies == 0 {
            return Confiance::Aucune;
        }
        match self.verifiee_il_y_a_s {
            // 🔴 Jamais relue : une sauvegarde jamais restaurée est une hypothèse. Le
            // dire « supposé » plutôt que « bon » est tout l'objet du §8.3.
            None => Confiance::Suppose,
            Some(age) if age > VERIFICATION_PERIMEE_S => Confiance::Ancienne,
            Some(_) if self.copies >= 2 => Confiance::Verifiee,
            // Une seule copie, même vérifiée : la perte de cette destination emporte
            // tout. Ce n'est pas le même niveau de confiance.
            Some(_) => Confiance::Ancienne,
        }
    }

    /// La réponse en une phrase.
    pub fn verdict(&self) -> String {
        let Some(rpo) = self.rpo_s else {
            // 🔴 Les deux situations opposées, nommées séparément. « AUCUNE copie »
            // affiché à côté d'une destination datée de trois semaines se lit comme une
            // contradiction, et on finit par douter de tout l'écran.
            return match self.perimee_depuis_s {
                Some(age) => format!(
                    "AUCUNE copie à jour : la plus récente date de {}, et les \
                     sauvegardes ont cessé de réussir depuis.",
                    humaniser(age)
                ),
                None => "AUCUNE restauration possible : cette application n'a JAMAIS \
                         été sauvegardée."
                    .to_string(),
            };
        };

        let base = format!(
            "on perdrait environ {} de données, depuis {}",
            humaniser(rpo),
            match self.copies {
                1 => "l'unique copie à jour".to_string(),
                n => format!("{n} copies à jour"),
            }
        );

        match self.pitr_profondeur_s {
            // La journalisation continue change la nature de la réponse : on peut viser
            // un instant, pas seulement une sauvegarde.
            Some(p) => format!(
                "{base}. Restauration possible à n'importe quel instant des {} passés.",
                humaniser(p)
            ),
            None => format!("{base}. Restauration possible aux instants des sauvegardes."),
        }
    }

    /// Ce qu'il faudrait faire pour être tranquille.
    ///
    /// 🔴 Rendu dans l'ordre d'urgence, et vide quand tout va bien : une liste de
    /// conseils affichée en permanence cesse d'être lue.
    pub fn remedes(&self) -> Vec<String> {
        let mut v = Vec::new();

        if self.rpo_s.is_none() {
            // Le remède suit le diagnostic : configurer ce qui n'existe pas, ou
            // comprendre pourquoi ce qui existe a cessé de servir.
            v.push(match self.perimee_depuis_s {
                Some(_) => "comprendre pourquoi les sauvegardes échouent : « hlb backup \
                            status » nomme la destination et son nombre d'échecs \
                            consécutifs"
                    .to_string(),
                None => "configurer une sauvegarde : « hlb backup dest add <nom> \
                         --location <chemin> --apply »"
                    .to_string(),
            });
            // Inutile de conseiller de vérifier une sauvegarde qui n'existe pas.
            return v;
        }

        if self.copies < 2 {
            v.push(
                "ajouter une seconde destination : une copie unique disparaît avec la \
                 machine qui la porte"
                    .to_string(),
            );
        }

        match self.verifiee_il_y_a_s {
            None => v.push(
                "vérifier une restauration : « hlb backup verify <app> » — une \
                 sauvegarde jamais relue est une hypothèse"
                    .to_string(),
            ),
            Some(age) if age > VERIFICATION_PERIMEE_S => v.push(format!(
                "revérifier une restauration : la dernière remonte à {}",
                humaniser(age)
            )),
            Some(_) => {}
        }

        if matches!(self.exercices, Readiness::Never | Readiness::Overdue { .. }) {
            v.push(
                "lancer un exercice de reprise : « hlb dr exercise » — c'est le seul \
                 indicateur fiable"
                    .to_string(),
            );
        }

        v
    }
}

/// Une durée, en gros.
fn humaniser(s: i64) -> String {
    match s {
        s if s < 90 => format!("{s} s"),
        s if s < 5_400 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3_600),
        s => format!("{} j", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::Couverture;

    fn couverture(app: &str, dests: Vec<(&str, Etat)>) -> Couverture {
        Couverture {
            app: app.into(),
            par_destination: dests.into_iter().map(|(n, e)| (n.to_string(), e)).collect(),
        }
    }

    #[test]
    fn the_rpo_ignores_destinations_that_no_longer_protect() {
        // 🔴 Le cœur du calcul : une destination périmée depuis trois semaines ne doit
        // PAS fournir le RPO. Sinon on afficherait « 2 h » en se fondant sur une copie
        // qui ne protège plus.
        let c = couverture(
            "immich",
            vec![
                ("nas", Etat::Frais { age_s: 7_200 }),
                ("offsite", Etat::Perime { age_s: 1_800 }),
            ],
        );
        let r = Restaurabilite::calculer(&c, Some(86_400), None, Readiness::Ready { days: 3 });
        assert_eq!(r.rpo_s, Some(7_200), "le périmé a été pris en compte");
    }

    #[test]
    fn nothing_to_restore_is_not_a_very_old_rpo() {
        // ⚠️ « Aucune copie » et « RPO de trois mois » se réparent différemment, et les
        // confondre ferait chercher pourquoi la sauvegarde est lente au lieu de la
        // configurer.
        let c = couverture("seafile", vec![("nas", Etat::Jamais)]);
        let r = Restaurabilite::calculer(&c, None, None, Readiness::Never);

        assert_eq!(r.rpo_s, None);
        assert_eq!(r.confiance(), Confiance::Aucune);
        assert!(r.verdict().contains("JAMAIS"), "{}", r.verdict());
        // Et le remède est de configurer, pas de vérifier.
        assert!(r.remedes()[0].contains("configurer"), "{:?}", r.remedes());
        assert_eq!(
            r.remedes().len(),
            1,
            "aucun conseil inutile : {:?}",
            r.remedes()
        );
    }

    #[test]
    fn stale_copies_are_not_the_same_diagnosis_as_no_copies_at_all() {
        // 🔴 Le piège du CLAUDE.md, transposé au verdict : « AUCUNE copie » affiché à
        // côté d'une destination datée de trois semaines se lit comme une
        // contradiction. Et les deux ne se réparent pas pareil.
        let jamais = couverture("neuve", vec![("nas", Etat::Jamais)]);
        let perimee = couverture(
            "abandonnee",
            vec![
                ("nas", Etat::Perime { age_s: 21 * 86_400 }),
                ("offsite", Etat::Perime { age_s: 30 * 86_400 }),
            ],
        );

        let a = Restaurabilite::calculer(&jamais, None, None, Readiness::Never);
        let b = Restaurabilite::calculer(&perimee, None, None, Readiness::Never);

        // Toutes deux sans copie à jour, donc toutes deux sans RPO…
        assert_eq!(a.rpo_s, None);
        assert_eq!(b.rpo_s, None);
        assert_eq!(a.confiance(), Confiance::Aucune);
        assert_eq!(b.confiance(), Confiance::Aucune);

        // …mais elles ne DISENT pas la même chose, et ne conseillent pas la même chose.
        assert!(a.verdict().contains("JAMAIS"), "{}", a.verdict());
        assert!(b.verdict().contains("21 j"), "{}", b.verdict());
        assert_ne!(a.verdict(), b.verdict());
        assert!(a.remedes()[0].contains("configurer"), "{:?}", a.remedes());
        assert!(b.remedes()[0].contains("échouent"), "{:?}", b.remedes());
    }

    #[test]
    fn a_fresh_backup_never_restored_is_only_supposed() {
        // 🔴 Le point du §8.3 : une sauvegarde jamais relue est une hypothèse, pas une
        // garantie. L'afficher comme « bonne » est exactement le mensonge qu'on évite.
        let c = couverture(
            "gitea",
            vec![
                ("nas", Etat::Frais { age_s: 3_600 }),
                ("offsite", Etat::Frais { age_s: 7_200 }),
            ],
        );
        let r = Restaurabilite::calculer(&c, None, None, Readiness::Ready { days: 2 });

        assert_eq!(r.copies, 2);
        assert_eq!(r.confiance(), Confiance::Suppose);
        assert!(r.confiance().describe().contains("jamais été relue"));
        assert!(r.remedes().iter().any(|x| x.contains("vérifier")));
    }

    #[test]
    fn one_verified_copy_is_not_as_good_as_two() {
        // La perte de cette unique destination emporte tout, vérifiée ou non.
        let une = couverture("gitea", vec![("nas", Etat::Frais { age_s: 600 })]);
        let deux = couverture(
            "gitea",
            vec![
                ("nas", Etat::Frais { age_s: 600 }),
                ("offsite", Etat::Frais { age_s: 900 }),
            ],
        );

        let r1 = Restaurabilite::calculer(&une, Some(86_400), None, Readiness::Ready { days: 1 });
        let r2 = Restaurabilite::calculer(&deux, Some(86_400), None, Readiness::Ready { days: 1 });

        assert!(r1.confiance() < r2.confiance());
        assert_eq!(r2.confiance(), Confiance::Verifiee);
        assert!(r1
            .remedes()
            .iter()
            .any(|x| x.contains("seconde destination")));
    }

    #[test]
    fn an_old_verification_downgrades_confidence() {
        let c = couverture(
            "gitea",
            vec![
                ("nas", Etat::Frais { age_s: 600 }),
                ("offsite", Etat::Frais { age_s: 900 }),
            ],
        );
        let r = Restaurabilite::calculer(
            &c,
            Some(VERIFICATION_PERIMEE_S + 86_400),
            None,
            Readiness::Ready { days: 1 },
        );
        assert_eq!(r.confiance(), Confiance::Ancienne);
        assert!(r.remedes().iter().any(|x| x.contains("revérifier")));
    }

    #[test]
    fn continuous_archiving_changes_what_the_answer_means() {
        // Sans PITR, on restaure aux instants des sauvegardes. Avec, à n'importe quel
        // instant — c'est une différence de nature, pas de degré.
        let c = couverture("postgres", vec![("nas", Etat::Frais { age_s: 300 })]);

        let sans = Restaurabilite::calculer(&c, Some(3_600), None, Readiness::Ready { days: 1 });
        assert!(sans.verdict().contains("aux instants des sauvegardes"));

        let avec = Restaurabilite::calculer(
            &c,
            Some(3_600),
            Some(7 * 86_400),
            Readiness::Ready { days: 1 },
        );
        assert!(
            avec.verdict().contains("n'importe quel instant"),
            "{}",
            avec.verdict()
        );
    }

    #[test]
    fn a_healthy_app_gets_no_advice_at_all() {
        // 🔴 Une liste de conseils affichée en permanence cesse d'être lue.
        let c = couverture(
            "gitea",
            vec![
                ("nas", Etat::Frais { age_s: 600 }),
                ("offsite", Etat::Frais { age_s: 900 }),
            ],
        );
        let r = Restaurabilite::calculer(&c, Some(86_400), None, Readiness::Ready { days: 3 });
        assert!(r.remedes().is_empty(), "{:?}", r.remedes());
    }

    #[test]
    fn never_drilled_is_named_as_a_remedy() {
        // Un exercice jamais fait est le seul indicateur fiable qui manque.
        let c = couverture(
            "gitea",
            vec![
                ("nas", Etat::Frais { age_s: 600 }),
                ("offsite", Etat::Frais { age_s: 900 }),
            ],
        );
        let r = Restaurabilite::calculer(&c, Some(86_400), None, Readiness::Never);
        assert!(r.remedes().iter().any(|x| x.contains("exercice")));
    }
}
