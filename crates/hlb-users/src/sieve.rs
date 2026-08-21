//! Génération des règles de tri Sieve (§5bis.3).
//!
//! ## Ce que ça résout
//!
//! Un alias par destinataire ne sert à rien si tout arrive en vrac dans la boîte de
//! réception : on sait qu'on a cinquante adresses, on ne voit pas laquelle reçoit
//! quoi. Le tri automatique est ce qui rend l'**attribution** visible — le seul vrai
//! bénéfice du dispositif. Ouvrir le dossier `fnac` et y trouver de la publicité pour
//! des matelas dit immédiatement qui a vendu l'adresse.
//!
//! ## 🔴 Le nom du dossier appartient à l'utilisateur, pas au générateur
//!
//! Il serait tentant de dériver le dossier de l'indice sans rien demander. Ce serait
//! une erreur : les gens rangent leur courrier selon **leur** logique, pas selon la
//! nôtre. Quelqu'un qui veut tout mettre dans `Achats/2026` plutôt qu'un dossier par
//! marchand a raison, et un système qui décide à sa place produit une arborescence
//! qu'il faut ensuite défaire à la main.
//!
//! [`Regle::dossier`] est donc **fourni**, avec un défaut seulement quand rien n'est
//! dit. Et la règle générée reste lisible et modifiable dans Roundcube — une règle
//! qu'on ne peut pas inspecter est une règle à laquelle on ne fait pas confiance.
//!
//! ## 🔴 Ne JAMAIS écraser ce que l'utilisateur a écrit
//!
//! Un script Sieve est un fichier unique par compte. Le réécrire entièrement
//! effacerait les règles écrites à la main — des heures de réglages, perdues sans un
//! avertissement, pour une simple création d'alias.
//!
//! D'où le bloc **délimité** : Homelabus n'écrit qu'entre ses deux marqueurs et
//! recopie le reste tel quel. Voir [`fusionner`].

use serde::{Deserialize, Serialize};

/// Début du bloc géré. Tout ce qui est **hors** de ce bloc appartient à l'utilisateur.
pub const DEBUT: &str = "# >>> Homelabus — début du bloc géré. Ne pas modifier à la main.";
/// Fin du bloc géré.
pub const FIN: &str = "# <<< Homelabus — fin du bloc géré.";

/// Une règle de tri.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Regle {
    /// La partie locale de l'alias concerné.
    pub alias: String,
    /// Le dossier de destination, tel que l'utilisateur le veut.
    ///
    /// ⚠️ Les séparateurs sont des `/` : Stalwart les traduit dans la hiérarchie IMAP.
    pub dossier: String,
    /// Faut-il aussi arrêter le traitement des règles suivantes ?
    ///
    /// Vrai par défaut : sans `stop`, un message correspondant à deux règles serait
    /// classé deux fois — et apparaîtrait en double dans le client.
    pub stop: bool,
}

impl Regle {
    /// Une règle qui range l'alias dans le dossier demandé.
    pub fn new(alias: impl Into<String>, dossier: impl Into<String>) -> Self {
        Self {
            alias: alias.into(),
            dossier: dossier.into(),
            stop: true,
        }
    }

    /// Le dossier par défaut, quand l'utilisateur n'en donne pas.
    ///
    /// ⚠️ C'est un DÉFAUT, pas une règle : l'indice du site est le meilleur point de
    /// départ, et il reste modifiable. Sans indice, on ne devine rien — mieux vaut la
    /// boîte de réception qu'un dossier `sans-nom` que personne n'ira regarder.
    pub fn dossier_par_defaut(indice: Option<&str>) -> Option<String> {
        indice
            .map(str::trim)
            .filter(|i| !i.is_empty())
            .map(|i| format!("Alias/{i}"))
    }
}

/// Échappe une chaîne pour une chaîne littérale Sieve.
///
/// 🔴 Un nom de dossier vient de l'utilisateur. Un guillemet non échappé casserait la
/// syntaxe du script — et Stalwart REFUSERAIT tout le script, y compris les règles
/// écrites à la main. Une seule apostrophe mal placée ferait donc perdre le tri de
/// toutes les adresses d'un coup.
pub fn echapper(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Le bloc géré, à insérer dans le script du compte.
pub fn bloc(regles: &[Regle]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();

    let _ = writeln!(s, "{DEBUT}");
    let _ = writeln!(
        s,
        "# Ces règles rangent le courrier de chaque alias. Modifie plutôt le dossier"
    );
    let _ = writeln!(
        s,
        "# via « hlb user alias folder », sinon la prochaine génération l'écrasera."
    );

    if regles.is_empty() {
        let _ = writeln!(s, "# (aucun alias trié pour l'instant)");
    }

    for r in regles {
        let _ = writeln!(s);
        // ⚠️ `:matches` sur `to` et non `:is` sur l'adresse complète : un message peut
        // arriver avec l'alias en copie, ou avec un affichage « Nom <alias@dom> ».
        // Comparer l'adresse entière raterait ces cas, et la règle ne se
        // déclencherait jamais — sans erreur nulle part.
        let _ = writeln!(
            s,
            "if address :localpart :is \"to\" \"{}\" {{",
            echapper(&r.alias)
        );
        let _ = writeln!(s, "    fileinto :create \"{}\";", echapper(&r.dossier));
        if r.stop {
            // Sans `stop`, un message correspondant à deux règles serait classé deux
            // fois et apparaîtrait en double dans le client.
            let _ = writeln!(s, "    stop;");
        }
        let _ = writeln!(s, "}}");
    }

    let _ = writeln!(s, "{FIN}");
    s
}

/// Insère ou remplace le bloc géré dans un script existant.
///
/// 🔴 **Ne touche jamais à ce qui est hors du bloc.** Un script Sieve est un fichier
/// unique par compte : le réécrire entièrement effacerait les règles écrites à la
/// main, sans un avertissement, pour une simple création d'alias.
pub fn fusionner(script_existant: &str, regles: &[Regle]) -> String {
    let nouveau = bloc(regles);

    match (script_existant.find(DEBUT), script_existant.find(FIN)) {
        (Some(d), Some(f)) if f > d => {
            let avant = &script_existant[..d];
            let apres = &script_existant[f + FIN.len()..];
            // On retire le saut de ligne qui suivait l'ancien marqueur de fin, sinon
            // les lignes vides s'accumulent à chaque génération.
            let apres = apres.strip_prefix('\n').unwrap_or(apres);
            format!("{avant}{nouveau}{apres}")
        }
        _ => {
            // Pas de bloc : on l'ajoute à la FIN. En tête, il capterait les messages
            // avant les règles de l'utilisateur, ce qui changerait le comportement de
            // son script sans qu'il l'ait demandé.
            let base = script_existant.trim_end();
            if base.is_empty() {
                format!("require [\"fileinto\", \"mailbox\"];\n\n{nouveau}")
            } else {
                let mut s = format!("{base}\n\n{nouveau}");
                // ⚠️ `fileinto` et `:create` exigent leurs extensions. Sans le
                // `require`, Stalwart refuse le script ENTIER — donc aussi les règles
                // de l'utilisateur, qui marchaient jusque-là.
                if !base.contains("fileinto") {
                    s = format!("require [\"fileinto\", \"mailbox\"];\n{s}");
                }
                s
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_written_rules_are_never_lost() {
        // 🔴 LE point du module. Un script Sieve est un fichier unique par compte :
        // le réécrire entièrement effacerait des heures de réglages, sans un
        // avertissement, pour une simple création d'alias.
        let existant = "require [\"fileinto\"];\n\
                        # ma règle à moi\n\
                        if header :contains \"subject\" \"facture\" {\n\
                        \x20   fileinto \"Compta\";\n\
                        }\n";

        let fusionne = fusionner(existant, &[Regle::new("fnac-a1b2", "Alias/fnac")]);

        assert!(fusionne.contains("# ma règle à moi"), "{fusionne}");
        assert!(fusionne.contains("\"Compta\""), "{fusionne}");
        assert!(fusionne.contains("fnac-a1b2"), "{fusionne}");
    }

    #[test]
    fn regenerating_replaces_only_the_managed_block() {
        // Deux générations de suite ne doivent pas empiler les blocs, ni faire
        // grossir le script à chaque alias créé.
        let base = "# perso\nif true { keep; }\n";
        let un = fusionner(base, &[Regle::new("a", "A")]);
        let deux = fusionner(&un, &[Regle::new("b", "B")]);

        assert_eq!(deux.matches(DEBUT).count(), 1, "{deux}");
        assert_eq!(deux.matches(FIN).count(), 1, "{deux}");
        assert!(deux.contains("# perso"), "le hors-bloc survit : {deux}");
        assert!(deux.contains("\"b\""), "{deux}");
        assert!(
            !deux.contains("\"a\""),
            "l'ancien bloc est REMPLACÉ : {deux}"
        );
    }

    #[test]
    fn the_managed_block_goes_last_not_first() {
        // En tête, il capterait les messages AVANT les règles de l'utilisateur, ce qui
        // changerait le comportement de son script sans qu'il l'ait demandé.
        let base = "require [\"fileinto\"];\nif true { fileinto \"Tout\"; stop; }\n";
        let f = fusionner(base, &[Regle::new("x", "X")]);

        let pos_user = f.find("\"Tout\"").expect("règle utilisateur");
        let pos_bloc = f.find(DEBUT).expect("bloc géré");
        assert!(pos_user < pos_bloc, "le bloc géré doit venir APRÈS : {f}");
    }

    #[test]
    fn a_quote_in_a_folder_name_cannot_break_the_whole_script() {
        // 🔴 Un nom de dossier vient de l'utilisateur. Un guillemet non échappé
        // casserait la syntaxe, et Stalwart refuserait le script ENTIER — y compris
        // les règles écrites à la main, qui marchaient jusque-là.
        let r = Regle::new("x", "Dossier \"spécial\"");
        let b = bloc(&[r]);

        assert!(b.contains(r#"\"spécial\""#), "{b}");
        // Le nombre de guillemets non échappés doit rester pair, sinon la chaîne
        // n'est pas fermée.
        let non_echappes = b.matches('"').count() - b.matches(r#"\""#).count() * 2;
        assert_eq!(non_echappes % 2, 0, "guillemets déséquilibrés : {b}");
    }

    #[test]
    fn a_backslash_is_escaped_too() {
        assert_eq!(echapper(r"a\b"), r"a\\b");
        assert_eq!(echapper(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn the_require_is_added_when_missing() {
        // ⚠️ `fileinto` et `:create` exigent leurs extensions. Sans le `require`,
        // Stalwart refuse le script ENTIER — donc aussi les règles de l'utilisateur.
        let f = fusionner("# rien\n", &[Regle::new("x", "X")]);
        assert!(f.starts_with("require ["), "{f}");
        assert!(f.contains("fileinto"), "{f}");

        // Et il n'est pas ajouté deux fois s'il y était déjà.
        let deja = fusionner("require [\"fileinto\"];\n", &[Regle::new("x", "X")]);
        assert_eq!(deja.matches("require [").count(), 1, "{deja}");
    }

    #[test]
    fn an_empty_script_still_gets_its_require() {
        let f = fusionner("", &[Regle::new("x", "X")]);
        assert!(f.starts_with("require ["), "{f}");
        assert!(f.contains(DEBUT));
    }

    #[test]
    fn rules_match_the_local_part_not_the_whole_address() {
        // ⚠️ Un message peut arriver avec l'alias en COPIE, ou sous la forme
        // « Nom <alias@domaine> ». Comparer l'adresse entière raterait ces cas, et la
        // règle ne se déclencherait jamais — sans erreur nulle part.
        let b = bloc(&[Regle::new("fnac-a1b2", "Alias/fnac")]);
        assert!(b.contains(":localpart"), "{b}");
        assert!(
            !b.contains("@"),
            "l'adresse complète n'a rien à faire ici : {b}"
        );
    }

    #[test]
    fn a_stopless_rule_can_be_asked_for() {
        // Par défaut on met `stop` — sinon un message correspondant à deux règles
        // serait classé deux fois et apparaîtrait en double dans le client.
        assert!(bloc(&[Regle::new("x", "X")]).contains("stop;"));

        let mut r = Regle::new("x", "X");
        r.stop = false;
        assert!(!bloc(&[r]).contains("stop;"));
    }

    #[test]
    fn the_default_folder_is_only_a_suggestion() {
        // 🔴 Les gens rangent leur courrier selon LEUR logique. Le défaut part de
        // l'indice du site, et reste modifiable.
        assert_eq!(
            Regle::dossier_par_defaut(Some("fnac")),
            Some("Alias/fnac".into())
        );
        // Sans indice, on ne devine rien : mieux vaut la boîte de réception qu'un
        // dossier « sans-nom » que personne n'ira regarder.
        assert_eq!(Regle::dossier_par_defaut(None), None);
        assert_eq!(Regle::dossier_par_defaut(Some("  ")), None);
    }

    #[test]
    fn an_empty_rule_set_still_produces_a_valid_block() {
        // Supprimer le dernier alias ne doit pas laisser un bloc mal formé, ni faire
        // échouer le script entier.
        let b = bloc(&[]);
        assert!(b.contains(DEBUT) && b.contains(FIN), "{b}");
        assert!(b.contains("aucun alias trié"), "{b}");
    }
}
