//! Accès SSH gérés par Homelabus (§2ter, phase 0bis).
//!
//! ## Pourquoi une clé dédiée plutôt que celle de l'utilisateur
//!
//! Si Homelabus empruntait la clé personnelle de l'administrateur, la révoquer
//! reviendrait à lui couper son propre accès. Avec une clé à part :
//!
//! - on peut la révoquer sur tout le parc sans toucher aux accès humains ;
//! - elle ne quitte jamais le coffre ;
//! - sa présence sur une machine dit exactement qui la pilote.
//!
//! ## 🔴 `authorized_keys` ne se réécrit JAMAIS en aveugle
//!
//! C'est le fichier le plus dangereux du système. Une écriture qui l'écrase enferme
//! dehors **tout le monde** — Homelabus *et* l'administrateur — sans recours autre
//! qu'un accès physique ou une console de secours.
//!
//! Trois règles en découlent, chacune vérifiée par un test :
//!
//! 1. On **filtre** les lignes plutôt que de reconstruire le fichier. Les clés
//!    inconnues sont recopiées telles quelles, y compris celles qu'on ne comprend pas.
//! 2. Le résultat est écrit dans un fichier temporaire puis **renommé** : un `rename`
//!    est atomique, donc une coupure de courant laisse l'ancien fichier intact plutôt
//!    qu'un fichier tronqué.
//! 3. On **refuse** de produire un contenu vide si l'entrée ne l'était pas.
//!
//! ## Le piège silencieux des permissions
//!
//! `sshd` **ignore** `authorized_keys` sans le moindre message si le fichier est
//! lisible par le groupe ou par tous, ou si `~/.ssh` l'est. La clé est installée, elle
//! paraît correcte, et l'authentification échoue quand même. D'où les `chmod`
//! systématiques dans le script d'installation.

use crate::runner::{Error, Result};
use crate::runner::{Runner, WriteFile};

/// Marqueur apposé en commentaire sur les clés que nous gérons.
///
/// 🔴 C'est lui qui rend la révocation possible **et sûre** : sans marqueur, il
/// faudrait deviner quelle ligne nous appartient, et l'on finirait par supprimer la
/// clé personnelle de quelqu'un.
pub const MARKER: &str = "homelabus-managed";

/// Restrictions posées sur la clé.
///
/// Homelabus a besoin d'un shell (il lance `docker`, `apt`…), donc pas de
/// `command=`. En revanche rien ne justifie les redirections de ports ou d'agent :
/// les interdire limite ce qu'une fuite de la clé privée permettrait.
const OPTIONS: &str = "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc";

/// Une clé publique gérée, prête à poser dans `authorized_keys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedKey {
    /// Le corps de la clé : `ssh-ed25519 AAAA…`.
    pub public: String,
    /// Nom du cluster, pour distinguer deux Homelabus sur une même machine.
    pub cluster: String,
}

impl ManagedKey {
    pub fn new(public: impl Into<String>, cluster: impl Into<String>) -> Self {
        Self {
            public: public.into().trim().to_string(),
            cluster: cluster.into(),
        }
    }

    /// Le commentaire qui identifie cette clé, et elle seule.
    pub fn comment(&self) -> String {
        format!("{MARKER}:{}", self.cluster)
    }

    /// La ligne complète à écrire.
    pub fn line(&self) -> String {
        // La clé peut déjà porter un commentaire (`… utilisateur@machine`) : on ne
        // garde que le type et le corps, sinon le marqueur ne serait pas en dernier
        // et la révocation ne le retrouverait pas.
        let corps: Vec<&str> = self.public.split_whitespace().take(2).collect();
        format!("{OPTIONS} {} {}", corps.join(" "), self.comment())
    }
}

/// Ce qu'une modification d'`authorized_keys` a changé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    pub added: usize,
    pub removed: usize,
    /// Lignes conservées sans y toucher — dont les clés humaines.
    pub kept: usize,
}

impl Change {
    pub fn is_noop(&self) -> bool {
        self.added == 0 && self.removed == 0
    }
}

/// Une ligne nous appartient-elle ?
///
/// On teste le commentaire exact, pas une simple présence du marqueur : deux clusters
/// sur une même machine ne doivent pas se révoquer mutuellement.
fn belongs_to(line: &str, comment: &str) -> bool {
    line.split_whitespace().any(|t| t == comment)
}

/// Installe la clé, en préservant tout le reste.
///
/// Idempotent : une clé déjà présente et identique ne produit aucun changement. Une
/// clé présente mais **différente** est remplacée — c'est le cas d'une rotation.
pub fn grant(existing: &str, key: &ManagedKey) -> (String, Change) {
    let comment = key.comment();
    let ligne = key.line();

    let mut sortie = Vec::new();
    let mut removed = 0;
    let mut kept = 0;
    let mut deja = false;

    for l in existing.lines() {
        if belongs_to(l, &comment) {
            if l.trim() == ligne {
                // Exactement la même : on la garde, rien à faire.
                deja = true;
                sortie.push(l.to_string());
            } else {
                // Même marqueur, contenu différent : rotation de clé.
                removed += 1;
            }
            continue;
        }
        // 🔴 Tout le reste est recopié TEL QUEL, y compris ce qu'on ne comprend pas.
        // Les commentaires, les lignes vides et les options exotiques appartiennent à
        // quelqu'un.
        kept += 1;
        sortie.push(l.to_string());
    }

    let added = usize::from(!deja);
    if !deja {
        sortie.push(ligne);
    }

    (
        finaliser(sortie),
        Change {
            added,
            removed,
            kept,
        },
    )
}

/// Retire la clé, en préservant tout le reste.
pub fn revoke(existing: &str, key: &ManagedKey) -> (String, Change) {
    let comment = key.comment();

    let mut sortie = Vec::new();
    let mut removed = 0;
    let mut kept = 0;

    for l in existing.lines() {
        if belongs_to(l, &comment) {
            removed += 1;
        } else {
            kept += 1;
            sortie.push(l.to_string());
        }
    }

    (
        finaliser(sortie),
        Change {
            added: 0,
            removed,
            kept,
        },
    )
}

/// Les clés gérées présentes dans un fichier, tous clusters confondus.
pub fn list_managed(existing: &str) -> Vec<String> {
    existing
        .lines()
        .filter_map(|l| {
            l.split_whitespace()
                .find(|t| t.starts_with(&format!("{MARKER}:")))
                .map(|t| t.trim_start_matches(&format!("{MARKER}:")).to_string())
        })
        .collect()
}

/// Termine le fichier par une newline.
///
/// Sans elle, une clé ajoutée par un autre outil se collerait à la dernière ligne et
/// les deux deviendraient invalides d'un coup.
fn finaliser(lignes: Vec<String>) -> String {
    if lignes.is_empty() {
        return String::new();
    }
    format!("{}\n", lignes.join("\n"))
}

/// Le script d'installation, exécuté sur la machine distante.
///
/// ⚠️ Les `chmod` ne sont pas décoratifs : `sshd` ignore silencieusement un
/// `authorized_keys` lisible par le groupe, et un `~/.ssh` en 755 suffit à le faire
/// refuser. C'est le mode d'échec le plus déroutant de tout SSH.
fn script_installation(home: &str, contenu: &str) -> String {
    let tmp = format!("{home}/.ssh/authorized_keys.hlb-tmp");
    format!(
        "set -e\n\
         mkdir -p {home}/.ssh\n\
         chmod 700 {home}/.ssh\n\
         cat > {tmp} <<'HLB_EOF_AUTHORIZED_KEYS'\n\
         {contenu}\n\
         HLB_EOF_AUTHORIZED_KEYS\n\
         chmod 600 {tmp}\n\
         # `mv` sur le même système de fichiers est atomique : une coupure laisse\n\
         # l'ancien fichier intact plutôt qu'un fichier tronqué.\n\
         mv {tmp} {home}/.ssh/authorized_keys\n"
    )
}

/// Lit `authorized_keys` sur une machine.
///
/// Un fichier absent n'est pas une erreur : c'est une machine qui n'a jamais eu de clé.
pub async fn read_authorized_keys<R: Runner>(runner: &R, home: &str) -> Result<String> {
    let out = runner
        .run(&[
            "sh".into(),
            "-c".into(),
            format!("cat {home}/.ssh/authorized_keys 2>/dev/null || true"),
        ])
        .await?;
    Ok(out.stdout)
}

/// Écrit `authorized_keys`, atomiquement et avec les bons droits.
///
/// 🔴 Refuse d'écrire un fichier vide quand l'ancien ne l'était pas. C'est le
/// garde-fou de dernier recours : quel que soit le bug en amont, on ne peut pas
/// enfermer tout le monde dehors.
pub async fn write_authorized_keys<R>(
    runner: &R,
    home: &str,
    contenu: &str,
    avant: &str,
) -> Result<()>
where
    R: Runner + WriteFile,
{
    if contenu.trim().is_empty() && !avant.trim().is_empty() {
        return Err(Error::Refused(
            "écriture d'un authorized_keys vide refusée — cela couperait tous les \
             accès à la machine, y compris les tiens"
                .into(),
        ));
    }

    let script = script_installation(home, contenu.trim_end());
    let out = runner.run(&["sh".into(), "-c".into(), script]).await?;

    if !out.ok() {
        return Err(Error::Refused(format!(
            "installation de la clé refusée : {}",
            out.stderr.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HUMAINE: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ remy@portable";
    const AUTRE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI collegue@bureau";

    fn cle() -> ManagedKey {
        ManagedKey::new(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHLB homelabus@hlb",
            "maison",
        )
    }

    #[test]
    fn a_managed_line_carries_its_marker_last() {
        // Le marqueur doit être le DERNIER champ : c'est le commentaire SSH, et une
        // clé qui en portait déjà un le masquerait.
        let l = cle().line();
        assert!(l.ends_with("homelabus-managed:maison"), "{l}");
        assert!(
            !l.contains("homelabus@hlb"),
            "l'ancien commentaire doit sauter : {l}"
        );
    }

    #[test]
    fn forwarding_is_disabled() {
        // Homelabus a besoin d'un shell, mais rien ne justifie les redirections :
        // les interdire limite ce qu'une fuite de la clé permettrait.
        let l = cle().line();
        assert!(l.contains("no-port-forwarding"), "{l}");
        assert!(l.contains("no-agent-forwarding"), "{l}");
        // Mais PAS de `command=` : ça casserait docker, apt, systemctl.
        assert!(!l.contains("command="), "{l}");
    }

    #[test]
    fn granting_never_touches_human_keys() {
        // 🔴 L'invariant central. Perdre la clé de l'administrateur en installant la
        // nôtre est l'échec le plus coûteux possible : plus personne n'entre.
        let avant = format!("{HUMAINE}\n{AUTRE}\n");
        let (apres, c) = grant(&avant, &cle());

        assert!(apres.contains(HUMAINE), "{apres}");
        assert!(apres.contains(AUTRE), "{apres}");
        assert_eq!(c.kept, 2);
        assert_eq!(c.added, 1);
        assert_eq!(c.removed, 0);
    }

    #[test]
    fn unknown_lines_are_copied_verbatim() {
        // Commentaires, lignes vides, options exotiques : tout appartient à quelqu'un.
        let avant = "# clé du NAS, ne pas supprimer\n\
                     \n\
                     from=\"10.0.0.0/8\" ssh-rsa AAAAB sauvegarde\n";
        let (apres, _) = grant(avant, &cle());

        assert!(apres.contains("# clé du NAS, ne pas supprimer"));
        assert!(apres.contains("from=\"10.0.0.0/8\""));
    }

    #[test]
    fn granting_twice_changes_nothing() {
        let (une, _) = grant("", &cle());
        let (deux, c) = grant(&une, &cle());

        assert_eq!(une, deux, "l'installation doit être idempotente");
        assert!(c.is_noop(), "{c:?}");
    }

    #[test]
    fn a_rotated_key_replaces_the_old_one() {
        // Rotation : même marqueur, corps différent. Il ne doit pas rester DEUX
        // lignes, sinon l'ancienne clé continuerait d'ouvrir la machine.
        let (avant, _) = grant("", &cle());
        let nouvelle = ManagedKey::new("ssh-ed25519 AAAANOUVELLE x@y", "maison");
        let (apres, c) = grant(&avant, &nouvelle);

        assert_eq!(c.removed, 1);
        assert_eq!(c.added, 1);
        assert!(apres.contains("AAAANOUVELLE"));
        assert!(!apres.contains("AAAAC3NzaC1lZDI1NTE5AAAAIHLB"), "{apres}");
        assert_eq!(apres.lines().count(), 1);
    }

    #[test]
    fn two_clusters_do_not_revoke_each_other() {
        // 🔴 Deux Homelabus sur une même machine : révoquer l'un ne doit pas couper
        // l'autre. C'est pourquoi on teste le commentaire ENTIER, pas le marqueur.
        let (a, _) = grant("", &cle());
        let bureau = ManagedKey::new("ssh-ed25519 AAAABUREAU x@y", "bureau");
        let (deux, _) = grant(&a, &bureau);

        let (apres, c) = revoke(&deux, &cle());
        assert_eq!(c.removed, 1);
        assert!(apres.contains("AAAABUREAU"), "{apres}");
        assert!(!apres.contains("AAAAC3NzaC1lZDI1NTE5AAAAIHLB"));
    }

    #[test]
    fn revoking_preserves_everything_else() {
        let avant = format!("{HUMAINE}\n{}\n{AUTRE}\n", cle().line());
        let (apres, c) = revoke(&avant, &cle());

        assert_eq!(c.removed, 1);
        assert_eq!(c.kept, 2);
        assert!(apres.contains(HUMAINE));
        assert!(apres.contains(AUTRE));
        assert!(!apres.contains(MARKER));
    }

    #[test]
    fn revoking_an_absent_key_is_a_noop() {
        let avant = format!("{HUMAINE}\n");
        let (apres, c) = revoke(&avant, &cle());
        assert!(c.is_noop());
        assert_eq!(apres, avant);
    }

    #[test]
    fn managed_clusters_are_listed() {
        let (a, _) = grant("", &cle());
        let (deux, _) = grant(&a, &ManagedKey::new("ssh-ed25519 AAAAB x@y", "bureau"));
        let mut noms = list_managed(&deux);
        noms.sort();
        assert_eq!(noms, ["bureau", "maison"]);
        // Une clé humaine n'apparaît pas.
        assert!(list_managed(HUMAINE).is_empty());
    }

    #[test]
    fn the_file_always_ends_with_a_newline() {
        // Sans elle, une clé ajoutée ensuite par un autre outil se collerait à la
        // dernière ligne et les deux deviendraient invalides.
        let (apres, _) = grant(HUMAINE, &cle());
        assert!(apres.ends_with('\n'), "{apres:?}");
        // Et pas de ligne vide parasite en fin.
        assert!(!apres.ends_with("\n\n"), "{apres:?}");
    }

    #[test]
    fn an_empty_input_gives_a_single_line() {
        let (apres, c) = grant("", &cle());
        assert_eq!(apres.lines().count(), 1);
        assert_eq!(c.kept, 0);
    }

    #[test]
    fn revoking_the_last_key_yields_an_empty_file() {
        // Le contenu vide est légitime ici ; c'est `write_authorized_keys` qui
        // refusera de l'écrire par-dessus un fichier non vide.
        let (a, _) = grant("", &cle());
        let (apres, _) = revoke(&a, &cle());
        assert!(apres.is_empty());
    }

    #[test]
    fn the_install_script_fixes_permissions() {
        // ⚠️ sshd ignore SILENCIEUSEMENT un authorized_keys lisible par le groupe.
        // La clé est installée, elle paraît bonne, et rien ne marche.
        let s = script_installation("/root", "ssh-ed25519 AAAA x");
        assert!(s.contains("chmod 700 /root/.ssh"), "{s}");
        assert!(s.contains("chmod 600"), "{s}");
    }

    #[test]
    fn the_install_script_is_atomic() {
        // Une coupure pendant l'écriture doit laisser l'ancien fichier intact, pas
        // un fichier tronqué qui n'ouvrirait plus rien.
        let s = script_installation("/root", "x");
        assert!(s.contains(".hlb-tmp"), "{s}");
        assert!(
            s.contains("mv /root/.ssh/authorized_keys.hlb-tmp /root/.ssh/authorized_keys"),
            "{s}"
        );
        // `set -e` : un chmod qui échoue ne doit pas laisser continuer le mv.
        assert!(s.starts_with("set -e"), "{s}");
    }

    #[test]
    fn the_heredoc_delimiter_is_quoted() {
        // Sans les quotes autour du délimiteur, le shell interpréterait `$` et les
        // backticks du contenu — une clé publique contient de l'aléatoire base64,
        // donc tôt ou tard un caractère qui casse tout.
        let s = script_installation("/root", "x");
        assert!(s.contains("<<'HLB_EOF_AUTHORIZED_KEYS'"), "{s}");
    }
}

/// Une paire de clés SSH fraîche.
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// Contenu du fichier de clé privée, format OpenSSH.
    pub private: String,
    /// `ssh-ed25519 AAAA…`
    pub public: String,
}

/// Génère une paire ed25519 via `ssh-keygen`.
///
/// ## Pourquoi déléguer plutôt qu'implémenter
///
/// Le format de clé privée OpenSSH n'est pas standardisé : c'est un conteneur maison
/// (`openssh-key-v1`) avec son propre encodage et son propre chiffrement. Le
/// réimplémenter pour produire un fichier que `ssh` doit accepter serait un pari
/// risqué pour zéro bénéfice — `ssh-keygen` est présent partout où `ssh` l'est, et
/// c'est déjà une dépendance de ce crate.
///
/// ed25519 plutôt que RSA : clés courtes, génération instantanée, et pas de choix de
/// taille à se tromper.
pub async fn generate_keypair(comment: &str) -> Result<KeyPair> {
    let dir = tempfile::tempdir().map_err(|source| Error::Spawn {
        command: "création d'un répertoire temporaire".into(),
        source,
    })?;
    let chemin = dir.path().join("hlb_ed25519");

    let out = tokio::process::Command::new("ssh-keygen")
        .args([
            "-t", "ed25519",
            // Sans phrase de passe : la clé est protégée par le coffre, et une
            // phrase interactive bloquerait tout automatisme.
            "-N", "", "-C", comment, "-f",
        ])
        .arg(&chemin)
        .output()
        .await
        .map_err(|source| Error::Spawn {
            command: "ssh-keygen".into(),
            source,
        })?;

    if !out.status.success() {
        return Err(Error::Refused(format!(
            "ssh-keygen a échoué : {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    let private = tokio::fs::read_to_string(&chemin)
        .await
        .map_err(|source| Error::Spawn {
            command: "lecture de la clé privée".into(),
            source,
        })?;
    let public = tokio::fs::read_to_string(chemin.with_extension("pub"))
        .await
        .map_err(|source| Error::Spawn {
            command: "lecture de la clé publique".into(),
            source,
        })?;

    Ok(KeyPair {
        private,
        public: public.trim().to_string(),
    })
}

#[cfg(test)]
mod tests_keygen {
    use super::*;

    #[tokio::test]
    async fn a_generated_pair_is_usable() {
        let Ok(kp) = generate_keypair("homelabus@test").await else {
            // `ssh-keygen` absent : on ne fait pas échouer la suite pour ça.
            return;
        };

        assert!(kp.public.starts_with("ssh-ed25519 "), "{}", kp.public);
        assert!(
            kp.private.contains("OPENSSH PRIVATE KEY"),
            "format inattendu"
        );
        // 🔴 La clé privée ne doit JAMAIS se retrouver dans la publique.
        assert!(!kp.public.contains("PRIVATE"));
        assert_eq!(
            kp.public.lines().count(),
            1,
            "la publique tient sur une ligne"
        );
    }

    #[tokio::test]
    async fn two_generations_differ() {
        let (Ok(a), Ok(b)) = (generate_keypair("x@1").await, generate_keypair("x@2").await) else {
            return;
        };
        assert_ne!(
            a.public, b.public,
            "deux clés identiques seraient une catastrophe"
        );
    }

    #[tokio::test]
    async fn a_generated_key_produces_a_valid_authorized_line() {
        let Ok(kp) = generate_keypair("homelabus@hlb").await else {
            return;
        };
        let l = ManagedKey::new(&kp.public, "maison").line();

        // Trois champs au minimum : options, type, corps, commentaire.
        let champs: Vec<&str> = l.split_whitespace().collect();
        assert_eq!(champs.len(), 4, "{l}");
        assert_eq!(champs[1], "ssh-ed25519");
        assert_eq!(champs[3], "homelabus-managed:maison");
    }
}
