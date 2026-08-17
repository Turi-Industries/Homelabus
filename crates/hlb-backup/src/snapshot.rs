//! Instantanés de système de fichiers : ZFS et btrfs (§8).
//!
//! ## Ce que ça apporte, et ce que ça n'apporte pas
//!
//! Un instantané ZFS ou btrfs est **quasi instantané** et rend un retour arrière en
//! minutes là où restic demande des heures. C'est le bon outil pour l'incident
//! logique : une mise à jour qui tourne mal, une manipulation qu'on regrette.
//!
//! 🔴 **Ce n'est PAS une sauvegarde**, et les confondre est le piège qui coûte le plus
//! cher. Un instantané vit sur le même pool que les données : le disque meurt,
//! l'instantané meurt avec. Il ne protège de **rien** de ce qui fait perdre un disque.
//!
//! | | Protège de | Ne protège pas de |
//! |---|---|---|
//! | Instantané | erreur logique, mise à jour ratée | perte de disque, incendie, vol |
//! | restic | tout ce qui précède | rien (mais lent) |
//!
//! Les deux se complètent, aucun ne remplace l'autre. Le PLAN le dit en ces termes :
//! « à combiner avec restic, pas à remplacer ».
//!
//! ## 🔴 Pourquoi cette commande ne supprime jamais rien
//!
//! Une rotation automatique d'instantanés est tentante — ils occupent de la place, et
//! ZFS le fait volontiers. Mais un instantané supprimé au mauvais moment fait perdre
//! exactement le point de retour qu'on cherchait, et l'erreur ne se voit qu'au moment
//! où on en a besoin.
//!
//! Cette commande crée et liste. La suppression reste une décision humaine, avec
//! `zfs destroy` ou `btrfs subvolume delete` sous les yeux.

use crate::{Error, Result};

/// Le système de fichiers du chemin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filesystem {
    Zfs,
    Btrfs,
}

impl Filesystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Zfs => "zfs",
            Self::Btrfs => "btrfs",
        }
    }
}

/// Un instantané existant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Snapshot {
    /// Nom complet, tel que l'outil le rend.
    pub name: String,
    /// Ce qui suit le `@` (ZFS) ou le dernier `/` (btrfs).
    pub label: String,
}

/// Le nom d'un instantané, horodaté.
///
/// ⚠️ Format trié lexicographiquement, comme les sauvegardes de base et les dumps :
/// c'est ce qui permet de retrouver le plus récent sans interpréter de date.
///
/// 🔴 Les caractères sont volontairement restreints. ZFS refuse `:` dans un nom de
/// snapshot, et un `@` en ferait un nom ambigu — l'outil échouerait sur un message
/// qui parle de syntaxe sans dire quel caractère pose problème.
pub fn snapshot_label(motif: &str, at: i64) -> Result<String> {
    if motif.is_empty() || motif.len() > 40 {
        return Err(Error::Unexpected(format!(
            "motif « {motif} » : 1 à 40 caractères"
        )));
    }
    if !motif.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(Error::Unexpected(format!(
            "motif « {motif} » : seuls les caractères alphanumériques, « - » et « _ » \
             sont admis. ZFS refuse « : » et « @ » dans un nom d'instantané, et échoue \
             alors sur un message qui ne dit pas quel caractère pose problème."
        )));
    }

    let (y, m, d, hh, mm, ss) = crate::pitr::civil_public(at);
    Ok(format!("hlb-{motif}-{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z"))
}

/// Détecte le système de fichiers d'un chemin.
///
/// ⚠️ `df -T` n'existe pas sur macOS et BSD ; `stat -f` n'a pas la même sortie sur
/// Linux. On interroge donc les outils eux-mêmes, qui savent répondre pour leurs
/// propres volumes — et l'absence de réponse veut dire « ni l'un ni l'autre », ce qui
/// est l'information utile.
pub async fn detect(path: &str) -> Option<Filesystem> {
    // ZFS : `zfs list -H -o name <chemin>` répond si le chemin est un dataset.
    if let Ok(o) = tokio::process::Command::new("zfs")
        .args(["list", "-H", "-o", "name", path])
        .output()
        .await
    {
        if o.status.success() {
            return Some(Filesystem::Zfs);
        }
    }

    if let Ok(o) = tokio::process::Command::new("btrfs")
        .args(["subvolume", "show", path])
        .output()
        .await
    {
        if o.status.success() {
            return Some(Filesystem::Btrfs);
        }
    }
    None
}

/// La commande de création, sans l'exécuter.
///
/// Séparée de l'exécution pour être testable : c'est la partie où une erreur de
/// syntaxe se paie par un instantané qui n'existe pas alors qu'on le croit pris.
pub fn create_command(fs: Filesystem, dataset: &str, label: &str) -> Vec<String> {
    match fs {
        // `-r` : récursif. Un dataset parent sans ses enfants donne un instantané
        // partiel — et c'est justement l'arborescence qu'on veut figer d'un coup.
        Filesystem::Zfs => vec![
            "zfs".into(),
            "snapshot".into(),
            "-r".into(),
            format!("{dataset}@{label}"),
        ],
        // btrfs : `-r` signifie ici « lecture seule », ce qui est différent mais tout
        // aussi souhaitable — un instantané modifiable n'est plus un point de retour.
        Filesystem::Btrfs => vec![
            "btrfs".into(),
            "subvolume".into(),
            "snapshot".into(),
            "-r".into(),
            dataset.into(),
            format!("{dataset}/.snapshots/{label}"),
        ],
    }
}

/// Crée l'instantané.
pub async fn create(fs: Filesystem, dataset: &str, label: &str) -> Result<String> {
    let cmd = create_command(fs, dataset, label);

    // btrfs exige que le répertoire de destination existe.
    if fs == Filesystem::Btrfs {
        let _ = tokio::fs::create_dir_all(format!("{dataset}/.snapshots")).await;
    }

    let out = tokio::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .output()
        .await
        .map_err(|e| Error::Unexpected(format!("{} introuvable : {e}", cmd[0])))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(Error::Unexpected(expliquer(fs, &stderr)));
    }

    Ok(label.to_string())
}

/// Enrichit les erreurs dont le message brut n'oriente pas.
fn expliquer(fs: Filesystem, stderr: &str) -> String {
    let b = stderr.to_lowercase();

    if b.contains("permission denied") || b.contains("not authorized") {
        return format!(
            "{stderr}\n\n\
             🔴 Créer un instantané demande les droits root, ou une délégation :\n\
             \x20   zfs allow <utilisateur> snapshot,mount <pool>"
        );
    }
    if b.contains("dataset does not exist") || b.contains("not a subvolume") {
        return format!(
            "{stderr}\n\n\
             Le chemin n'est pas un {} — un instantané ne peut porter que sur un\n\
             dataset ({}) ou un sous-volume (btrfs), pas sur un répertoire ordinaire.",
            fs.as_str(),
            if fs == Filesystem::Zfs { "ZFS" } else { "btrfs" }
        );
    }
    if b.contains("already exists") {
        return format!(
            "{stderr}\n\n\
             Un instantané porte déjà ce nom. On n'écrase JAMAIS : ce serait détruire\n\
             le point de retour qu'on croit créer."
        );
    }
    stderr.to_string()
}

/// La commande de listage.
pub fn list_command(fs: Filesystem, dataset: &str) -> Vec<String> {
    match fs {
        Filesystem::Zfs => vec![
            "zfs".into(),
            "list".into(),
            "-H".into(),
            "-t".into(),
            "snapshot".into(),
            "-o".into(),
            "name".into(),
            "-s".into(),
            "creation".into(),
            "-r".into(),
            dataset.into(),
        ],
        Filesystem::Btrfs => vec![
            "btrfs".into(),
            "subvolume".into(),
            "list".into(),
            "-s".into(),
            dataset.into(),
        ],
    }
}

/// Les instantanés créés par HomelabUS.
///
/// 🔴 On ne liste **que les nôtres** (préfixe `hlb-`). Afficher les instantanés du
/// NAS ou d'un autre outil laisserait croire qu'on peut les supprimer — et un
/// instantané supprimé au mauvais moment fait perdre exactement le point de retour
/// qu'on cherchait.
pub fn parse_list(fs: Filesystem, sortie: &str) -> Vec<Snapshot> {
    let mut out: Vec<Snapshot> = sortie
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() {
                return None;
            }
            let label = match fs {
                Filesystem::Zfs => l.split('@').nth(1)?,
                // `btrfs subvolume list` rend « ID 256 gen 9 top level 5 path <chemin> ».
                Filesystem::Btrfs => l.rsplit('/').next()?,
            };
            label.starts_with("hlb-").then(|| Snapshot {
                name: l.to_string(),
                label: label.to_string(),
            })
        })
        .collect();

    // Le format horodaté trie chronologiquement : le plus récent en dernier.
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const J0: i64 = 1_786_881_600;

    #[test]
    fn labels_sort_chronologically() {
        // Retrouver le point de retour le plus récent doit être un tri de noms.
        let a = snapshot_label("avant-maj", J0).expect("nom");
        let b = snapshot_label("avant-maj", J0 + 3600).expect("nom");
        assert_eq!(a, "hlb-avant-maj-20260816T120000Z");
        assert!(a < b);
    }

    #[test]
    fn characters_zfs_refuses_are_rejected_early() {
        // 🔴 ZFS refuse « : » et « @ », et échoue sur un message de syntaxe qui ne
        // dit pas quel caractère pose problème.
        assert!(snapshot_label("avant:maj", J0).is_err());
        assert!(snapshot_label("avant@maj", J0).is_err());
        assert!(snapshot_label("avec espace", J0).is_err());
        assert!(snapshot_label("", J0).is_err());

        let e = snapshot_label("a:b", J0).unwrap_err().to_string();
        assert!(e.contains("ZFS refuse"), "{e}");
    }

    #[test]
    fn ordinary_labels_pass() {
        assert!(snapshot_label("avant-maj", J0).is_ok());
        assert!(snapshot_label("avant_maj_gitea", J0).is_ok());
        assert!(snapshot_label("test123", J0).is_ok());
    }

    #[test]
    fn the_zfs_snapshot_is_recursive() {
        // ⚠️ Un dataset parent sans ses enfants donne un instantané PARTIEL, alors
        // que c'est justement l'arborescence qu'on veut figer d'un coup.
        let c = create_command(Filesystem::Zfs, "tank/hlb", "hlb-x-20260816T120000Z");
        assert!(c.contains(&"-r".to_string()), "{c:?}");
        assert_eq!(c.last().expect("cible"), "tank/hlb@hlb-x-20260816T120000Z");
    }

    #[test]
    fn the_btrfs_snapshot_is_read_only() {
        // Un instantané modifiable n'est plus un point de retour : on peut détruire
        // sans le vouloir ce vers quoi on comptait revenir.
        let c = create_command(Filesystem::Btrfs, "/donnees", "hlb-x-20260816T120000Z");
        assert!(c.contains(&"-r".to_string()), "{c:?}");
        assert!(c.last().expect("cible").contains(".snapshots/"), "{c:?}");
    }

    #[test]
    fn the_two_filesystems_do_not_share_a_syntax() {
        // Transposer la commande de l'un à l'autre échouerait — ou pire, créerait
        // quelque chose d'inattendu.
        let z = create_command(Filesystem::Zfs, "tank/x", "l");
        let b = create_command(Filesystem::Btrfs, "/x", "l");
        assert_ne!(z[0], b[0]);
        assert!(z.iter().any(|a| a.contains('@')));
        assert!(!b.iter().any(|a| a.contains('@')));
    }

    #[test]
    fn only_our_own_snapshots_are_listed() {
        // 🔴 Afficher ceux du NAS laisserait croire qu'on peut les supprimer.
        let sortie = "tank/hlb@hlb-avant-maj-20260816T120000Z\n\
                      tank/hlb@autoznap_2026-08-16_12.00.00_hourly\n\
                      tank/hlb@hlb-avant-maj-20260817T120000Z\n";
        let v = parse_list(Filesystem::Zfs, sortie);

        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v.iter().all(|s| s.label.starts_with("hlb-")));
        // Le plus récent en dernier.
        assert!(v[0].label < v[1].label);
    }

    #[test]
    fn an_empty_listing_is_not_an_error() {
        assert!(parse_list(Filesystem::Zfs, "").is_empty());
        assert!(parse_list(Filesystem::Btrfs, "\n\n").is_empty());
    }

    #[test]
    fn a_permission_error_says_how_to_delegate() {
        let m = expliquer(Filesystem::Zfs, "cannot create snapshot: permission denied");
        assert!(m.contains("zfs allow"), "{m}");
    }

    #[test]
    fn a_plain_directory_is_explained() {
        // L'erreur brute dit « dataset does not exist », ce qui envoie chercher une
        // faute de frappe alors que le chemin est simplement un répertoire ordinaire.
        let m = expliquer(Filesystem::Zfs, "cannot open 'x': dataset does not exist");
        assert!(m.contains("répertoire ordinaire"), "{m}");
    }

    #[test]
    fn an_existing_snapshot_is_never_overwritten() {
        let m = expliquer(Filesystem::Zfs, "snapshot already exists");
        assert!(m.contains("point de retour"), "{m}");
    }
}
