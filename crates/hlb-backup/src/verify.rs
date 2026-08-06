//! Vérification de restauration (§8.3).
//!
//! > « Un backup non testé n'est pas un backup. »
//!
//! Le piège est de croire qu'on a vérifié quelque chose alors qu'on n'a rien prouvé :
//!
//! | Ce qu'on fait souvent | Ce que ça prouve |
//! |---|---|
//! | L'instantané a un identifiant | restic a répondu |
//! | `restic check` passe | les métadonnées sont cohérentes |
//! | `restic check --read-data` passe | les blocs sont lisibles et non corrompus |
//! | **On restaure et on compare** | **les données reviennent réellement** |
//!
//! Seule la dernière ligne répond à la question qu'on se pose vraiment. C'est donc
//! celle-ci qu'on implémente : restaurer dans un espace jetable, puis comparer le
//! contenu obtenu à ce que l'instantané prétend contenir.

use crate::restic::{Repository, Runner};
use crate::Result;

/// Ce qu'une vérification a établi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub snapshot_id: String,
    /// Nombre de fichiers effectivement restaurés.
    pub files_restored: u64,
    /// Octets effectivement restaurés.
    pub bytes_restored: u64,
    /// Ce que l'instantané annonçait.
    pub files_expected: u64,
    pub bytes_expected: u64,
}

impl Verification {
    /// La restauration correspond-elle à ce que l'instantané annonçait ?
    pub fn matches(&self) -> bool {
        self.files_restored == self.files_expected && self.bytes_restored == self.bytes_expected
    }

    pub fn describe(&self) -> String {
        if self.matches() {
            format!(
                "{} fichiers / {} octets restaurés, conformes à l'instantané",
                self.files_restored, self.bytes_restored
            )
        } else {
            format!(
                "ÉCART — restauré {} fichiers / {} octets, l'instantané en annonçait \
                 {} / {}",
                self.files_restored,
                self.bytes_restored,
                self.files_expected,
                self.bytes_expected
            )
        }
    }
}

/// Statistiques d'un instantané, telles que restic les rapporte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub files: u64,
    pub bytes: u64,
}

impl<R: Runner> Repository<R> {
    /// Ce que l'instantané prétend contenir : **fichiers réguliers seulement**.
    ///
    /// ⚠️ On n'utilise pas `restic stats` : son `total_file_count` compte aussi les
    /// répertoires (une sauvegarde de 2 fichiers dans 2 niveaux en annonce 4). Une
    /// vérification bâtie dessus comparerait des choux et des carottes.
    ///
    /// `restic ls --json` distingue les types, ce qui donne un décompte comparable à
    /// ce qu'on trouve réellement sur le disque après restauration.
    pub async fn stats(&self, snapshot: &str) -> Result<Stats> {
        let out = self.exec_public(&["ls", snapshot, "--json"]).await?;

        let mut s = Stats { files: 0, bytes: 0 };
        // Sortie en JSON par ligne : un objet par entrée.
        for line in out.stdout.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if v.get("type").and_then(|t| t.as_str()) == Some("file") {
                s.files += 1;
                s.bytes += v.get("size").and_then(|x| x.as_u64()).unwrap_or(0);
            }
        }
        Ok(s)
    }

    /// Vérifie l'intégrité **et la lisibilité réelle** d'un sous-ensemble des données.
    ///
    /// `restic check` seul ne lit que les métadonnées : un bloc corrompu sur le disque
    /// passerait inaperçu. `--read-data-subset` en relit un échantillon, ce qui
    /// attrape la corruption silencieuse sans relire tout le dépôt à chaque fois.
    pub async fn check_data(&self, subset: &str) -> Result<()> {
        self.exec_public(&["check", "--read-data-subset", subset]).await?;
        Ok(())
    }
}

/// Restaure un instantané dans un espace jetable et compare au contenu annoncé.
///
/// `count_target` doit renvoyer `(fichiers, octets)` réellement présents à
/// l'emplacement restauré — c'est l'appelant qui sait inspecter cet espace (volume
/// Docker, chemin local, montage distant).
pub async fn verify_by_restore<R, F, Fut>(
    repo: &Repository<R>,
    snapshot: &str,
    scratch: &str,
    count_target: F,
) -> Result<Verification>
where
    R: Runner,
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<(u64, u64)>>,
{
    let expected = repo.stats(snapshot).await?;

    repo.restore(snapshot, scratch).await?;
    let (files, bytes) = count_target(scratch.to_string()).await?;

    let v = Verification {
        snapshot_id: snapshot.to_string(),
        files_restored: files,
        bytes_restored: bytes,
        files_expected: expected.files,
        bytes_expected: expected.bytes,
    };

    if v.matches() {
        tracing::info!(snapshot, "{}", v.describe());
    } else {
        // Ne jamais passer sous silence : c'est exactement le cas où on croyait
        // avoir une sauvegarde et où on n'en a pas.
        tracing::error!(snapshot, "{}", v.describe());
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verification(restored: (u64, u64), expected: (u64, u64)) -> Verification {
        Verification {
            snapshot_id: "abc".into(),
            files_restored: restored.0,
            bytes_restored: restored.1,
            files_expected: expected.0,
            bytes_expected: expected.1,
        }
    }

    #[test]
    fn an_exact_restore_matches() {
        assert!(verification((12, 4096), (12, 4096)).matches());
    }

    #[test]
    fn a_missing_file_is_detected() {
        // Le cas qui compte : la restauration « a marché » mais il manque des données.
        let v = verification((11, 4096), (12, 4096));
        assert!(!v.matches());
        assert!(v.describe().contains("ÉCART"), "{}", v.describe());
    }

    #[test]
    fn a_truncated_file_is_detected() {
        // Même nombre de fichiers, mais du contenu manquant.
        assert!(!verification((12, 2048), (12, 4096)).matches());
    }

    #[test]
    fn an_empty_restore_is_never_a_success() {
        // 🔴 Une restauration qui ne produit rien ne doit surtout pas passer.
        let v = verification((0, 0), (12, 4096));
        assert!(!v.matches());
        assert!(v.describe().contains("ÉCART"));
    }

    #[test]
    fn the_description_is_readable_in_both_cases() {
        assert!(verification((3, 100), (3, 100)).describe().contains("conformes"));
        assert!(verification((3, 100), (4, 100)).describe().contains("annonçait"));
    }
}
