//! Sauvegarde logique de PostgreSQL (§8.1, couche L1).
//!
//! 🔴 **Pourquoi c'est indispensable, et pas redondant avec restic.**
//!
//! Sauvegarder les *fichiers* d'un PostgreSQL en cours d'écriture produit une
//! sauvegarde qu'on croit bonne et qui ne restaure pas : les pages de données, le WAL
//! et les fichiers de contrôle sont copiés à des instants différents, donc
//! incohérents entre eux. Le fichier existe, restic le rend fidèlement, et
//! PostgreSQL refuse de démarrer dessus.
//!
//! `pg_dump` prend au contraire un instantané **transactionnellement cohérent** : il
//! ouvre une transaction en isolation `REPEATABLE READ` et exporte le contenu tel
//! qu'il était à cet instant précis, quelles que soient les écritures concurrentes.
//!
//! Comme pour restic, `pg_dump` n'est pas garanti présent sur l'hôte : on passe donc
//! par la même abstraction d'exécution.

use crate::{Error, Result};

/// Exécute `pg_dump` / `pg_restore`, où qu'ils se trouvent.
#[async_trait::async_trait]
pub trait DumpRunner: Send + Sync {
    /// Lance un outil client PostgreSQL et renvoie sa sortie standard **brute**.
    ///
    /// Le dump est binaire (format `custom`) : on ne peut pas le traiter comme du
    /// texte sans le corrompre.
    async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<RawOutput>;
}

pub struct RawOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Où se connecter, et avec quoi.
#[derive(Debug, Clone)]
pub struct PgTarget {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
}

impl PgTarget {
    fn env(&self) -> Vec<(String, String)> {
        // Comme pour restic : le mot de passe passe par l'environnement, jamais par
        // la ligne de commande, lisible par tout utilisateur de la machine.
        vec![
            ("PGPASSWORD".into(), self.password.clone()),
            ("PGHOST".into(), self.host.clone()),
            ("PGPORT".into(), self.port.to_string()),
            ("PGUSER".into(), self.user.clone()),
            ("PGDATABASE".into(), self.database.clone()),
        ]
    }
}

pub struct PgDumper<R: DumpRunner> {
    runner: R,
}

impl<R: DumpRunner> PgDumper<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    /// Produit un dump cohérent, au format `custom` de PostgreSQL.
    ///
    /// Le format `custom` (`-Fc`) est compressé, et surtout **restaurable
    /// sélectivement** : on peut n'en ressortir qu'une table le jour où c'est une
    /// seule table qu'on a perdue.
    pub async fn dump(&self, target: &PgTarget) -> Result<Vec<u8>> {
        let args: Vec<String> = [
            "pg_dump",
            "--format=custom",
            // Sans cette option, un dump restauré dans une base neuve échoue sur les
            // propriétaires absents.
            "--no-owner",
            "--no-privileges",
            // Cohérence transactionnelle explicite.
            "--serializable-deferrable",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let out = self.runner.run(&args, &target.env()).await?;
        if out.status != 0 {
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: out.stderr.trim().to_string(),
            });
        }

        if out.stdout.is_empty() {
            // Un dump vide n'est jamais normal, même pour une base sans table :
            // l'en-tête du format custom fait déjà plusieurs octets.
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: "dump vide".into(),
            });
        }

        tracing::info!(
            database = %target.database,
            octets = out.stdout.len(),
            "dump logique produit"
        );
        Ok(out.stdout)
    }

    /// Restaure un dump dans une base existante.
    ///
    /// `clean` supprime les objets avant de les recréer — nécessaire pour restaurer
    /// par-dessus une base déjà peuplée.
    pub async fn restore(&self, target: &PgTarget, dump: &[u8], clean: bool) -> Result<()> {
        let mut args = vec!["pg_restore".to_string(), "--no-owner".to_string()];
        if clean {
            args.push("--clean".into());
            args.push("--if-exists".into());
        }
        args.push("--dbname".into());
        args.push(target.database.clone());

        let mut env = target.env();
        // Le contenu à restaurer voyage par l'environnement d'exécution du runner,
        // qui sait comment l'acheminer (fichier temporaire, stdin…).
        env.push(("HLB_STDIN_B64".into(), base64_encode(dump)));

        let out = self.runner.run(&args, &env).await?;
        if out.status != 0 {
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: out.stderr.trim().to_string(),
            });
        }
        tracing::info!(database = %target.database, "dump restauré");
        Ok(())
    }
}

/// Encodage base64 minimal, pour transporter un binaire à travers l'environnement.
///
/// Évite une dépendance de plus pour une poignée de lignes.
fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);

        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fake {
        out: Mutex<RawOutput>,
        calls: Mutex<Vec<Vec<String>>>,
        envs: Mutex<Vec<Vec<(String, String)>>>,
    }

    impl Fake {
        fn new(status: i32, stdout: Vec<u8>, stderr: &str) -> Self {
            Self {
                out: Mutex::new(RawOutput {
                    status,
                    stdout,
                    stderr: stderr.into(),
                }),
                calls: Mutex::new(Vec::new()),
                envs: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl DumpRunner for Fake {
        async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<RawOutput> {
            self.calls.lock().expect("mutex").push(args.to_vec());
            self.envs.lock().expect("mutex").push(env.to_vec());
            let o = self.out.lock().expect("mutex");
            Ok(RawOutput {
                status: o.status,
                stdout: o.stdout.clone(),
                stderr: o.stderr.clone(),
            })
        }
    }

    fn target() -> PgTarget {
        PgTarget {
            host: "postgres".into(),
            port: 5432,
            database: "gitea".into(),
            user: "gitea".into(),
            password: "secret".into(),
        }
    }

    #[tokio::test]
    async fn the_password_never_reaches_the_command_line() {
        let d = PgDumper::new(Fake::new(0, b"PGDMP-fake".to_vec(), ""));
        d.dump(&target()).await.expect("dump");

        let calls = d.runner.calls.lock().expect("mutex");
        assert!(
            !calls[0].iter().any(|a| a.contains("secret")),
            "mot de passe dans les arguments : {:?}",
            calls[0]
        );
        let envs = d.runner.envs.lock().expect("mutex");
        assert!(envs[0].iter().any(|(k, v)| k == "PGPASSWORD" && v == "secret"));
    }

    #[tokio::test]
    async fn the_dump_is_transactionally_consistent() {
        // 🔴 Sans ça, un dump pris pendant des écritures est incohérent.
        let d = PgDumper::new(Fake::new(0, b"PGDMP".to_vec(), ""));
        d.dump(&target()).await.expect("dump");

        let calls = d.runner.calls.lock().expect("mutex");
        let joined = calls[0].join(" ");
        assert!(joined.contains("--serializable-deferrable"), "{joined}");
        assert!(joined.contains("--format=custom"), "{joined}");
    }

    #[tokio::test]
    async fn an_empty_dump_is_an_error() {
        // Un dump vide serait accepté silencieusement puis archivé comme valide.
        let d = PgDumper::new(Fake::new(0, Vec::new(), ""));
        let err = d.dump(&target()).await.unwrap_err();
        assert!(err.to_string().contains("vide"), "{err}");
    }

    #[tokio::test]
    async fn a_failing_dump_surfaces_the_message() {
        let d = PgDumper::new(Fake::new(1, Vec::new(), "FATAL: role does not exist"));
        let err = d.dump(&target()).await.unwrap_err();
        assert!(err.to_string().contains("role does not exist"), "{err}");
    }

    #[tokio::test]
    async fn restore_can_clean_first() {
        let d = PgDumper::new(Fake::new(0, Vec::new(), ""));
        d.restore(&target(), b"donnees", true).await.expect("restore");

        let calls = d.runner.calls.lock().expect("mutex");
        let joined = calls[0].join(" ");
        assert!(joined.contains("--clean"));
        assert!(joined.contains("--if-exists"), "sinon un objet absent fait échouer");
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_handles_binary() {
        // Le format custom est binaire : les octets nuls et hauts doivent passer.
        assert_eq!(base64_encode(&[0x00, 0xff, 0x80]), "AP+A");
    }
}
