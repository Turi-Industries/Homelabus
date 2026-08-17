//! Sauvegarde logique de MariaDB (§8.1, couche L1).
//!
//! Le pendant de [`crate::pgdump`] pour l'autre moteur du catalogue. Jusqu'ici
//! l'ordonnanceur sautait toute base non-PostgreSQL en le disant — c'était honnête,
//! mais une app MariaDB n'avait **aucune sauvegarde logique**.
//!
//! ## 🔴 Trois façons pour un dump MariaDB de réussir en étant inutilisable
//!
//! Ce module existe surtout pour ces trois pièges. Chacun produit un fichier de taille
//! plausible, un code de sortie 0, et une restauration qui *paraît* marcher.
//!
//! **1. Les routines, déclencheurs et événements ne sont PAS dans le dump par
//! défaut.** `mariadb-dump` sans `--routines --triggers --events` exporte les tables
//! et les données, et laisse silencieusement de côté les procédures stockées, les
//! déclencheurs et les tâches planifiées. Le dump restaure sans une erreur, les
//! données sont là, et l'app est subtilement cassée — un déclencheur manquant ne se
//! voit qu'à la première écriture qui aurait dû le déclencher.
//!
//! **2. Sans `--single-transaction`, le dump n'est pas cohérent.** Le défaut de
//! `mariadb-dump` est `--lock-tables`, qui verrouille une base à la fois : les tables
//! sont donc capturées à des instants différents, et les clés étrangères entre elles
//! peuvent pointer dans le vide. C'est le même vice que copier les fichiers d'un
//! PostgreSQL à chaud, en moins visible.
//!
//! **3. `--single-transaction` ne protège QUE les tables transactionnelles.** Sur une
//! table MyISAM ou Aria, l'option est acceptée sans un mot et n'apporte
//! rigoureusement aucune cohérence. On croit avoir un instantané ; on a une copie
//! étalée dans le temps. D'où [`MariaDumper::dump`] qui exige de savoir à quoi il
//! touche, et [`NON_TRANSACTIONNEL`].
//!
//! ## 🔴 Comment on sait qu'un dump est complet
//!
//! Contrairement au format `custom` de PostgreSQL, un dump MariaDB est du **texte
//! concaténé au fil de l'eau**. Un dump interrompu à mi-course — conteneur tué,
//! disque plein, connexion coupée — laisse un fichier de SQL parfaitement valide,
//! simplement amputé de la fin. Restauré, il produit une base à qui il manque des
//! tables, sans une seule erreur.
//!
//! `mariadb-dump` écrit une ligne de garde en dernier (`-- Dump completed`). Sa
//! présence est la **seule** preuve que le processus est allé jusqu'au bout, et
//! [`verifier_complet`] refuse tout dump qui ne la porte pas. C'est pour cela qu'on ne
//! passe jamais `--skip-comments` : l'option supprimerait la ligne de garde, et donc
//! notre unique moyen de détecter une troncature.

use crate::pgdump::DumpRunner;
use crate::{Error, Result};

/// La ligne que `mariadb-dump` écrit en tout dernier.
///
/// 🔴 Notre seule preuve de complétude. Voir la section « Comment on sait qu'un dump
/// est complet » en tête de module.
pub const LIGNE_DE_GARDE: &str = "-- Dump completed";

/// Les moteurs de stockage que `--single-transaction` ne protège pas.
///
/// 🔴 L'option est acceptée sans le moindre avertissement sur ces tables, et n'apporte
/// aucune cohérence. Le dump paraît bon.
pub const NON_TRANSACTIONNEL: &[&str] = &["MyISAM", "Aria", "MEMORY", "CSV", "ARCHIVE"];

/// Où se connecter, et avec quoi.
#[derive(Debug, Clone)]
pub struct MariaTarget {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
}

impl MariaTarget {
    /// Les variables d'environnement du client.
    ///
    /// 🔴 `MYSQL_PWD` et non `--password=…` : un mot de passe en ligne de commande est
    /// lisible par n'importe quel utilisateur de la machine via `ps`, et MariaDB le
    /// signale lui-même sur stderr — un avertissement qu'on verrait passer dans les
    /// journaux, une fois le secret déjà exposé.
    fn env(&self) -> Vec<(String, String)> {
        vec![
            ("MYSQL_PWD".into(), self.password.clone()),
            ("MYSQL_HOST".into(), self.host.clone()),
            ("MYSQL_TCP_PORT".into(), self.port.to_string()),
        ]
    }
}

/// Ce que l'appelant sait de la cohérence atteignable.
///
/// 🔴 Ce n'est pas une option de confort : c'est le choix entre un instantané cohérent
/// et une copie étalée dans le temps, et il doit être **explicite**. Un booléen par
/// défaut aurait laissé passer le cas MyISAM en silence, qui est précisément celui
/// qu'on cherche à ne pas rater.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coherence {
    /// Toutes les tables sont transactionnelles (InnoDB) : `--single-transaction`
    /// donne un instantané cohérent, sans verrouiller la base.
    Transactionnelle,
    /// Au moins une table ne l'est pas. `--single-transaction` serait un mensonge :
    /// on verrouille en lecture le temps du dump.
    ///
    /// ⚠️ Les écritures de l'app sont bloquées pendant ce temps. C'est le prix d'un
    /// dump restaurable, et il vaut mieux le payer que découvrir l'incohérence à la
    /// restauration.
    VerrouillageRequis,
}

pub struct MariaDumper<R: DumpRunner> {
    runner: R,
}

impl<R: DumpRunner> MariaDumper<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    /// Les arguments du dump, séparés pour être testables sans serveur.
    pub fn dump_args(database: &str, coherence: Coherence) -> Vec<String> {
        let mut args: Vec<String> = vec!["mariadb-dump".into()];

        match coherence {
            // Cohérence sans verrou : possible uniquement en tout-InnoDB.
            Coherence::Transactionnelle => args.push("--single-transaction".into()),
            // 🔴 Le verrou est le seul moyen d'obtenir un instantané cohérent d'une
            // table non transactionnelle. `--single-transaction` ici ne verrouillerait
            // rien ET n'apporterait aucune cohérence : le pire des deux.
            Coherence::VerrouillageRequis => args.push("--lock-tables".into()),
        }

        args.extend(
            [
                // 🔴 Aucun des trois n'est pris par défaut. Sans eux, procédures
                // stockées, déclencheurs et tâches planifiées disparaissent du dump
                // sans un mot, et la restauration réussit quand même.
                "--routines",
                "--triggers",
                "--events",
                // Inclut `CREATE DATABASE IF NOT EXISTS` et `USE` : sans cela, le dump
                // ne dit pas où se restaurer et dépend d'une base déjà sélectionnée.
                "--databases",
            ]
            .iter()
            .map(|s| s.to_string()),
        );

        args.push(database.to_string());
        args
    }

    /// Produit un dump logique complet.
    ///
    /// La cohérence atteignable doit être passée explicitement — voir [`Coherence`].
    pub async fn dump(&self, target: &MariaTarget, coherence: Coherence) -> Result<Vec<u8>> {
        let mut env = target.env();
        // Utilisateur en variable d'environnement plutôt qu'en argument, par symétrie
        // avec le mot de passe.
        env.push(("MYSQL_USER".into(), target.user.clone()));

        let mut args = Self::dump_args(&target.database, coherence);
        // `mariadb-dump` ne lit pas MYSQL_USER : il faut le lui donner. Le mot de
        // passe, lui, vient bien de MYSQL_PWD — c'est l'argument dangereux qu'on
        // évite, pas le nom d'utilisateur.
        args.insert(1, format!("--user={}", target.user));

        let out = self.runner.run(&args, &env).await?;

        if out.status != 0 {
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: out.stderr.trim().to_string(),
            });
        }

        verifier_complet(&target.database, &out.stdout)?;

        tracing::info!(
            database = %target.database,
            octets = out.stdout.len(),
            coherence = ?coherence,
            "dump MariaDB produit"
        );
        Ok(out.stdout)
    }

    /// Restaure un dump dans le serveur.
    ///
    /// ⚠️ Le dump portant `CREATE DATABASE`/`USE`, il se restaure au niveau du serveur
    /// et recrée sa base lui-même.
    pub async fn restore(&self, target: &MariaTarget, dump: &[u8]) -> Result<()> {
        // 🔴 On refuse de restaurer un dump tronqué. Le laisser passer produirait une
        // base à qui il manque des tables, sans une seule erreur — le mode de panne
        // que toute cette vérification existe pour empêcher.
        verifier_complet(&target.database, dump)?;

        let args = vec![
            "mariadb".to_string(),
            format!("--user={}", target.user),
        ];

        let mut env = target.env();
        env.push(("HLB_STDIN_B64".into(), crate::pgdump::base64_encode(dump)));

        let out = self.runner.run(&args, &env).await?;
        if out.status != 0 {
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: out.stderr.trim().to_string(),
            });
        }
        tracing::info!(database = %target.database, "dump MariaDB restauré");
        Ok(())
    }
}

/// Refuse un dump qui ne porte pas la ligne de garde finale.
///
/// 🔴 C'est la vérification centrale de ce module. Un dump MariaDB est du texte écrit
/// au fil de l'eau : interrompu à mi-course, il reste du SQL valide, simplement amputé.
/// Restauré, il donne une base incomplète **sans une seule erreur**.
///
/// La ligne de garde n'est écrite qu'après le dernier octet utile. Sa présence est la
/// seule preuve que le processus est allé au bout.
pub fn verifier_complet(database: &str, dump: &[u8]) -> Result<()> {
    if dump.is_empty() {
        return Err(Error::Dump {
            database: database.to_string(),
            stderr: "dump vide".into(),
        });
    }

    // La ligne de garde est en fin de fichier : inutile de balayer un dump de plusieurs
    // gigaoctets. 4 Kio couvrent très largement la ligne et ce qui la suit.
    let queue = &dump[dump.len().saturating_sub(4096)..];

    if !String::from_utf8_lossy(queue).contains(LIGNE_DE_GARDE) {
        return Err(Error::Dump {
            database: database.to_string(),
            stderr: format!(
                "dump TRONQUÉ : la ligne de garde « {LIGNE_DE_GARDE} » est absente. \
                 Le fichier reste du SQL valide mais il lui manque la fin, et le \
                 restaurer donnerait une base incomplète sans erreur. \
                 Causes usuelles : disque plein, conteneur tué, connexion coupée."
            ),
        });
    }
    Ok(())
}

/// La requête qui dit si `--single-transaction` peut tenir sa promesse.
///
/// 🔴 Elle doit être posée **avant** chaque dump, pas une fois pour toutes : une
/// migration d'app peut introduire une table MyISAM des mois après l'installation, et
/// le dump deviendrait silencieusement incohérent.
pub fn requete_moteurs(database: &str) -> String {
    format!(
        "SELECT DISTINCT ENGINE FROM information_schema.TABLES \
         WHERE TABLE_SCHEMA = '{database}' AND ENGINE IS NOT NULL"
    )
}

/// Déduit la cohérence atteignable de la liste des moteurs en présence.
///
/// ⚠️ Une liste **vide** ne vaut pas « tout va bien » : elle veut dire qu'on n'a rien
/// pu lire, et l'on retombe alors sur le verrouillage. Conclure à l'InnoDB par défaut
/// serait exactement l'erreur que ce module cherche à empêcher.
pub fn coherence_pour(moteurs: &[String]) -> Coherence {
    if moteurs.is_empty() {
        return Coherence::VerrouillageRequis;
    }

    let risque = moteurs.iter().any(|m| {
        NON_TRANSACTIONNEL
            .iter()
            .any(|nt| nt.eq_ignore_ascii_case(m.trim()))
    });

    if risque {
        Coherence::VerrouillageRequis
    } else {
        Coherence::Transactionnelle
    }
}

/// Production et archivage planifiés, pendant de [`crate::pgdump::scheduled`].
pub mod scheduled {
    use super::*;
    use crate::pgdump::scheduled::Dump;

    /// Produit le dump d'une base MariaDB.
    pub async fn produce<R: DumpRunner>(
        dumper: &MariaDumper<R>,
        app: &str,
        target: &MariaTarget,
        coherence: Coherence,
        at: i64,
    ) -> Result<Dump> {
        let bytes = dumper.dump(target, coherence).await?;
        Ok(Dump {
            app: app.to_string(),
            database: target.database.clone(),
            // `.sql` et non `.dump` : c'est du texte, et le nom doit le dire pour
            // qu'on ne tente pas un `pg_restore` dessus le jour de l'incident.
            filename: nom_de_fichier(app, &target.database, at),
            bytes,
        })
    }

    /// Le nom de fichier d'un dump MariaDB.
    pub fn nom_de_fichier(app: &str, database: &str, at: i64) -> String {
        let (y, m, d, hh, mm, ss) = crate::pitr::civil_public(at);
        format!("{app}-{database}-{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z.sql")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgdump::RawOutput;

    /// Un runner qui rend ce qu'on lui dit, pour éprouver la logique sans serveur.
    struct Faux {
        sortie: Vec<u8>,
        status: i32,
        vus: std::sync::Mutex<Vec<String>>,
    }

    impl Faux {
        fn nouveau(sortie: &str, status: i32) -> Self {
            Self {
                sortie: sortie.as_bytes().to_vec(),
                status,
                vus: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn arguments(&self) -> String {
            self.vus.lock().expect("verrou").join(" ")
        }
    }

    #[async_trait::async_trait]
    impl DumpRunner for Faux {
        async fn run(&self, args: &[String], _env: &[(String, String)]) -> Result<RawOutput> {
            *self.vus.lock().expect("verrou") = args.to_vec();
            Ok(RawOutput {
                status: self.status,
                stdout: self.sortie.clone(),
                stderr: String::new(),
            })
        }
    }

    fn cible() -> MariaTarget {
        MariaTarget {
            host: "mariadb".into(),
            port: 3306,
            database: "app".into(),
            user: "admin".into(),
            password: "s3cr3t".into(),
        }
    }

    const DUMP_COMPLET: &str =
        "-- MariaDB dump\nCREATE TABLE t(i int);\n-- Dump completed on 2026-08-17\n";

    #[test]
    fn routines_triggers_and_events_are_always_asked_for() {
        // 🔴 Aucun des trois n'est pris par défaut par mariadb-dump. Sans eux, le dump
        // réussit, restaure sans erreur, et l'app est subtilement cassée : un
        // déclencheur manquant ne se voit qu'à la première écriture concernée.
        let args = MariaDumper::<Faux>::dump_args("app", Coherence::Transactionnelle).join(" ");
        assert!(args.contains("--routines"), "{args}");
        assert!(args.contains("--triggers"), "{args}");
        assert!(args.contains("--events"), "{args}");
    }

    #[test]
    fn comments_are_never_disabled() {
        // 🔴 `--skip-comments` supprimerait la ligne de garde finale, donc notre seul
        // moyen de détecter un dump tronqué. L'option ne doit jamais apparaître.
        for c in [Coherence::Transactionnelle, Coherence::VerrouillageRequis] {
            let args = MariaDumper::<Faux>::dump_args("app", c).join(" ");
            assert!(!args.contains("skip-comments"), "{args}");
            assert!(!args.contains("--compact"), "{args}");
        }
    }

    #[test]
    fn single_transaction_is_never_used_on_non_transactional_tables() {
        // 🔴 Sur MyISAM, `--single-transaction` est accepté SANS AVERTISSEMENT et
        // n'apporte aucune cohérence. On croit tenir un instantané ; on a une copie
        // étalée dans le temps. Il faut le verrou, malgré son coût.
        let t = MariaDumper::<Faux>::dump_args("app", Coherence::Transactionnelle).join(" ");
        assert!(t.contains("--single-transaction"), "{t}");
        assert!(!t.contains("--lock-tables"), "{t}");

        let v = MariaDumper::<Faux>::dump_args("app", Coherence::VerrouillageRequis).join(" ");
        assert!(
            !v.contains("--single-transaction"),
            "une promesse de cohérence que l'option ne peut pas tenir : {v}"
        );
        assert!(v.contains("--lock-tables"), "{v}");
    }

    #[test]
    fn a_myisam_table_forces_locking() {
        assert_eq!(
            coherence_pour(&["InnoDB".into()]),
            Coherence::Transactionnelle
        );
        // Une seule table non transactionnelle suffit à contaminer tout le dump.
        assert_eq!(
            coherence_pour(&["InnoDB".into(), "MyISAM".into()]),
            Coherence::VerrouillageRequis
        );
        // La casse d'`information_schema` n'est pas garantie.
        assert_eq!(
            coherence_pour(&["myisam".into()]),
            Coherence::VerrouillageRequis
        );
        assert_eq!(coherence_pour(&["Aria".into()]), Coherence::VerrouillageRequis);
    }

    #[test]
    fn an_unreadable_engine_list_is_not_a_green_light() {
        // 🔴 Le même invariant que « un outil de scan absent n'est pas un feu vert » :
        // ne rien avoir pu lire ne veut pas dire « tout est en InnoDB ». Conclure à la
        // cohérence par défaut, c'est produire un dump incohérent en silence.
        assert_eq!(coherence_pour(&[]), Coherence::VerrouillageRequis);
    }

    #[test]
    fn a_truncated_dump_is_refused() {
        // 🔴 LE mode de panne du module. Un dump interrompu reste du SQL valide,
        // simplement amputé : restauré, il donne une base à qui il manque des tables,
        // sans une seule erreur.
        let tronque = "-- MariaDB dump\nCREATE TABLE t(i int);\nINSERT INTO t VALUES (1),";
        let e = verifier_complet("app", tronque.as_bytes()).expect_err("doit être refusé");
        let m = e.to_string();
        assert!(m.contains("TRONQUÉ"), "{m}");
        assert!(m.contains("disque plein"), "la cause doit être suggérée : {m}");

        verifier_complet("app", DUMP_COMPLET.as_bytes()).expect("dump complet accepté");
    }

    #[test]
    fn an_empty_dump_is_refused() {
        // Même pour une base sans table, l'en-tête et la ligne de garde sont écrits.
        let e = verifier_complet("app", b"").expect_err("doit être refusé");
        assert!(e.to_string().contains("vide"));
    }

    #[test]
    fn the_guard_line_is_looked_for_at_the_end_only() {
        // Un dump où « Dump completed » apparaîtrait dans les DONNÉES, mais qui serait
        // tronqué, doit rester refusé : la ligne de garde ne compte qu'en fin de
        // fichier. On la noie sous plus de 4 Kio de contenu.
        let mut faux = String::from("INSERT INTO t VALUES ('-- Dump completed');\n");
        faux.push_str(&"-- remplissage\n".repeat(400));
        assert!(faux.len() > 4096, "le leurre doit sortir de la fenêtre");
        assert!(verifier_complet("app", faux.as_bytes()).is_err());
    }

    #[tokio::test]
    async fn the_password_never_reaches_the_command_line() {
        // 🔴 Un mot de passe en argument est lisible par tout utilisateur via `ps`.
        // MariaDB le signale lui-même sur stderr — trop tard, le secret est exposé.
        let f = Faux::nouveau(DUMP_COMPLET, 0);
        let d = MariaDumper::new(f);
        d.dump(&cible(), Coherence::Transactionnelle)
            .await
            .expect("dump");

        let args = d.runner.arguments();
        assert!(!args.contains("s3cr3t"), "mot de passe en argument : {args}");
        assert!(!args.contains("--password"), "{args}");
    }

    #[tokio::test]
    async fn a_truncated_dump_is_refused_by_the_dumper_too() {
        // Le code de sortie 0 ne suffit pas : mariadb-dump peut être tué en cours
        // d'écriture sans que le shell le rapporte.
        let f = Faux::nouveau("CREATE TABLE t(i int);\n", 0);
        let d = MariaDumper::new(f);
        let e = d
            .dump(&cible(), Coherence::Transactionnelle)
            .await
            .expect_err("un dump sans ligne de garde doit être refusé malgré le status 0");
        assert!(e.to_string().contains("TRONQUÉ"));
    }

    #[tokio::test]
    async fn restoring_a_truncated_dump_is_refused() {
        // On vérifie AUSSI à la restauration : le dump peut avoir été tronqué après
        // sa production, dans le dépôt ou pendant le transfert.
        let f = Faux::nouveau("", 0);
        let d = MariaDumper::new(f);
        let e = d
            .restore(&cible(), b"CREATE TABLE t(i int);")
            .await
            .expect_err("restauration d'un dump tronqué");
        assert!(e.to_string().contains("TRONQUÉ"));
    }

    #[test]
    fn the_filename_says_it_is_text() {
        // 🔴 Un dump MariaDB n'est pas au format custom de PostgreSQL. Le jour de
        // l'incident, l'extension doit empêcher de tenter un pg_restore dessus.
        let n = scheduled::nom_de_fichier("nextcloud", "nc", 1_755_000_000);
        assert!(n.ends_with(".sql"), "{n}");
        assert!(n.starts_with("nextcloud-nc-"), "{n}");
    }

    #[test]
    fn the_engine_query_targets_one_database() {
        // Sans le filtre, on lirait les moteurs de TOUTES les bases du serveur et une
        // table MyISAM d'une autre app forcerait un verrou inutile.
        let q = requete_moteurs("gitea");
        assert!(q.contains("TABLE_SCHEMA = 'gitea'"), "{q}");
    }
}
