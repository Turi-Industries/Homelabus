//! Réplication streaming PostgreSQL (§3.2, phase 2).
//!
//! ## Ce que ça change par rapport au PITR
//!
//! `hlb dr promote` restaure une sauvegarde de base et rejoue le WAL : RTO d'environ
//! vingt minutes. Un standby en réplication reçoit les modifications **en continu** et
//! se promeut en quelques secondes.
//!
//! Les deux ne se remplacent pas : le standby suit la primaire, donc il suit aussi ses
//! erreurs. Une table effacée par mégarde est répliquée immédiatement. C'est
//! l'instantané et le PITR qui protègent des erreurs humaines ; le standby protège de
//! la panne matérielle.
//!
//! ## 🔴 Le piège du slot de réplication
//!
//! C'est **exactement** le même que celui de l'`archive_command` (§8.1), et il se
//! paie de la même façon.
//!
//! Un slot garantit que la primaire conserve les segments WAL tant que le standby ne
//! les a pas consommés. C'est ce qui rend la réplication fiable — et ce qui la rend
//! dangereuse : si le standby s'arrête et que le slot reste, **`pg_wal` grossit
//! indéfiniment** jusqu'à saturer le disque de la primaire. Le standby était censé
//! protéger la production ; son absence la tue.
//!
//! D'où [`max_slot_wal_keep_size`] : au-delà, PostgreSQL invalide le slot et laisse
//! le WAL se recycler. Le standby devient irrécupérable et devra être reconstruit —
//! ce qui est **très préférable** à une primaire dont le disque est plein.
//!
//! ## 🔴 Pourquoi la réplication est ASYNCHRONE
//!
//! En synchrone, la primaire attend la confirmation du standby avant de valider
//! chaque transaction. Si le standby tombe, **la primaire se bloque** : plus aucune
//! écriture n'aboutit. Sur un homelab à deux nœuds, ça transforme la panne d'un nœud
//! de secours en panne totale — soit l'inverse de ce qu'on cherchait.
//!
//! Le coût de l'asynchrone est un RPO de quelques centaines de millisecondes. C'est
//! le bon compromis ici, et il est dit plutôt que subi.

use crate::{Error, Result};

/// Combien de WAL la primaire accepte de retenir pour un slot inactif.
///
/// 🔴 La valeur qui empêche un standby mort de tuer la primaire. À `-1` (le défaut
/// de PostgreSQL), la rétention est **illimitée** : c'est le comportement qui remplit
/// les disques.
///
/// 8 Go laisse largement le temps de redémarrer un standby après un incident, et
/// reste très en dessous de ce qui sature un disque de nœud.
pub const MAX_SLOT_WAL_KEEP: &str = "8GB";

/// Le nom du slot d'un standby.
///
/// ⚠️ PostgreSQL n'accepte que des minuscules, chiffres et « _ » : un nom d'hôte avec
/// un tiret est refusé, sur une erreur qui parle de syntaxe sans dire laquelle.
pub fn slot_name(standby: &str) -> Result<String> {
    let nettoye: String = standby
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();

    if nettoye.is_empty() || nettoye.len() > 55 {
        return Err(Error::Unexpected(format!(
            "« {standby} » : nom de standby inutilisable comme slot (1 à 55 caractères)"
        )));
    }
    Ok(format!("hlb_{nettoye}"))
}

/// Les réglages à poser sur la **primaire**.
///
/// ⚠️ `wal_level` et `max_wal_senders` exigent un redémarrage, comme pour l'archivage
/// (§8.1). Rechargés à chaud, ils sont acceptés sans erreur et restent sans effet :
/// la réplication paraît configurée et aucun standby ne peut se connecter.
pub fn primary_settings(max_standbys: u32) -> String {
    format!(
        "# Généré par Homelabus (§3.2) — primaire.\n\
         # ⚠️ wal_level et max_wal_senders exigent un REDÉMARRAGE, pas un reload.\n\
         wal_level = replica\n\
         # Un émetteur par standby, plus une marge pour pg_basebackup qui en\n\
         # consomme un le temps de la copie.\n\
         max_wal_senders = {}\n\
         max_replication_slots = {}\n\
         \n\
         # 🔴 LA ligne qui empêche un standby mort de saturer le disque de la\n\
         # primaire. Le défaut (-1) retient le WAL SANS LIMITE : au-delà de ce\n\
         # seuil, le slot est invalidé et le standby devra être reconstruit — très\n\
         # préférable à une primaire à l'arrêt faute de place.\n\
         max_slot_wal_keep_size = {MAX_SLOT_WAL_KEEP}\n\
         \n\
         # Asynchrone : en synchrone, la primaire se BLOQUE si le standby tombe.\n\
         # Sur deux nœuds, ça transforme la panne du secours en panne totale.\n\
         synchronous_commit = on\n\
         synchronous_standby_names = ''\n",
        max_standbys + 2,
        max_standbys + 2,
    )
}

/// Les réglages à poser sur le **standby**.
///
/// 🔴 `hot_standby = on` n'est pas un détail : sans lui, le standby ne répond à
/// aucune requête et l'on ne peut pas vérifier qu'il réplique — on découvrirait le
/// problème au moment de la promotion.
///
/// 🔴 **À appliquer APRÈS `pg_basebackup -R`, jamais avant.** Constaté contre un vrai
/// couple primaire/standby : `-R` écrit son PROPRE `primary_conninfo` dans
/// `postgresql.auto.conf`, sans `application_name`. Or `auto.conf` est lu **en
/// dernier** et écrase `postgresql.conf`. Posés avant, ces réglages sont donc
/// silencieusement perdus — voir [`APPLIQUER_APRES_BASEBACKUP`].
pub fn standby_settings(primary_host: &str, port: u16, slot: &str, user: &str) -> String {
    format!(
        "# Généré par Homelabus (§3.2) — standby.\n\
         # ⚠️ À écrire dans postgresql.auto.conf APRÈS `pg_basebackup -R` (qui\n\
         # réécrit ce fichier), ou à poser via ALTER SYSTEM. Avant, c'est perdu.\n\
         # ⚠️ Le fichier `standby.signal` (VIDE) doit exister dans le répertoire de\n\
         # données. Sans lui, PostgreSQL démarre comme une primaire indépendante et\n\
         # ne réplique RIEN — sans le moindre avertissement.\n\
         primary_conninfo = 'host={primary_host} port={port} user={user} \
         application_name={slot}'\n\
         primary_slot_name = '{slot}'\n\
         \n\
         # Répond aux requêtes en lecture : c'est ce qui permet de VÉRIFIER que la\n\
         # réplication avance, au lieu de le découvrir à la promotion.\n\
         hot_standby = on\n\
         \n\
         # Remonte sa position à la primaire, ce qui alimente pg_stat_replication\n\
         # et rend le retard mesurable.\n\
         hot_standby_feedback = on\n"
    )
}

/// Le nom sous lequel un standby s'annonce quand personne ne le lui a dit.
///
/// C'est le défaut de `walreceiver`, celui que produit `pg_basebackup -R` seul.
pub const NOM_PAR_DEFAUT: &str = "walreceiver";

/// L'avertissement d'ordre des opérations, à afficher par le CLI.
pub const APPLIQUER_APRES_BASEBACKUP: &str =
    "⚠️ Applique ces réglages APRÈS `pg_basebackup -R` : la commande réécrit\n\
     postgresql.auto.conf, qui est lu APRÈS postgresql.conf et l'emporte donc.\n\
     Posés avant, l'application_name est perdu et tous les standbys s'annoncent\n\
     « walreceiver » — impossible alors de savoir LEQUEL décroche.";

/// Les standbys qu'on ne sait pas distinguer les uns des autres.
///
/// 🔴 Deux standbys sous le même nom rendent `hlb replication status` inutile au pire
/// moment : on voit qu'un nœud décroche sans pouvoir dire lequel. Un seul standby
/// anonyme reste identifiable, donc ne mérite pas d'alerte.
pub fn indistinguishable(standbys: &[StandbyStatus]) -> Vec<String> {
    let mut noms: Vec<&str> = standbys
        .iter()
        .map(|s| s.application_name.as_str())
        .collect();
    noms.sort_unstable();

    let mut ambigus: Vec<String> = Vec::new();
    for nom in &noms {
        if noms.iter().filter(|n| *n == nom).count() > 1 && !ambigus.iter().any(|a| a == nom) {
            ambigus.push((*nom).to_string());
        }
    }
    ambigus
}

/// L'état d'un standby, tel que la primaire le voit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandbyStatus {
    pub application_name: String,
    /// `streaming`, `catchup`, `startup`…
    pub state: String,
    /// Retard en octets de WAL.
    pub lag_bytes: Option<i64>,
}

/// Le niveau d'attention que mérite un standby.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Il suit.
    Streaming,
    /// Il rattrape son retard — normal après un redémarrage.
    CatchingUp,
    /// 🔴 Il a décroché : le retard grandit, ou l'état n'est pas `streaming`.
    Lagging,
    /// 🔴 Absent de `pg_stat_replication` : il n'est plus connecté du tout.
    Disconnected,
}

/// Au-delà de ce retard, le standby ne suit plus vraiment.
///
/// 64 Mo = quatre segments WAL. En dessous, c'est le fonctionnement normal d'une base
/// qui écrit ; au-dessus, quelque chose ralentit — réseau, disque du standby, ou
/// standby arrêté depuis peu.
pub const RETARD_MAX_OCTETS: i64 = 64 * 1024 * 1024;

impl StandbyStatus {
    pub fn health(&self) -> Health {
        match self.state.as_str() {
            "streaming" if self.lag_bytes.is_some_and(|l| l > RETARD_MAX_OCTETS) => Health::Lagging,
            "streaming" => Health::Streaming,
            "catchup" | "startup" => Health::CatchingUp,
            _ => Health::Lagging,
        }
    }

    pub fn describe(&self) -> String {
        let retard = match self.lag_bytes {
            Some(l) if l < 1024 => format!("{l} o"),
            Some(l) if l < 1024 * 1024 => format!("{} Ko", l / 1024),
            Some(l) => format!("{} Mo", l / (1024 * 1024)),
            None => "?".into(),
        };

        match self.health() {
            Health::Streaming => format!("✓ {} suit ({retard} de retard)", self.application_name),
            Health::CatchingUp => {
                format!("🟠 {} rattrape ({retard})", self.application_name)
            }
            Health::Lagging => format!(
                "🔴 {} a décroché — état « {} », {retard} de retard",
                self.application_name, self.state
            ),
            Health::Disconnected => format!("🔴 {} n'est plus connecté", self.application_name),
        }
    }
}

/// Un slot inactif, qui retient du WAL pour rien.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanSlot {
    pub name: String,
    /// WAL retenu à cause de ce slot.
    pub retained_bytes: i64,
    /// PostgreSQL a-t-il déjà invalidé ce slot ?
    pub invalidated: bool,
}

impl OrphanSlot {
    /// Ce slot met-il la primaire en danger ?
    ///
    /// 🔴 Un slot invalidé ne retient plus rien : il est *inutile*, pas *dangereux*.
    /// Les confondre ferait crier au loup sur un slot que PostgreSQL a déjà neutralisé,
    /// et diluerait l'alerte qui compte.
    pub fn is_dangerous(&self) -> bool {
        !self.invalidated && self.retained_bytes > RETARD_MAX_OCTETS
    }

    pub fn describe(&self) -> String {
        if self.invalidated {
            return format!(
                "🟠 slot « {} » INVALIDÉ : il ne retient plus de WAL, mais le standby \
                 correspondant est irrécupérable et doit être reconstruit.",
                self.name
            );
        }
        if self.is_dangerous() {
            return format!(
                "🔴 slot « {} » retient {} Mo de WAL sans consommateur. Il remplit le \
                 disque de la PRIMAIRE. Redémarre le standby, ou supprime le slot :\n\
                 \x20   SELECT pg_drop_replication_slot('{}');",
                self.name,
                self.retained_bytes / (1024 * 1024),
                self.name
            );
        }
        // ⚠️ Ce cas n'est PAS « tout va bien » : `parse_slots` ne rend que les slots
        // SANS consommateur. Celui-ci retient encore peu de WAL, mais il retient — et
        // il grossira tant que le standby ne revient pas. Dire « actif » ici serait
        // l'inverse de la vérité.
        format!(
            "🟠 slot « {} » sans consommateur, {} Ko retenus pour l'instant. \
             Il grossira jusqu'à {MAX_SLOT_WAL_KEEP} puis sera invalidé.",
            self.name,
            self.retained_bytes / 1024
        )
    }
}

/// Analyse la sortie de `pg_stat_replication`.
///
/// Format attendu : `application_name|state|lag_bytes` par ligne.
pub fn parse_standbys(sortie: &str) -> Vec<StandbyStatus> {
    sortie
        .lines()
        .filter_map(|l| {
            let mut c = l.trim().split('|');
            let nom = c.next()?.trim();
            if nom.is_empty() {
                return None;
            }
            Some(StandbyStatus {
                application_name: nom.to_string(),
                state: c.next().unwrap_or("").trim().to_string(),
                lag_bytes: c.next().and_then(|v| v.trim().parse().ok()),
            })
        })
        .collect()
}

/// Analyse la sortie de `pg_replication_slots`.
///
/// Format attendu : `slot_name|active|retained_bytes|invalidated`.
pub fn parse_slots(sortie: &str) -> Vec<OrphanSlot> {
    sortie
        .lines()
        .filter_map(|l| {
            let mut c = l.trim().split('|');
            let nom = c.next()?.trim();
            if nom.is_empty() {
                return None;
            }
            let actif = c.next().unwrap_or("").trim() == "t";
            let retenu: i64 = c.next().and_then(|v| v.trim().parse().ok()).unwrap_or(0);
            let invalide = c.next().unwrap_or("").trim() == "t";

            // Un slot actif n'est jamais orphelin : quelqu'un le consomme.
            (!actif).then(|| OrphanSlot {
                name: nom.to_string(),
                retained_bytes: retenu,
                invalidated: invalide,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_primary_never_retains_wal_without_limit() {
        // 🔴 LE réglage de ce module. Le défaut de PostgreSQL (-1) retient le WAL
        // sans limite : un standby arrêté remplit alors le disque de la PRIMAIRE.
        // Le standby était censé la protéger ; son absence la tue.
        let s = primary_settings(1);
        assert!(s.contains("max_slot_wal_keep_size = 8GB"), "{s}");
        assert!(!s.contains("max_slot_wal_keep_size = -1"));
        assert!(s.contains("SANS LIMITE"), "l'avertissement doit être là");
    }

    #[test]
    fn replication_is_asynchronous_on_purpose() {
        // 🔴 En synchrone, la primaire SE BLOQUE si le standby tombe : sur deux
        // nœuds, la panne du secours devient une panne totale.
        let s = primary_settings(1);
        assert!(s.contains("synchronous_standby_names = ''"), "{s}");
        assert!(s.contains("panne totale"), "le choix doit être expliqué");
    }

    #[test]
    fn there_is_a_wal_sender_to_spare_for_the_base_backup() {
        // ⚠️ `pg_basebackup` consomme un émetteur le temps de la copie. Sans marge,
        // reconstruire un standby pendant qu'un autre réplique échoue.
        let s = primary_settings(1);
        assert!(s.contains("max_wal_senders = 3"), "{s}");
    }

    #[test]
    fn the_restart_requirement_is_stated() {
        // Rechargé à chaud, `wal_level` est accepté sans erreur et reste sans effet :
        // la réplication paraît configurée et aucun standby ne se connecte.
        assert!(primary_settings(1).contains("REDÉMARRAGE"));
    }

    #[test]
    fn the_standby_signal_file_is_announced() {
        // 🔴 Sans `standby.signal`, PostgreSQL démarre comme une primaire
        // indépendante et ne réplique RIEN — sans le moindre avertissement. C'est le
        // même piège que `recovery.signal` pour le PITR.
        let s = standby_settings("big-01", 5432, "hlb_small01", "replicant");
        assert!(s.contains("standby.signal"), "{s}");
        assert!(s.contains("ne réplique RIEN"), "{s}");
    }

    #[test]
    fn the_standby_answers_queries_so_replication_can_be_checked() {
        // Sans `hot_standby`, on ne peut pas vérifier que la réplication avance — on
        // le découvrirait à la promotion.
        let s = standby_settings("big-01", 5432, "hlb_x", "replicant");
        assert!(s.contains("hot_standby = on"), "{s}");
        assert!(s.contains("hot_standby_feedback = on"), "{s}");
    }

    #[test]
    fn slot_names_survive_a_hostname_with_a_dash() {
        // ⚠️ PostgreSQL refuse les tirets dans un nom de slot, sur une erreur de
        // syntaxe qui ne dit pas lequel.
        assert_eq!(slot_name("small-01").expect("nom"), "hlb_small_01");
        assert_eq!(slot_name("BIG-02.local").expect("nom"), "hlb_big_02_local");
        assert!(slot_name("").is_err());
    }

    #[test]
    fn a_streaming_standby_is_healthy() {
        let v = parse_standbys("hlb_small01|streaming|1024\n");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].health(), Health::Streaming);
        assert!(v[0].describe().contains("suit"));
    }

    #[test]
    fn a_standby_that_falls_behind_is_flagged() {
        // 64 Mo = quatre segments. En dessous c'est le fonctionnement normal ;
        // au-dessus, quelque chose ralentit.
        let v = parse_standbys("hlb_small01|streaming|200000000\n");
        assert_eq!(v[0].health(), Health::Lagging);
        assert!(v[0].describe().contains("décroché"), "{}", v[0].describe());
        assert!(v[0].describe().contains("190 Mo"), "{}", v[0].describe());
    }

    #[test]
    fn catching_up_is_not_an_alert() {
        // C'est l'état normal après un redémarrage du standby. Alerter dessus
        // apprendrait à ignorer l'alerte.
        let v = parse_standbys("hlb_small01|catchup|500000\n");
        assert_eq!(v[0].health(), Health::CatchingUp);
    }

    #[test]
    fn an_orphan_slot_that_fills_the_disk_is_the_loudest_alert() {
        // 🔴 Le mode de panne le plus coûteux : le standby était censé protéger la
        // primaire, et son absence la tue.
        let v = parse_slots("hlb_small01|f|500000000|f\n");
        assert_eq!(v.len(), 1);
        assert!(v[0].is_dangerous());
        assert!(
            v[0].describe().contains("disque de la PRIMAIRE"),
            "{}",
            v[0].describe()
        );
        // Le message doit donner la commande, pas seulement le constat.
        assert!(v[0].describe().contains("pg_drop_replication_slot"));
    }

    #[test]
    fn an_invalidated_slot_is_useless_not_dangerous() {
        // 🔴 Les confondre ferait crier au loup sur un slot que PostgreSQL a déjà
        // neutralisé, et diluerait l'alerte qui compte.
        let v = parse_slots("hlb_small01|f|0|t\n");
        assert!(!v[0].is_dangerous());
        assert!(v[0].describe().contains("INVALIDÉ"));
        assert!(
            v[0].describe().contains("reconstruit"),
            "il faut dire quoi faire"
        );
    }

    #[test]
    fn an_active_slot_is_never_an_orphan() {
        // Quelqu'un le consomme : il n'y a rien à signaler.
        assert!(parse_slots("hlb_small01|t|1000|f\n").is_empty());
    }

    #[test]
    fn standby_settings_warn_about_basebackup_order() {
        // 🔴 Constaté contre un vrai couple primaire/standby : `pg_basebackup -R`
        // écrit son propre primary_conninfo dans postgresql.auto.conf, SANS
        // application_name. Ce fichier étant lu en dernier, des réglages posés
        // avant sont silencieusement perdus. L'ordre doit être dit.
        let s = standby_settings("primaire.local", 5432, "hlb_nas", "repl");
        assert!(s.contains("application_name=hlb_nas"));
        assert!(
            s.contains("APRÈS") && s.contains("pg_basebackup"),
            "l'ordre des opérations doit être explicite : {s}"
        );
        assert!(APPLIQUER_APRES_BASEBACKUP.contains(NOM_PAR_DEFAUT));
    }

    #[test]
    fn two_standbys_under_the_same_name_are_flagged() {
        // 🔴 Le symptôme exact du piège précédent : sans application_name, tous les
        // standbys s'annoncent « walreceiver ». On voit alors qu'un nœud décroche
        // sans pouvoir dire lequel — un statut qui ment par ambiguïté.
        let anonyme = |lag| StandbyStatus {
            application_name: NOM_PAR_DEFAUT.to_string(),
            state: "streaming".into(),
            lag_bytes: Some(lag),
        };

        assert_eq!(
            indistinguishable(&[anonyme(0), anonyme(0)]),
            [NOM_PAR_DEFAUT]
        );

        // Un seul standby anonyme reste identifiable : pas d'alerte inutile.
        assert!(indistinguishable(&[anonyme(0)]).is_empty());

        // Des noms distincts non plus.
        let nomme = |n: &str| StandbyStatus {
            application_name: n.to_string(),
            state: "streaming".into(),
            lag_bytes: Some(0),
        };
        assert!(indistinguishable(&[nomme("hlb_a"), nomme("hlb_b")]).is_empty());

        // Et un nom en double n'en signale qu'un, pas deux fois.
        assert_eq!(
            indistinguishable(&[nomme("hlb_a"), nomme("hlb_a"), nomme("hlb_b")]),
            ["hlb_a"]
        );
    }

    #[test]
    fn a_young_orphan_slot_is_never_called_active() {
        // 🔴 Constaté contre un vrai PostgreSQL : la première version affichait
        // « ✓ slot actif » pour un slot SANS consommateur qui retenait encore peu
        // de WAL. C'était l'inverse de la vérité, sur le mode de panne le plus
        // coûteux du module.
        let v = parse_slots("hlb_small01|f|1000|f\n");
        assert_eq!(v.len(), 1);
        assert!(!v[0].is_dangerous(), "pas encore dangereux");

        let d = v[0].describe();
        assert!(
            !d.contains("actif"),
            "un slot sans consommateur n'est pas actif : {d}"
        );
        assert!(d.contains("sans consommateur"), "{d}");
        assert!(
            d.contains("grossira"),
            "il doit dire ce qui va se passer : {d}"
        );
    }

    #[test]
    fn empty_output_is_not_an_error() {
        assert!(parse_standbys("").is_empty());
        assert!(parse_slots("\n\n").is_empty());
    }
}
