//! What each side wrote since the site took over, read for `hlb site return`
//! (`hlb_engine::site_return` compares them).
//!
//! Every position is read against the one the promotion recorded, each by the clock that
//! wrote it: the house's against the house's, the site's against the site's.

use hlb_backup::{images, sqlite_ship, volume_ship};
use hlb_bootstrap::Runner;
use hlb_engine::lifeboat::PROMOTED_MARK;
use hlb_engine::site_return::{self, Seen, Wrote};
use hlb_orchestrator::{Orchestrator as _, SwarmOrchestrator};
use hlb_state::State;
use hlb_types::{DbServer, VITAL_POSTGRES};

type Result<T> = std::result::Result<T, String>;

/// What comes home, as the comparison needs it.
pub struct Coming<'a> {
    pub apps: &'a [String],
    /// `(app, database, server)`.
    pub databases: Vec<(String, String, DbServer)>,
    /// `(app, volume)`.
    pub volumes: Vec<(String, String)>,
}

/// A script's output, run on the site as root.
async fn on_site(ssh: &dyn Runner, script: String) -> Result<String> {
    let out = ssh
        .run(&["sh".into(), "-c".into(), script])
        .await
        .map_err(|e| format!("the site: {e}"))?;
    if !out.ok() {
        return Err(format!("the site: {}", out.stderr.trim()));
    }
    Ok(out.stdout)
}

/// A script's output, run in a running task of `service` at home.
async fn at_home(house: &SwarmOrchestrator, service: &str, script: String) -> Result<String> {
    let out = house
        .exec_in_service(service, &["sh".into(), "-c".into(), script])
        .await
        .map_err(|e| format!("{service} at home: {e}"))?;
    if !out.ok() {
        return Err(format!("{service} at home: {}", out.stderr.trim()));
    }
    Ok(out.stdout)
}

fn number(out: &str, key: &str) -> Option<u64> {
    sqlite_ship::probed(out, key).and_then(|v| v.parse().ok())
}

/// Everything that comes home, each with what either side wrote of it.
pub async fn seen(
    state: &State,
    house: &SwarmOrchestrator,
    ssh: &dyn Runner,
    coming: &Coming<'_>,
) -> Vec<Seen> {
    let mut seen = Vec::new();
    seen.extend(databases(house, ssh, &coming.databases).await);
    seen.extend(sqlite(state, house, ssh, coming.apps).await);
    seen.extend(volumes(state, house, ssh, coming).await);
    seen
}

async fn databases(
    house: &SwarmOrchestrator,
    ssh: &dyn Runner,
    databases: &[(String, String, DbServer)],
) -> Vec<Seen> {
    let mut seen = Vec::new();
    let vital: Vec<&str> = databases
        .iter()
        .filter(|(_, _, s)| *s == DbServer::PostgresVital)
        .map(|(_, d, _)| d.as_str())
        .collect();
    if !vital.is_empty() {
        let site = on_site(ssh, site_return::site_xid_script()).await;
        let parted = site.as_deref().ok().and_then(|o| number(o, "parted"));
        let site_now = site.and_then(|o| {
            number(&o, "now").ok_or_else(|| format!("the site's {VITAL_POSTGRES} did not answer"))
        });
        let house_now = at_home(
            house,
            VITAL_POSTGRES,
            format!(
                "psql -U postgres -X -qtA -c '{}'",
                site_return::NEXT_XID_SQL
            ),
        )
        .await
        .and_then(|o| {
            o.trim()
                .parse::<u64>()
                .map_err(|_| format!("{VITAL_POSTGRES} at home said {:?}", o.trim()))
        });
        seen.push(Seen {
            what: format!("{VITAL_POSTGRES} ({})", vital.join(", ")),
            house: site_return::by_transactions(parted, house_now),
            site: site_return::by_transactions(parted, site_now),
        });
    }
    // 🔴 Exhaustive: a server added to `DbServer` must say how its position is read.
    for (app, db, server) in databases {
        match server {
            DbServer::PostgresVital => {}
            DbServer::Postgres | DbServer::Mariadb => {
                let why = "it reached the site as a nightly dump, which holds no position";
                seen.push(Seen {
                    what: format!("{app}'s database {db}"),
                    house: Wrote::Unknown(why.into()),
                    site: Wrote::Unknown(why.into()),
                })
            }
        }
    }
    seen
}

async fn sqlite(
    state: &State,
    house: &SwarmOrchestrator,
    ssh: &dyn Runner,
    apps: &[String],
) -> Vec<Seen> {
    let carried = match super::litestream::carried_among(state, apps).await {
        Ok(c) => c,
        Err(e) => {
            let why = format!("the vital SQLite databases could not be listed: {e}");
            return vec![Seen {
                what: "SQLite".into(),
                house: Wrote::Unknown(why.clone()),
                site: Wrote::Unknown(why),
            }];
        }
    };
    let mut seen = Vec::new();
    for c in carried {
        let what = format!("{}'s SQLite in {}", c.app, c.volume);
        // Found through Litestream's container, which mounts the volume: the app's own
        // may be held stopped.
        let pusher = match c.user() {
            Ok(u) => u,
            Err(e) => {
                seen.push(unknown(what, e.to_string()));
                continue;
            }
        };
        let dbs = match at_home(
            house,
            &pusher,
            sqlite_ship::discover_script(sqlite_ship::MOUNTED_AT),
        )
        .await
        .and_then(|o| sqlite_ship::parse_discovered(&o).map_err(|e| e.to_string()))
        {
            Ok(Some((_, dbs))) => dbs,
            Ok(None) => continue,
            Err(e) => {
                seen.push(unknown(what, e));
                continue;
            }
        };
        let positions = at_home(house, &pusher, sqlite_ship::house_position_script(&dbs)).await;
        let site = on_site(
            ssh,
            sqlite_ship::site_since_script(&c.volume, &dbs, images::LITESTREAM, PROMOTED_MARK),
        )
        .await;
        for db in &dbs {
            let restored = site
                .as_deref()
                .ok()
                .and_then(|o| sqlite_ship::probed(o, &format!("{db}.txid")))
                .and_then(sqlite_ship::parse_txid);
            let house_now = positions
                .as_deref()
                .map(|o| sqlite_ship::probed(o, db).and_then(sqlite_ship::parse_txid))
                .map_err(Clone::clone);
            let (marked, written) = match &site {
                Ok(o) => (
                    number(o, &format!("{db}.marked")),
                    Ok(number(o, &format!("{db}.written"))),
                ),
                Err(e) => (None, Err(e.clone())),
            };
            seen.push(Seen {
                what: format!("{}'s SQLite {db}", c.app),
                house: site_return::by_litestream(restored, house_now),
                site: site_return::by_time(marked, written),
            });
        }
    }
    seen
}

async fn volumes(
    state: &State,
    house: &SwarmOrchestrator,
    ssh: &dyn Runner,
    coming: &Coming<'_>,
) -> Vec<Seen> {
    let pushed: Vec<String> = match super::volumes::carried_among(state, coming.apps).await {
        Ok((c, _)) => c.into_iter().map(|c| c.pushed.volume).collect(),
        Err(_) => Vec::new(),
    };
    let mut seen = Vec::new();
    for (app, volume) in &coming.volumes {
        let what = format!("{app}'s volume {volume}");
        let site = on_site(
            ssh,
            volume_ship::site_since_script(volume, images::RCLONE, PROMOTED_MARK),
        )
        .await;
        let (laid, marked, site_newest) = match &site {
            Ok(o) => (
                number(o, &format!("{volume}.pushed")),
                number(o, &format!("{volume}.marked")),
                Ok(number(o, &format!("{volume}.newest"))),
            ),
            Err(e) => (None, None, Err(e.clone())),
        };
        let house_side = if pushed.contains(volume) {
            let newest = match volume_ship::user(volume) {
                Ok(pusher) => at_home(house, &pusher, volume_ship::newest_script())
                    .await
                    .map(|o| number(&o, "newest")),
                Err(e) => Err(e),
            };
            site_return::by_time(laid, newest)
        } else {
            Wrote::Unknown("carried by the nightly copy alone: no round to compare with".into())
        };
        seen.push(Seen {
            what,
            house: house_side,
            site: site_return::by_time(marked, site_newest),
        });
    }
    seen
}

fn unknown(what: String, why: String) -> Seen {
    Seen {
        what,
        house: Wrote::Unknown(why.clone()),
        site: Wrote::Unknown(why),
    }
}
