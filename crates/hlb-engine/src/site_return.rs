//! Which side keeps its writes when the site comes home: what each wrote past the point
//! where they parted, compared, and the choice it leaves.
//!
//! A house serving its LAN through a cut ([`OnCut::Serve`]) is written beside a promoted
//! site; two copies written apart cannot be merged. Each side's position is read against
//! the one the promotion recorded as it took over — the vital server's next transaction,
//! each SQLite's Litestream transaction, each volume's round — and the return keeps
//! whichever side alone wrote, asking only when both did.
//!
//! 🔴 **A position that cannot be read is a side that wrote.** Taken for "nothing", it
//! would choose unasked; taken for "something", it costs a question. And the side not
//! kept is never dropped: the house's is copied before each restore replaces it, the
//! site's read into the house's backups, both named by the return.

use crate::site_guard::OnCut;

/// A PostgreSQL server's next transaction id, the whole 64 bits: what the promotion
/// records as the sides part and what each side is read at by the return. A session
/// that writes nothing takes none.
pub const NEXT_XID_SQL: &str = "SELECT pg_snapshot_xmax(pg_current_snapshot())";

/// Run on the site as root: the vital server's next transaction as the promotion
/// recorded it (`parted=`) and as it is (`now=`), empty when unread.
pub fn site_xid_script() -> String {
    let vital = hlb_types::VITAL_POSTGRES;
    let recorded = crate::lifeboat::PROMOTED_XID;
    format!(
        r#"echo "parted=$(cat {recorded} 2>/dev/null)"
id=$(docker ps -q --filter label=com.docker.swarm.service.name={vital} | head -n 1)
echo "now=$([ -z "$id" ] || docker exec -u postgres "$id" psql -X -qtA -c '{NEXT_XID_SQL}')"
"#
    )
}

/// What one side wrote of one thing since the two parted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wrote {
    No,
    Yes(String),
    /// Its position could not be read, or the promotion recorded none: counted as written.
    Unknown(String),
}

impl Wrote {
    pub fn counts(&self) -> bool {
        !matches!(self, Wrote::No)
    }

    pub fn said(&self) -> String {
        match self {
            Wrote::No => "nothing".into(),
            Wrote::Yes(w) => w.clone(),
            Wrote::Unknown(why) => format!("unknown ({why}): counted as written"),
        }
    }
}

/// One thing both sides hold, and what each wrote of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub what: String,
    pub house: Wrote,
    pub site: Wrote,
}

/// A side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keep {
    House,
    Site,
}

impl Keep {
    pub const fn as_str(self) -> &'static str {
        match self {
            Keep::House => "house",
            Keep::Site => "site",
        }
    }
}

/// What the return does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// That side's copy is the one served from now on, for this reason.
    Keep(Keep, &'static str),
    /// Both wrote, and nothing says which wins: the owner says.
    Ask,
}

/// The choice, from what was seen and what the owner asked, if anything.
///
/// The house stopping on a cut ([`OnCut::Stop`], the default) was held from before the
/// site took over: what it shows past the parting point is the tail the link never
/// carried, which the site's writes replace as they always did. Serving its LAN, it is
/// a person's work of the outage.
pub fn choose(on_cut: OnCut, asked: Option<Keep>, seen: &[Seen]) -> Choice {
    if let Some(k) = asked {
        return Choice::Keep(k, "asked");
    }
    let house = seen.iter().any(|s| s.house.counts());
    let site = seen.iter().any(|s| s.site.counts());
    match (house, site, on_cut) {
        (_, false, _) => Choice::Keep(Keep::House, "the site wrote nothing since it took over"),
        (false, true, _) => Choice::Keep(Keep::Site, "the house wrote nothing past it"),
        (true, true, OnCut::Stop) => Choice::Keep(
            Keep::Site,
            "the house stops on a cut: what it shows past the site is what the link never \
             carried",
        ),
        (true, true, OnCut::Serve) => Choice::Ask,
    }
}

/// A transaction counter against the one recorded where the sides parted: the vital
/// server's next transaction id. Each side starts from the same, so any other number is
/// a transaction run since — a read-only session takes none.
pub fn by_transactions(recorded: Option<u64>, now: Result<u64, String>) -> Wrote {
    match (recorded, now) {
        (None, _) => Wrote::Unknown("the promotion recorded no position".into()),
        (_, Err(e)) => Wrote::Unknown(e),
        (Some(r), Ok(n)) if n == r => Wrote::No,
        (Some(r), Ok(n)) if n > r => Wrote::Yes(format!(
            "{} transaction{}",
            n - r,
            if n - r == 1 { "" } else { "s" }
        )),
        (Some(r), Ok(n)) => Wrote::Unknown(format!(
            "at transaction {n}, before the {r} the sides parted at: another server"
        )),
    }
}

/// A Litestream position against the transaction the promotion restored. Only the same
/// transaction is "nothing": a Litestream restarted where it could not reach its replica
/// may number afresh, and a lower number is no proof of silence.
pub fn by_litestream(recorded: Option<u64>, now: Result<Option<u64>, String>) -> Wrote {
    match (recorded, now) {
        (None, _) => Wrote::Unknown("the site restored no replica of it".into()),
        (_, Err(e)) => Wrote::Unknown(e),
        (_, Ok(None)) => Wrote::Unknown("Litestream holds no position at home".into()),
        (Some(r), Ok(Some(n))) if n == r => Wrote::No,
        (Some(r), Ok(Some(n))) if n > r => Wrote::Yes(format!(
            "{} Litestream transaction{}",
            n - r,
            if n - r == 1 { "" } else { "s" }
        )),
        (Some(_), Ok(Some(_))) => {
            Wrote::Unknown("Litestream numbered afresh since: its position says nothing".into())
        }
    }
}

/// A newest modification time against a reference read off the SAME clock: never the
/// house's against the site's.
pub fn by_time(reference: Option<u64>, newest: Result<Option<u64>, String>) -> Wrote {
    match (reference, newest) {
        (None, _) => Wrote::Unknown("no point to compare with".into()),
        (_, Err(e)) => Wrote::Unknown(e),
        (_, Ok(None)) => Wrote::Unknown("its files could not be read".into()),
        (Some(r), Ok(Some(n))) if n > r => Wrote::Yes(format!("changed {} s past it", n - r)),
        (Some(_), Ok(Some(_))) => Wrote::No,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(house: Wrote, site: Wrote) -> Vec<Seen> {
        vec![Seen {
            what: "vaultwarden".into(),
            house,
            site,
        }]
    }

    fn yes() -> Wrote {
        Wrote::Yes("1 transaction".into())
    }

    #[test]
    fn the_one_side_that_wrote_is_kept_unasked() {
        for on_cut in [OnCut::Stop, OnCut::Serve] {
            assert!(matches!(
                choose(on_cut, None, &seen(Wrote::No, yes())),
                Choice::Keep(Keep::Site, _)
            ));
            assert!(matches!(
                choose(on_cut, None, &seen(yes(), Wrote::No)),
                Choice::Keep(Keep::House, _)
            ));
            assert!(matches!(
                choose(on_cut, None, &seen(Wrote::No, Wrote::No)),
                Choice::Keep(Keep::House, _)
            ));
        }
    }

    #[test]
    fn both_written_while_the_lan_was_served_is_asked() {
        assert_eq!(choose(OnCut::Serve, None, &seen(yes(), yes())), Choice::Ask);
        // An unreadable side counts: never chosen unasked on a guess.
        let unknown = Wrote::Unknown("unreachable".into());
        assert_eq!(
            choose(OnCut::Serve, None, &seen(unknown.clone(), yes())),
            Choice::Ask
        );
        assert_eq!(
            choose(OnCut::Serve, None, &seen(yes(), unknown)),
            Choice::Ask
        );
        assert_eq!(
            choose(OnCut::Serve, Some(Keep::House), &seen(yes(), yes())),
            Choice::Keep(Keep::House, "asked")
        );
    }

    #[test]
    fn a_house_that_stopped_shows_only_the_tail_and_the_site_wins() {
        assert!(matches!(
            choose(OnCut::Stop, None, &seen(yes(), yes())),
            Choice::Keep(Keep::Site, _)
        ));
    }

    #[test]
    fn one_thing_written_on_each_side_is_both_written() {
        let two = vec![
            Seen {
                what: "a".into(),
                house: yes(),
                site: Wrote::No,
            },
            Seen {
                what: "b".into(),
                house: Wrote::No,
                site: yes(),
            },
        ];
        assert_eq!(choose(OnCut::Serve, None, &two), Choice::Ask);
    }

    #[test]
    fn transactions_are_compared_with_where_the_sides_parted() {
        assert_eq!(by_transactions(Some(900), Ok(900)), Wrote::No);
        assert_eq!(
            by_transactions(Some(900), Ok(903)),
            Wrote::Yes("3 transactions".into())
        );
        assert!(matches!(by_transactions(None, Ok(900)), Wrote::Unknown(_)));
        assert!(matches!(
            by_transactions(Some(900), Err("down".into())),
            Wrote::Unknown(_)
        ));
        assert!(matches!(
            by_transactions(Some(900), Ok(12)),
            Wrote::Unknown(_)
        ));
    }

    #[test]
    fn only_the_same_litestream_transaction_is_silence() {
        assert_eq!(by_litestream(Some(0x99), Ok(Some(0x99))), Wrote::No);
        assert!(by_litestream(Some(0x99), Ok(Some(0x9a))).counts());
        // Numbered afresh after a restart that could not reach the replica.
        assert!(matches!(
            by_litestream(Some(0x99), Ok(Some(3))),
            Wrote::Unknown(_)
        ));
        assert!(matches!(
            by_litestream(Some(0x99), Ok(None)),
            Wrote::Unknown(_)
        ));
        assert!(matches!(
            by_litestream(None, Ok(Some(0x99))),
            Wrote::Unknown(_)
        ));
    }

    #[test]
    fn a_time_counts_only_past_its_reference() {
        assert_eq!(by_time(Some(100), Ok(Some(100))), Wrote::No);
        assert_eq!(by_time(Some(100), Ok(Some(40))), Wrote::No);
        assert!(by_time(Some(100), Ok(Some(101))).counts());
        assert!(matches!(by_time(None, Ok(Some(1))), Wrote::Unknown(_)));
        assert!(matches!(by_time(Some(1), Ok(None)), Wrote::Unknown(_)));
    }
}
