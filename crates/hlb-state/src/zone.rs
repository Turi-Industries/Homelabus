//! The house's own zone, as `hlb zone set` declared it.

use sqlx::Row;

use crate::{Result, State};

/// The zone the house's Knot signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneConfig {
    /// `example.org`, normalized.
    pub apex: String,
    /// The front door's public addresses, as written.
    pub addresses: Vec<String>,
    /// The owner's own lines, relative to the apex.
    pub extra: String,
    /// The registrar delegates to it (`hlb zone switch`): what the house writes over
    /// RFC 2136 goes into it from then on.
    pub delegated: bool,
}

/// Stored names: the settings the zone's other records are kept under.
const MAIL: &str = "zone-mail-records";
const CAA: &str = "zone-caa-pins";
const DS: &str = "zone-parent-ds";
const DNSKEY: &str = "zone-parent-dnskey";

impl State {
    /// The lines of the house's mail the zone carries, as Stalwart computed them, kept
    /// by the last reading of its zones; empty before one.
    pub async fn zone_mail(&self) -> Result<String> {
        Ok(self.setting(MAIL).await?.unwrap_or_default())
    }

    /// Keeps them; `true` when they changed, and the zone must be published again.
    pub async fn keep_zone_mail(&self, lines: &str) -> Result<bool> {
        self.keep(MAIL, lines).await
    }

    /// The CAA records pinning the house's ACME accounts, from the last reading that
    /// read every one of them.
    pub async fn zone_caa(&self) -> Result<Vec<String>> {
        Ok(self
            .setting(CAA)
            .await?
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect())
    }

    /// Keeps them; `true` when they changed.
    pub async fn keep_zone_caa(&self, records: &[String]) -> Result<bool> {
        self.keep(CAA, &records.join("\n")).await
    }

    /// What the registrar must hold for the zone, as Knot last published it: each DS's
    /// data, then each key's. Empty before Knot first signed it.
    pub async fn zone_parent(&self) -> Result<(Vec<String>, Vec<String>)> {
        let lines = |v: Option<String>| -> Vec<String> {
            v.unwrap_or_default().lines().map(str::to_string).collect()
        };
        Ok((
            lines(self.setting(DS).await?),
            lines(self.setting(DNSKEY).await?),
        ))
    }

    /// Keeps them; `true` when they changed — Knot signs with another key, and the DS
    /// the registrar holds no longer names it.
    pub async fn keep_zone_parent(&self, ds: &[String], dnskey: &[String]) -> Result<bool> {
        let ds = self.keep(DS, &ds.join("\n")).await?;
        Ok(self.keep(DNSKEY, &dnskey.join("\n")).await? || ds)
    }

    async fn keep(&self, key: &str, value: &str) -> Result<bool> {
        if self.setting(key).await?.unwrap_or_default() == value {
            return Ok(false);
        }
        self.put_setting(key, Some(value)).await?;
        Ok(true)
    }

    pub async fn zone(&self) -> Result<Option<ZoneConfig>> {
        let Some(r) =
            sqlx::query("SELECT apex, addresses, extra, delegated FROM zone WHERE id = 1")
                .fetch_optional(&self.pool)
                .await?
        else {
            return Ok(None);
        };
        let addresses: String = r.try_get("addresses")?;
        Ok(Some(ZoneConfig {
            apex: r.try_get("apex")?,
            addresses: addresses.split_whitespace().map(str::to_string).collect(),
            extra: r.try_get("extra")?,
            delegated: r.try_get::<i64, _>("delegated")? != 0,
        }))
    }

    pub async fn set_zone(&self, z: &ZoneConfig) -> Result<()> {
        sqlx::query(
            "INSERT INTO zone (id, apex, addresses, extra, delegated) VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
               apex = excluded.apex, addresses = excluded.addresses, extra = excluded.extra,
               delegated = excluded.delegated, modified_at = datetime('now')",
        )
        .bind(&z.apex)
        .bind(z.addresses.join(" "))
        .bind(&z.extra)
        .bind(i64::from(z.delegated))
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::State;

    use super::ZoneConfig;

    #[tokio::test]
    async fn the_parents_records_are_kept_and_a_new_key_is_said() {
        let s = State::in_memory().await.expect("state");
        assert_eq!(
            s.zone_parent().await.expect("read"),
            (Vec::new(), Vec::new())
        );
        let ds = vec!["1 13 2 AB".to_string()];
        let key = vec!["257 3 13 k1".to_string()];
        assert!(s.keep_zone_parent(&ds, &key).await.expect("keep"));
        assert!(!s.keep_zone_parent(&ds, &key).await.expect("again"));
        assert_eq!(s.zone_parent().await.expect("read"), (ds.clone(), key));
        assert!(s
            .keep_zone_parent(&ds, &["257 3 13 k2".to_string()])
            .await
            .expect("a new key"));
    }

    #[tokio::test]
    async fn the_zone_is_kept_as_declared_and_replaced_whole() {
        let s = State::in_memory().await.expect("state");
        assert_eq!(s.zone().await.expect("read"), None);
        let mut z = ZoneConfig {
            apex: "example.org".into(),
            addresses: vec!["203.0.113.4".into(), "2001:db8::4".into()],
            extra: "@ TXT \"x\"\n".into(),
            delegated: false,
        };
        s.set_zone(&z).await.expect("set");
        assert_eq!(s.zone().await.expect("read").as_ref(), Some(&z));
        z.addresses.truncate(1);
        z.extra.clear();
        z.delegated = true;
        s.set_zone(&z).await.expect("set again");
        assert_eq!(s.zone().await.expect("read"), Some(z));
    }

    #[tokio::test]
    async fn the_zones_other_records_say_when_they_change() {
        let s = State::in_memory().await.expect("state");
        assert_eq!(s.zone_mail().await.expect("read"), "");
        assert!(s.keep_zone_mail("a. IN MX 10 b.").await.expect("keep"));
        assert!(!s.keep_zone_mail("a. IN MX 10 b.").await.expect("again"));
        assert_eq!(s.zone_mail().await.expect("read"), "a. IN MX 10 b.");

        assert!(s.zone_caa().await.expect("read").is_empty());
        let pins = vec!["0 issue \"a\"".to_string(), "0 issue \"b\"".to_string()];
        assert!(s.keep_zone_caa(&pins).await.expect("keep"));
        assert!(!s.keep_zone_caa(&pins).await.expect("again"));
        assert_eq!(s.zone_caa().await.expect("read"), pins);
    }
}
