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
}

impl State {
    pub async fn zone(&self) -> Result<Option<ZoneConfig>> {
        let Some(r) = sqlx::query("SELECT apex, addresses, extra FROM zone WHERE id = 1")
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
        }))
    }

    pub async fn set_zone(&self, z: &ZoneConfig) -> Result<()> {
        sqlx::query(
            "INSERT INTO zone (id, apex, addresses, extra) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
               apex = excluded.apex, addresses = excluded.addresses, extra = excluded.extra,
               modified_at = datetime('now')",
        )
        .bind(&z.apex)
        .bind(z.addresses.join(" "))
        .bind(&z.extra)
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
    async fn the_zone_is_kept_as_declared_and_replaced_whole() {
        let s = State::in_memory().await.expect("state");
        assert_eq!(s.zone().await.expect("read"), None);
        let mut z = ZoneConfig {
            apex: "example.org".into(),
            addresses: vec!["203.0.113.4".into(), "2001:db8::4".into()],
            extra: "@ TXT \"x\"\n".into(),
        };
        s.set_zone(&z).await.expect("set");
        assert_eq!(s.zone().await.expect("read").as_ref(), Some(&z));
        z.addresses.truncate(1);
        z.extra.clear();
        s.set_zone(&z).await.expect("set again");
        assert_eq!(s.zone().await.expect("read"), Some(z));
    }
}
