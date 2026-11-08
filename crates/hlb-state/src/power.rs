//! The UPS, as NUT says it, and the stop the privileged side ordered when the house ran on
//! its battery. Read only toward NUT: the machines themselves are shut down by NUT's own
//! `upsmon`, once every app is stopped.

use sqlx::Row;

use crate::{Result, State};

/// One reading of the UPS's variables.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpsReading {
    /// `ups.status`, its flags as NUT wrote them: `OL`, `OB LB`, `FSD OB LB`…
    pub status: String,
    /// `battery.runtime`, in seconds, where the UPS gives one.
    pub runtime_s: Option<i64>,
    /// `battery.charge`, in percent.
    pub charge: Option<i64>,
}

impl UpsReading {
    fn flag(&self, f: &str) -> bool {
        self.status.split_whitespace().any(|s| s == f)
    }

    /// Running on its battery: the mains are gone.
    pub fn on_battery(&self) -> bool {
        self.flag("OB")
    }

    /// The UPS says its battery is low, or its primary ordered every machine down (`FSD`):
    /// no time is left to wait.
    pub fn exhausted(&self) -> bool {
        self.flag("LB") || self.flag("FSD")
    }

    /// On the mains, and not on battery: some UPS say `OL OB` for a moment.
    pub fn online(&self) -> bool {
        self.flag("OL") && !self.on_battery()
    }
}

/// The last reading, and since when its state lasts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpsState {
    pub read_at: Option<i64>,
    pub failed_at: Option<i64>,
    pub error: Option<String>,
    /// The last good reading's.
    pub reading: Option<UpsReading>,
    pub on_battery_since: Option<i64>,
    pub online_since: Option<i64>,
}

/// Where a stop for the power stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerPhase {
    /// Waves being stopped.
    Stopping,
    /// Everything stopped: waiting for the mains, or for NUT to shut the machines down.
    Stopped,
    /// The mains are back: waves being started again.
    Starting,
}

impl PowerPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Starting => "starting",
        }
    }

    /// 🔴 A phase this binary does not know reads as stopping: the stop is finished
    /// again, never taken for apps that run.
    fn parse(s: &str) -> Self {
        match s {
            "stopped" => Self::Stopped,
            "starting" => Self::Starting,
            _ => Self::Stopping,
        }
    }
}

/// The stop ordered for the power.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerStop {
    pub phase: PowerPhase,
    pub reason: String,
    pub started_at: i64,
    pub phase_at: i64,
    /// The waves, in the order they stop, each service with the replicas it ran.
    pub waves: Vec<Vec<(String, u64)>>,
}

/// When the house stops its apps for the power.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpsPolicy {
    /// NUT's server, `host:port`; `None`: no UPS is read.
    pub server: Option<String>,
    /// The UPS's name on that server (`upsc -l` lists them).
    pub ups: String,
    /// On battery this long, the apps stop: most outages are shorter.
    pub after_s: i64,
    /// Or once the UPS says less runtime than this is left — the time the waves take.
    pub runtime_s: i64,
    /// Back on the mains this long, the apps start again: a flickering line would
    /// start and stop them with every flicker.
    pub steady_s: i64,
}

impl Default for UpsPolicy {
    fn default() -> Self {
        Self {
            server: None,
            ups: "ups".into(),
            after_s: 300,
            runtime_s: 600,
            steady_s: 120,
        }
    }
}

const SERVER_KEY: &str = "ups-server";
const NAME_KEY: &str = "ups-name";
const AFTER_KEY: &str = "ups-after-s";
const RUNTIME_KEY: &str = "ups-runtime-s";
const STEADY_KEY: &str = "ups-steady-s";

impl State {
    /// The house's rule: no UPS until one is set.
    pub async fn ups_policy(&self) -> Result<UpsPolicy> {
        let d = UpsPolicy::default();
        let secs = |v: Option<String>, or: i64| v.and_then(|v| v.parse().ok()).unwrap_or(or);
        Ok(UpsPolicy {
            server: self.setting(SERVER_KEY).await?,
            ups: self.setting(NAME_KEY).await?.unwrap_or(d.ups),
            after_s: secs(self.setting(AFTER_KEY).await?, d.after_s),
            runtime_s: secs(self.setting(RUNTIME_KEY).await?, d.runtime_s),
            steady_s: secs(self.setting(STEADY_KEY).await?, d.steady_s),
        })
    }

    pub async fn set_ups_policy(&self, p: &UpsPolicy) -> Result<()> {
        self.put_setting(SERVER_KEY, p.server.as_deref()).await?;
        self.put_setting(NAME_KEY, Some(&p.ups)).await?;
        self.put_setting(AFTER_KEY, Some(&p.after_s.to_string()))
            .await?;
        self.put_setting(RUNTIME_KEY, Some(&p.runtime_s.to_string()))
            .await?;
        self.put_setting(STEADY_KEY, Some(&p.steady_s.to_string()))
            .await
    }

    /// The UPS's last reading; `None` before the first.
    pub async fn ups_state(&self) -> Result<Option<UpsState>> {
        let row = sqlx::query(
            "SELECT read_at, failed_at, error, status, runtime_s, charge,
                    on_battery_since, online_since
             FROM ups_reading WHERE one = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| {
            let status: Option<String> = r.try_get("status")?;
            Ok(UpsState {
                read_at: r.try_get("read_at")?,
                failed_at: r.try_get("failed_at")?,
                error: r.try_get("error")?,
                reading: match status {
                    Some(status) => Some(UpsReading {
                        status,
                        runtime_s: r.try_get("runtime_s")?,
                        charge: r.try_get("charge")?,
                    }),
                    None => None,
                },
                on_battery_since: r.try_get("on_battery_since")?,
                online_since: r.try_get("online_since")?,
            })
        })
        .transpose()
    }

    /// Records a reading: a failure keeps the last good one, and since when it lasted.
    pub async fn record_ups(
        &self,
        at: i64,
        reading: std::result::Result<&UpsReading, &str>,
    ) -> Result<UpsState> {
        let before = self.ups_state().await?.unwrap_or_default();
        match reading {
            Ok(r) => {
                // A state that lasts keeps its start; a new one begins now.
                let on_battery_since = r
                    .on_battery()
                    .then(|| before.on_battery_since.unwrap_or(at));
                let online_since = r.online().then(|| before.online_since.unwrap_or(at));
                sqlx::query(
                    "INSERT INTO ups_reading (one, read_at, status, runtime_s, charge,
                         on_battery_since, online_since)
                     VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT (one) DO UPDATE SET read_at = ?1, status = ?2,
                         runtime_s = ?3, charge = ?4, on_battery_since = ?5,
                         online_since = ?6, failed_at = NULL, error = NULL",
                )
                .bind(at)
                .bind(&r.status)
                .bind(r.runtime_s)
                .bind(r.charge)
                .bind(on_battery_since)
                .bind(online_since)
                .execute(&self.pool)
                .await?;
            }
            Err(why) => {
                sqlx::query(
                    "INSERT INTO ups_reading (one, failed_at, error) VALUES (1, ?1, ?2)
                     ON CONFLICT (one) DO UPDATE SET failed_at = ?1, error = ?2",
                )
                .bind(at)
                .bind(why)
                .execute(&self.pool)
                .await?;
            }
        }
        Ok(self.ups_state().await?.unwrap_or_default())
    }

    /// The stop ordered for the power, if one is under way or not yet undone.
    pub async fn power_stop(&self) -> Result<Option<PowerStop>> {
        let row = sqlx::query(
            "SELECT phase, reason, started_at, phase_at, waves FROM power_stop WHERE one = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        row.map(|r| {
            let phase: String = r.try_get("phase")?;
            let waves: String = r.try_get("waves")?;
            Ok(PowerStop {
                phase: PowerPhase::parse(&phase),
                reason: r.try_get("reason")?,
                started_at: r.try_get("started_at")?,
                phase_at: r.try_get("phase_at")?,
                waves: serde_json::from_str(&waves).map_err(crate::Error::StoredPower)?,
            })
        })
        .transpose()
    }

    /// Writes the stop BEFORE anything stops: `false` when one is already recorded.
    pub async fn begin_power_stop(
        &self,
        reason: &str,
        waves: &[Vec<(String, u64)>],
        at: i64,
    ) -> Result<bool> {
        let done = sqlx::query(
            "INSERT OR IGNORE INTO power_stop (one, phase, reason, started_at, phase_at, waves)
             VALUES (1, ?1, ?2, ?3, ?3, ?4)",
        )
        .bind(PowerPhase::Stopping.as_str())
        .bind(reason)
        .bind(at)
        .bind(serde_json::to_string(waves).map_err(crate::Error::StoredPower)?)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    pub async fn set_power_phase(&self, phase: PowerPhase, at: i64) -> Result<()> {
        sqlx::query("UPDATE power_stop SET phase = ?1, phase_at = ?2 WHERE one = 1")
            .bind(phase.as_str())
            .bind(at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Ends the stop: every wave is started again.
    pub async fn clear_power_stop(&self) -> Result<()> {
        sqlx::query("DELETE FROM power_stop WHERE one = 1")
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(status: &str) -> UpsReading {
        UpsReading {
            status: status.into(),
            runtime_s: Some(900),
            charge: Some(80),
        }
    }

    #[test]
    fn the_flags_are_read_one_by_one() {
        assert!(reading("OL").online() && !reading("OL").on_battery());
        assert!(reading("OB DISCHRG").on_battery() && !reading("OB").exhausted());
        assert!(reading("OB LB").exhausted() && reading("FSD OL").exhausted());
        // Some UPS say both for a moment: on battery wins.
        assert!(!reading("OL OB").online());
        // `LBX` is not `LB`.
        assert!(!reading("OL LBX").exhausted());
    }

    #[tokio::test]
    async fn a_state_that_lasts_keeps_its_start() {
        let s = State::in_memory().await.expect("state");
        let st = s.record_ups(10, Ok(&reading("OL"))).await.expect("read");
        assert_eq!((st.online_since, st.on_battery_since), (Some(10), None));
        let st = s.record_ups(20, Ok(&reading("OB"))).await.expect("read");
        assert_eq!((st.online_since, st.on_battery_since), (None, Some(20)));
        let st = s.record_ups(30, Ok(&reading("OB LB"))).await.expect("read");
        assert_eq!(st.on_battery_since, Some(20));
        // A failed reading keeps what was known, and since when.
        let st = s.record_ups(40, Err("refused")).await.expect("failed");
        assert_eq!(
            (st.read_at, st.failed_at, st.on_battery_since),
            (Some(30), Some(40), Some(20))
        );
        assert_eq!(st.reading.expect("kept").status, "OB LB");
        let st = s
            .record_ups(50, Ok(&reading("OL CHRG")))
            .await
            .expect("read");
        assert_eq!((st.online_since, st.error), (Some(50), None));
    }

    #[tokio::test]
    async fn a_stop_is_written_once_and_read_back_with_its_waves() {
        let s = State::in_memory().await.expect("state");
        let waves = vec![
            vec![("gitea".to_string(), 1)],
            vec![("postgres".to_string(), 1)],
        ];
        assert!(s
            .begin_power_stop("on battery", &waves, 5)
            .await
            .expect("begin"));
        assert!(!s.begin_power_stop("again", &[], 6).await.expect("once"));
        s.set_power_phase(PowerPhase::Stopped, 7)
            .await
            .expect("phase");
        let p = s.power_stop().await.expect("read").expect("one");
        assert_eq!(
            (p.phase, p.started_at, p.phase_at),
            (PowerPhase::Stopped, 5, 7)
        );
        assert_eq!(p.waves, waves);
        s.clear_power_stop().await.expect("clear");
        assert_eq!(s.power_stop().await.expect("read"), None);
    }

    #[tokio::test]
    async fn no_ups_is_read_until_one_is_set() {
        let s = State::in_memory().await.expect("state");
        assert_eq!(s.ups_policy().await.expect("read"), UpsPolicy::default());
        let p = UpsPolicy {
            server: Some("10.0.0.2:3493".into()),
            ups: "eaton".into(),
            after_s: 60,
            ..UpsPolicy::default()
        };
        s.set_ups_policy(&p).await.expect("set");
        assert_eq!(s.ups_policy().await.expect("read"), p);
    }
}
