//! Roles, who holds them, which apps let them in, and the quotas they carry.
//!
//! The rules live in `hlb_users::access`; this is where their inputs are kept.

use std::collections::{BTreeMap, BTreeSet};

use hlb_users::{MailLimits, RoleDef};
use sqlx::Row;

use crate::{Error, Result, State};

/// Who holds which role, as the accounts screen lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub user: String,
    /// The role's id; `None` for an account given none.
    pub role: Option<String>,
    /// What it may do to Homelabus — the lowest level for no role, or one that no
    /// longer exists.
    pub level: hlb_types::Role,
    /// Who gave it: the first question asked after an incident.
    pub granted_by: Option<String>,
    pub granted_at: Option<String>,
}

/// A quota given to one person in one app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonQuota {
    pub app: String,
    /// `None`: none at all, even where their role has one.
    pub bytes: Option<u64>,
    pub set_by: String,
    pub set_at: String,
}

/// Why a role cannot be deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InUse {
    HeldBy(Vec<String>),
    LetInto(Vec<String>),
    Invited(usize),
}

impl std::fmt::Display for InUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeldBy(people) => {
                write!(f, "held by {} — give them another first", people.join(", "))
            }
            Self::LetInto(apps) => write!(
                f,
                "let into {} — `hlb role deny` it there first, or those apps close",
                apps.join(", ")
            ),
            Self::Invited(n) => write!(
                f,
                "{n} open invitation(s) grant it — revoke them first, or the link creates \
                 an account with no role"
            ),
        }
    }
}

fn level_of(s: &str) -> hlb_types::Role {
    hlb_types::Role::parse(s).unwrap_or_default()
}

fn as_u32(v: i64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

impl State {
    /// Every role, with its quotas, by id.
    pub async fn roles(&self) -> Result<Vec<RoleDef>> {
        let mut quotas: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for r in sqlx::query("SELECT role, app, bytes FROM role_quotas")
            .fetch_all(&self.pool)
            .await?
        {
            quotas.entry(r.try_get("role")?).or_default().insert(
                r.try_get("app")?,
                r.try_get::<i64, _>("bytes")?.max(0) as u64,
            );
        }
        let rows = sqlx::query(
            "SELECT id, name, level, max_mailboxes, max_permanent_aliases,
                    max_temporary_aliases, max_duration_s, mail_quota_bytes
             FROM roles ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let id: String = r.try_get("id")?;
                Ok(RoleDef {
                    name: r.try_get("name")?,
                    level: level_of(&r.try_get::<String, _>("level")?),
                    mail: MailLimits {
                        max_mailboxes: as_u32(r.try_get("max_mailboxes")?),
                        max_permanent_aliases: as_u32(r.try_get("max_permanent_aliases")?),
                        max_temporary_aliases: as_u32(r.try_get("max_temporary_aliases")?),
                        max_duration_s: r.try_get("max_duration_s")?,
                        quota_bytes: r
                            .try_get::<Option<i64>, _>("mail_quota_bytes")?
                            .map(|b| b.max(0) as u64),
                    },
                    quotas: quotas.remove(&id).unwrap_or_default(),
                    id,
                })
            })
            .collect()
    }

    pub async fn role(&self, id: &str) -> Result<Option<RoleDef>> {
        Ok(self.roles().await?.into_iter().find(|r| r.id == id))
    }

    /// The role a person holds — [`RoleDef::nothing`] for none, or one that no longer
    /// exists: never more than the lowest.
    pub async fn role_of(&self, user: &str) -> Result<RoleDef> {
        let held: Option<String> = sqlx::query("SELECT role FROM users WHERE name = ?1")
            .bind(user)
            .fetch_optional(&self.pool)
            .await?
            .and_then(|r| r.try_get("role").ok())
            .flatten();
        Ok(match held {
            Some(id) => self.role(&id).await?.unwrap_or_else(RoleDef::nothing),
            None => RoleDef::nothing(),
        })
    }

    /// Creates a role, or writes over its name, level and mail limits. Its quotas are
    /// set one app at a time ([`Self::set_role_quota`]).
    pub async fn put_role(&self, role: &RoleDef, by: &str) -> Result<()> {
        if !hlb_types::access::valid_role_id(&role.id) {
            return Err(Error::InvalidRole(role.id.clone()));
        }
        let m = &role.mail;
        sqlx::query(
            "INSERT INTO roles (id, name, level, max_mailboxes, max_permanent_aliases,
                                max_temporary_aliases, max_duration_s, mail_quota_bytes,
                                created_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name, level = excluded.level,
               max_mailboxes = excluded.max_mailboxes,
               max_permanent_aliases = excluded.max_permanent_aliases,
               max_temporary_aliases = excluded.max_temporary_aliases,
               max_duration_s = excluded.max_duration_s,
               mail_quota_bytes = excluded.mail_quota_bytes",
        )
        .bind(&role.id)
        .bind(&role.name)
        .bind(role.level.as_str())
        .bind(i64::from(m.max_mailboxes))
        .bind(i64::from(m.max_permanent_aliases))
        .bind(i64::from(m.max_temporary_aliases))
        .bind(m.max_duration_s)
        .bind(m.quota_bytes.map(|b| b as i64))
        .bind(by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// What still uses the role, if anything does.
    pub async fn role_in_use(&self, id: &str, now: i64) -> Result<Option<InUse>> {
        let held: Vec<String> = sqlx::query("SELECT name FROM users WHERE role = ?1 ORDER BY name")
            .bind(id)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(|r| r.try_get("name"))
            .collect::<std::result::Result<_, _>>()?;
        if !held.is_empty() {
            return Ok(Some(InUse::HeldBy(held)));
        }
        let apps: Vec<String> =
            sqlx::query("SELECT app FROM app_roles WHERE role = ?1 ORDER BY app")
                .bind(id)
                .fetch_all(&self.pool)
                .await?
                .iter()
                .map(|r| r.try_get("app"))
                .collect::<std::result::Result<_, _>>()?;
        if !apps.is_empty() {
            return Ok(Some(InUse::LetInto(apps)));
        }
        let open: i64 = sqlx::query(
            "SELECT COUNT(*) AS n FROM invitations
             WHERE role = ?1 AND uses < max_uses AND expires_at > ?2",
        )
        .bind(id)
        .bind(now)
        .fetch_one(&self.pool)
        .await?
        .try_get("n")?;
        Ok((open > 0).then_some(InUse::Invited(open as usize)))
    }

    /// Deletes a role nothing uses. Returns whether it existed; the caller checks
    /// [`Self::role_in_use`] first and says why when it refuses.
    pub async fn delete_role(&self, id: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM roles WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// A role's quota in an app; `None` removes it.
    pub async fn set_role_quota(&self, role: &str, app: &str, bytes: Option<u64>) -> Result<()> {
        match bytes {
            Some(b) => {
                sqlx::query(
                    "INSERT INTO role_quotas (role, app, bytes) VALUES (?1, ?2, ?3)
                     ON CONFLICT(role, app) DO UPDATE SET bytes = excluded.bytes",
                )
                .bind(role)
                .bind(app)
                .bind(b as i64)
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM role_quotas WHERE role = ?1 AND app = ?2")
                    .bind(role)
                    .bind(app)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Gives a person a role. The role must exist: an id naming none would read as no
    /// role at all, which is not what anyone giving it meant.
    pub async fn set_user_role(
        &self,
        user: &str,
        role: &str,
        granted_by: Option<&str>,
    ) -> Result<()> {
        if self.role(role).await?.is_none() {
            return Err(Error::UnknownRole(role.to_string()));
        }
        sqlx::query(
            "UPDATE users SET role = ?2, role_granted_by = ?3, role_granted_at = datetime('now')
             WHERE name = ?1",
        )
        .bind(user)
        .bind(role)
        .bind(granted_by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// A person's permission level, read on EVERY request.
    ///
    /// 🔴 No role, a role that no longer exists, an unreadable level: all three are
    /// `Role::default()`, that is `user`. A PocketID identity unknown to Homelabus
    /// comes in at the lowest level, never higher.
    pub async fn user_role(&self, user: &str) -> Result<hlb_types::Role> {
        let row = sqlx::query(
            "SELECT r.level AS level FROM users u JOIN roles r ON r.id = u.role
             WHERE u.name = ?1",
        )
        .bind(user)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row
            .and_then(|r| r.try_get::<String, _>("level").ok())
            .and_then(|s| hlb_types::Role::parse(&s))
            .unwrap_or_default())
    }

    /// Takes a person's role away: the lowest level, nothing to create, no app.
    pub async fn clear_user_role(&self, user: &str) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE users SET role = NULL, role_granted_by = NULL, role_granted_at = NULL
             WHERE name = ?1 AND role IS NOT NULL",
        )
        .bind(user)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Every account and the role it holds.
    pub async fn users_with_roles(&self) -> Result<Vec<Holder>> {
        let rows = sqlx::query(
            "SELECT u.name AS name, u.role AS role, r.level AS level,
                    u.role_granted_by AS granted_by, u.role_granted_at AS granted_at
             FROM users u LEFT JOIN roles r ON r.id = u.role
             ORDER BY u.name",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(Holder {
                    user: r.try_get("name")?,
                    role: r.try_get("role")?,
                    level: r
                        .try_get::<Option<String>, _>("level")?
                        .map(|l| level_of(&l))
                        .unwrap_or_default(),
                    granted_by: r.try_get("granted_by")?,
                    granted_at: r.try_get("granted_at")?,
                })
            })
            .collect()
    }

    /// Is there an administrator other than this person?
    ///
    /// 🔴 Used to refuse demoting the last admin: a system with nobody able to grant
    /// rights can only be repaired by editing the database by hand.
    pub async fn has_other_admin(&self, except: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM users u JOIN roles r ON r.id = u.role
             WHERE r.level = 'admin' AND u.name <> ?1",
        )
        .bind(except)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get::<i64, _>("n")? > 0)
    }

    /// The roles each installed app lets in.
    pub async fn app_roles(&self) -> Result<BTreeMap<String, BTreeSet<String>>> {
        let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for r in sqlx::query("SELECT app, role FROM app_roles ORDER BY app, role")
            .fetch_all(&self.pool)
            .await?
        {
            out.entry(r.try_get("app")?)
                .or_default()
                .insert(r.try_get("role")?);
        }
        Ok(out)
    }

    /// Lets a role into an installed app. Returns whether it was not already.
    pub async fn allow_role(&self, app: &str, role: &str, by: &str) -> Result<bool> {
        let r = sqlx::query(
            "INSERT INTO app_roles (app, role, granted_by) VALUES (?1, ?2, ?3)
             ON CONFLICT(app, role) DO NOTHING",
        )
        .bind(app)
        .bind(role)
        .bind(by)
        .execute(&self.pool)
        .await;
        match r {
            Ok(r) => Ok(r.rows_affected() > 0),
            // The foreign key on `apps`: allowing a role into an app not installed.
            Err(sqlx::Error::Database(e)) if e.is_foreign_key_violation() => {
                Err(Error::UnknownApp(app.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Stops letting a role into an app. Returns whether it was let in.
    pub async fn deny_role(&self, app: &str, role: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM app_roles WHERE app = ?1 AND role = ?2")
            .bind(app)
            .bind(role)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// The quotas given to people themselves, by person.
    pub async fn person_quotas(&self) -> Result<BTreeMap<String, Vec<PersonQuota>>> {
        let mut out: BTreeMap<String, Vec<PersonQuota>> = BTreeMap::new();
        for r in sqlx::query(
            "SELECT user, app, bytes, set_by, set_at FROM person_quotas ORDER BY user, app",
        )
        .fetch_all(&self.pool)
        .await?
        {
            out.entry(r.try_get("user")?)
                .or_default()
                .push(PersonQuota {
                    app: r.try_get("app")?,
                    bytes: r
                        .try_get::<Option<i64>, _>("bytes")?
                        .map(|b| b.max(0) as u64),
                    set_by: r.try_get("set_by")?,
                    set_at: r.try_get("set_at")?,
                });
        }
        Ok(out)
    }

    /// Gives a person their own quota in an app: `Some(None)` is none at all, `None`
    /// takes theirs away and their role's applies again.
    pub async fn set_person_quota(
        &self,
        user: &str,
        app: &str,
        quota: Option<Option<u64>>,
        by: &str,
    ) -> Result<()> {
        match quota {
            Some(bytes) => {
                sqlx::query(
                    "INSERT INTO person_quotas (user, app, bytes, set_by) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(user, app) DO UPDATE SET
                       bytes = excluded.bytes, set_by = excluded.set_by,
                       set_at = datetime('now')",
                )
                .bind(user)
                .bind(app)
                .bind(bytes.map(|b| b as i64))
                .bind(by)
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM person_quotas WHERE user = ?1 AND app = ?2")
                    .bind(user)
                    .bind(app)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }
}

/// Where a person's quota stands inside an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaState {
    Applied,
    /// They have no account there yet: retried at every sync.
    Absent,
    Failed,
}

impl QuotaState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Absent => "absent",
            Self::Failed => "failed",
        }
    }
    fn parse(s: &str) -> Self {
        match s {
            "applied" => Self::Applied,
            "absent" => Self::Absent,
            _ => Self::Failed,
        }
    }
}

/// What a quota last became, for one person in one app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaRecord {
    pub bytes: Option<u64>,
    pub state: QuotaState,
    pub detail: Option<String>,
    pub at: i64,
}

/// What an administrator's right last became, for one person in one app — its state
/// read as a quota's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRecord {
    pub admin: bool,
    pub state: QuotaState,
    pub detail: Option<String>,
    pub at: i64,
}

impl State {
    /// What each person's administrator right last became, by `(person, app)`.
    pub async fn admins_applied(&self) -> Result<BTreeMap<(String, String), AdminRecord>> {
        let mut out = BTreeMap::new();
        for r in sqlx::query("SELECT user, app, admin, state, detail, at FROM admin_applied")
            .fetch_all(&self.pool)
            .await?
        {
            out.insert(
                (r.try_get("user")?, r.try_get("app")?),
                AdminRecord {
                    admin: r.try_get::<i64, _>("admin")? == 1,
                    state: QuotaState::parse(&r.try_get::<String, _>("state")?),
                    detail: r.try_get("detail")?,
                    at: r.try_get("at")?,
                },
            );
        }
        Ok(out)
    }

    pub async fn record_admin(&self, user: &str, app: &str, record: &AdminRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO admin_applied (user, app, admin, state, detail, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(user, app) DO UPDATE SET admin = excluded.admin,
               state = excluded.state, detail = excluded.detail, at = excluded.at",
        )
        .bind(user)
        .bind(app)
        .bind(i64::from(record.admin))
        .bind(record.state.as_str())
        .bind(&record.detail)
        .bind(record.at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// What each person's quota last became, by `(person, app)`.
    pub async fn quotas_applied(&self) -> Result<BTreeMap<(String, String), QuotaRecord>> {
        let mut out = BTreeMap::new();
        for r in sqlx::query("SELECT user, app, bytes, state, detail, at FROM quota_applied")
            .fetch_all(&self.pool)
            .await?
        {
            out.insert(
                (r.try_get("user")?, r.try_get("app")?),
                QuotaRecord {
                    bytes: r
                        .try_get::<Option<i64>, _>("bytes")?
                        .map(|b| b.max(0) as u64),
                    state: QuotaState::parse(&r.try_get::<String, _>("state")?),
                    detail: r.try_get("detail")?,
                    at: r.try_get("at")?,
                },
            );
        }
        Ok(out)
    }

    pub async fn record_quota(&self, user: &str, app: &str, record: &QuotaRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO quota_applied (user, app, bytes, state, detail, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(user, app) DO UPDATE SET bytes = excluded.bytes,
               state = excluded.state, detail = excluded.detail, at = excluded.at",
        )
        .bind(user)
        .bind(app)
        .bind(record.bytes.map(|b| b as i64))
        .bind(record.state.as_str())
        .bind(&record.detail)
        .bind(record.at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn st() -> State {
        State::in_memory().await.expect("in-memory database")
    }

    #[tokio::test]
    async fn a_new_installation_starts_with_three_roles() {
        let s = st().await;
        let roles = s.roles().await.expect("roles");
        let ids: Vec<(&str, hlb_types::Role)> =
            roles.iter().map(|r| (r.id.as_str(), r.level)).collect();
        assert_eq!(
            ids,
            [
                ("admin", hlb_types::Role::Admin),
                ("guest", hlb_types::Role::User),
                ("standard", hlb_types::Role::User)
            ]
        );
        assert_eq!(roles[2].mail, MailLimits::standard());
        assert_eq!(roles[0].mail, MailLimits::unlimited());
    }

    #[tokio::test]
    async fn a_level_is_read_through_the_role_held() {
        let s = st().await;
        s.upsert_user("lena", "standard", None).await.expect("user");
        assert_eq!(
            s.user_role("lena").await.expect("level"),
            hlb_types::Role::User
        );
        s.set_user_role("lena", "admin", Some("cli"))
            .await
            .expect("role");
        assert_eq!(
            s.user_role("lena").await.expect("level"),
            hlb_types::Role::Admin
        );
        assert!(matches!(
            s.set_user_role("lena", "typo", None).await,
            Err(Error::UnknownRole(_))
        ));
        assert!(s.clear_user_role("lena").await.expect("clear"));
        assert_eq!(
            s.user_role("lena").await.expect("level"),
            hlb_types::Role::User
        );
        assert_eq!(s.role_of("lena").await.expect("role"), RoleDef::nothing());
    }

    #[tokio::test]
    async fn a_role_still_used_says_by_what() {
        let s = st().await;
        let mut family = RoleDef::new("family", hlb_types::Role::User, MailLimits::guest());
        family.name = "Family".into();
        s.put_role(&family, "lena").await.expect("role");
        assert_eq!(s.role_in_use("family", 0).await.expect("use"), None);
        s.upsert_user("sacha", "family", None).await.expect("user");
        assert_eq!(
            s.role_in_use("family", 0).await.expect("use"),
            Some(InUse::HeldBy(vec!["sacha".into()]))
        );
        assert!(
            s.put_role(
                &RoleDef::new("Bad Id", hlb_types::Role::User, MailLimits::guest()),
                "x"
            )
            .await
            .is_err(),
            "an id is a PocketID group name"
        );
    }

    #[tokio::test]
    async fn quotas_by_role_and_by_person_are_kept_apart() {
        let s = st().await;
        s.set_role_quota("standard", "immich", Some(50 << 30))
            .await
            .expect("quota");
        s.upsert_user("lena", "standard", None).await.expect("user");
        s.set_person_quota("lena", "immich", Some(None), "camille")
            .await
            .expect("own");
        assert_eq!(
            s.role("standard")
                .await
                .expect("role")
                .expect("exists")
                .quotas["immich"],
            50 << 30
        );
        let own = &s.person_quotas().await.expect("own")["lena"][0];
        assert_eq!((own.bytes, own.set_by.as_str()), (None, "camille"));
        s.set_person_quota("lena", "immich", None, "camille")
            .await
            .expect("cleared");
        assert!(s.person_quotas().await.expect("own").is_empty());
    }
}
