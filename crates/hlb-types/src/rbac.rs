//! Roles and permissions.
//!
//! **Four roles, and not one more.** A fine-grained permission model is a source of
//! security bugs: every untested combination is a potential hole, and nobody re-reads
//! a matrix of thirty rights.
//!
//! Three of them - `viewer`, `operator`, `admin` - are **operations** roles. The one
//! that was missing is the person who simply has an account: a mailbox, some aliases,
//! a portal. Giving them `viewer` would open the cluster state, the secret names and
//! the audit log. Hence [`Role::User`], below everything else.
//!
//! ## Identities in PocketID, roles here
//!
//! *Identities* stay in PocketID - a single source of truth for "who is this person" -
//! but *roles* are assigned here. Managing access to Homelabus from PocketID's
//! interface, by editing groups only Homelabus knows the meaning of, would hide half
//! the model inside another product. [`Role::from_groups`] remains available for
//! anyone who prefers the group-driven scheme.
//!
//! ## Why [`Action`] is an exhaustive enum
//!
//! Same reason as `Capability`: adding a variant must **break compilation** everywhere
//! a decision has to be made. A free-string model (`"backup.restore"`) would silently
//! accept a misspelled permission that is never granted - or worse, never required.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Someone who has an account and nothing else: their mailbox, their aliases,
    /// the portal. This is **not** an operations role.
    ///
    /// It is the default, so it is what an unreadable token role and a PocketID
    /// identity unknown to Homelabus both get. The default must always be the least
    /// privileged.
    #[default]
    User,
    /// Tout voir de l'exploitation, ne rien modifier.
    Viewer,
    /// Day-to-day work: install, update, back up, publish.
    Operator,
    /// Everything, including what destroys and what grants rights.
    Admin,
}

/// What someone is trying to do.
///
/// 🔴 Exhaustive by construction: see the module header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Read one's own data: account, mailboxes, aliases, and the announcements
    /// addressed to them.
    ReadSelf,
    /// Act on one's own data: create an alias, set up Sieve sorting, pick a theme,
    /// revoke sessions.
    ActOnSelf,
    /// Read operations data: cluster state, nodes, logs, metrics, the secret
    /// inventory (their names), the audit log.
    Read,
    /// Publish an announcement, open or close an incident, declare a maintenance.
    Publish,
    /// Install, update, restart, back up, drain a node.
    Operate,
    /// Create an account, invite someone, change someone's role.
    ///
    /// Separate from [`Self::Destroy`] because it is not the same mistake: destroying
    /// loses data, granting a role loses control.
    ManageAccounts,
    /// 🔴 Destroy: `--purge`, restoring into production, removing a node, rekeying,
    /// tearing the cluster down.
    Destroy,
}

impl Action {
    /// The minimum role that allows this action.
    ///
    /// 🔴 This is **the only place** the matrix is written. An exhaustive `match`, so a
    /// variant added to [`Action`] will not compile until someone has decided who may
    /// do it - never a permissive default inherited by accident.
    pub fn minimum_role(&self) -> Role {
        match self {
            Self::ReadSelf | Self::ActOnSelf => Role::User,
            Self::Read => Role::Viewer,
            Self::Operate | Self::Publish => Role::Operator,
            Self::ManageAccounts | Self::Destroy => Role::Admin,
        }
    }

    /// The action's name as it appears in a refusal.
    ///
    /// A phrase, not an identifier: the message must read as-is in an interface
    /// ("*publish an announcement* requires...").
    /// The short, stable identifier, for the audit log.
    ///
    /// ⚠️ Distinct from `describe`, which is a phrase meant to be read. A log gets
    /// filtered: it needs a stable token, not a wording someone might rephrase.
    pub fn nom(&self) -> &'static str {
        match self {
            Self::ReadSelf => "lire-soi",
            Self::ActOnSelf => "agir-sur-soi",
            Self::Read => "lire",
            Self::Publish => "publier",
            Self::Operate => "operer",
            Self::ManageAccounts => "gerer-comptes",
            Self::Destroy => "detruire",
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::ReadSelf => "view your own account",
            Self::ActOnSelf => "change your own account",
            Self::Read => "view the state of the system",
            Self::Publish => "publish an announcement",
            Self::Operate => "act on the system",
            Self::ManageAccounts => "manage accounts and rights",
            Self::Destroy => "destroy, or restore into production",
        }
    }
}

impl Role {
    /// ⚠️ The French spellings are **legacy aliases**, not decoration.
    ///
    /// `as_str` used to write "utilisateur" and "lecteur" into `api_tokens.role` and
    /// `personnes.role`. Dropping them from `parse` would make every row written before
    /// the translation unreadable, and an unreadable role silently falls back to the
    /// least privileged one - so an administrator would quietly become a plain user.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "user" | "utilisateur" => Some(Self::User),
            "viewer" | "lecteur" => Some(Self::Viewer),
            "operator" | "operateur" => Some(Self::Operator),
            "admin" | "administrateur" => Some(Self::Admin),
            _ => None,
        }
    }

    /// The canonical form, and what gets written to the database from now on.
    ///
    /// Older rows may hold the French spelling; [`Role::parse`] still accepts it.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }

    /// What this role allows, in one line, for a rights-management screen.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::User => "their account, their mailbox, their aliases",
            Self::Viewer => "tout voir, ne rien modifier",
            Self::Operator => "install, update, back up, publish",
            Self::Admin => "everything, including destroying and granting rights",
        }
    }

    /// Does this role allow this action?
    ///
    /// Roles are ordered from least to most privileged, so a comparison is enough once
    /// the matrix is set by [`Action::minimum_role`] - and a role inserted in the
    /// middle would not create a silent hole.
    pub fn allows(&self, action: Action) -> bool {
        *self >= action.minimum_role()
    }

    /// 🔴 The wording of a refusal: **never a bare "forbidden"**.
    ///
    /// A greyed-out button with no explanation, or a naked `403`, leaves the person
    /// guessing whether they are on the wrong screen, the system is broken, or a right
    /// is missing. So the refusal names the action, the required role, the held role,
    /// and **who can grant it** - the only actionable form.
    ///
    /// Returns `None` when the action is allowed: the type carries the information, so
    /// a refusal cannot be displayed by mistake.
    pub fn refus(&self, action: Action) -> Option<String> {
        if self.allows(action) {
            return None;
        }
        let requis = action.minimum_role();
        Some(format!(
            "{} requires the \"{}\" role; yours is \"{}\". An administrator can grant it to you.",
            action.describe(),
            requis.as_str(),
            self.as_str(),
        ))
    }

    /// The role inferred from PocketID groups.
    ///
    /// Kept for anyone who prefers driving rights from PocketID rather than from
    /// Homelabus (see the module header). The highest wins: belonging to both
    /// `homelab-admins` and `homelab-users` gives `admin`, not the other way round.
    pub fn from_groups(groups: &[String], mapping: &[(String, Role)]) -> Self {
        groups
            .iter()
            .filter_map(|g| mapping.iter().find(|(nom, _)| nom == g).map(|(_, r)| *r))
            .max()
            .unwrap_or_default()
    }

    /// Every role, from least to most privileged.
    ///
    /// For populating a selection menu without a newly added role being forgotten.
    pub fn tous() -> [Role; 4] {
        [Self::User, Self::Viewer, Self::Operator, Self::Admin]
    }
}

/// 🔴 The operations that require a confirmation naming the target explicitly.
///
/// The role is not enough: a tired admin at 2 a.m. is still an admin. The confirmation
/// must **repeat the name** of what is being destroyed, so that a `--purge` typed
/// against the wrong app does not go through.
pub fn needs_confirmation(action: &str) -> bool {
    matches!(
        action,
        "purge" | "restore-production" | "node-remove" | "secrets-rekey" | "cluster-destroy"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_user_never_sees_the_cluster() {
        // 🔴 Someone who has an account is not a read-only operator. Giving them
        // `viewer` would open the cluster state, the secret names and the audit log.
        let r = Role::User;
        assert!(r.allows(Action::ReadSelf));
        assert!(r.allows(Action::ActOnSelf));
        assert!(!r.allows(Action::Read), "le portail n'est pas la console");
        assert!(!r.allows(Action::Operate));
        assert!(!r.allows(Action::Publish));
        assert!(!r.allows(Action::Destroy));
    }

    #[test]
    fn a_viewer_can_only_read() {
        let r = Role::Viewer;
        assert!(r.allows(Action::Read));
        assert!(
            r.allows(Action::ReadSelf),
            "voir le cluster implique se voir soi"
        );
        assert!(!r.allows(Action::Operate));
        assert!(!r.allows(Action::Publish));
        assert!(!r.allows(Action::Destroy));
    }

    #[test]
    fn an_operator_works_but_never_destroys() {
        // 🔴 The distinction that matters: installing is not destroying.
        let r = Role::Operator;
        assert!(r.allows(Action::Read));
        assert!(r.allows(Action::Operate));
        assert!(
            r.allows(Action::Publish),
            "annoncer une maintenance est du travail courant"
        );
        assert!(!r.allows(Action::Destroy), "an operator does not destroy");
        assert!(!r.allows(Action::ManageAccounts), "ni n'accorde de droits");
    }

    #[test]
    fn granting_rights_is_separate_from_destroying() {
        // Destroying loses data; granting a role loses control. Both are admin-only,
        // but they are two different mistakes - and naming them separately allows
        // logging them separately.
        assert_eq!(Action::ManageAccounts.minimum_role(), Role::Admin);
        assert_eq!(Action::Destroy.minimum_role(), Role::Admin);
        assert_ne!(Action::ManageAccounts, Action::Destroy);
    }

    #[test]
    fn an_admin_may_do_everything() {
        let r = Role::Admin;
        for a in [
            Action::ReadSelf,
            Action::ActOnSelf,
            Action::Read,
            Action::Publish,
            Action::Operate,
            Action::ManageAccounts,
            Action::Destroy,
        ] {
            assert!(r.allows(a), "admin devrait pouvoir {}", a.describe());
        }
    }

    #[test]
    fn the_default_is_the_least_privileged() {
        // A missing or unreadable role must never grant more. This is what
        // `State::find_token` returns when the `role` column is corrupt.
        assert_eq!(Role::default(), Role::User);
        for r in Role::tous() {
            assert!(Role::default() <= r);
        }
    }

    #[test]
    fn roles_are_ordered_by_privilege() {
        assert!(Role::User < Role::Viewer);
        assert!(Role::Viewer < Role::Operator);
        assert!(Role::Operator < Role::Admin);
    }

    #[test]
    fn a_refusal_says_what_is_missing_and_who_can_fix_it() {
        // 🔴 A bare "forbidden" leaves you guessing whether you are on the wrong
        // screen, the system is broken, or a right is missing.
        let m = Role::Viewer
            .refus(Action::Destroy)
            .expect("a viewer cannot destroy");
        assert!(m.contains("admin"), "the required role must be named: {m}");
        assert!(m.contains("viewer"), "the held role must be named: {m}");
        assert!(m.contains("administrator"), "the remedy must be named: {m}");
    }

    #[test]
    fn an_allowed_action_has_no_refusal_to_display() {
        // The guarantee is structural: a refusal cannot be shown for an allowed
        // action, because `refusal` returns nothing.
        assert_eq!(Role::Admin.refus(Action::Destroy), None);
        assert_eq!(Role::User.refus(Action::ActOnSelf), None);
    }

    #[test]
    fn every_action_names_itself_readably() {
        // The refusal message reads as-is in an interface: no technical identifier,
        // and never an empty string.
        for a in [
            Action::ReadSelf,
            Action::ActOnSelf,
            Action::Read,
            Action::Publish,
            Action::Operate,
            Action::ManageAccounts,
            Action::Destroy,
        ] {
            assert!(!a.describe().is_empty());
            assert!(
                !a.describe().contains('_'),
                "{} n'est pas une phrase",
                a.describe()
            );
        }
    }

    #[test]
    fn the_highest_group_wins() {
        let mapping = vec![
            ("homelab-admins".to_string(), Role::Admin),
            ("homelab-users".to_string(), Role::Operator),
        ];
        let groupes = vec!["homelab-users".to_string(), "homelab-admins".to_string()];
        assert_eq!(Role::from_groups(&groupes, &mapping), Role::Admin);
    }

    #[test]
    fn an_unmapped_group_gives_the_lowest_role() {
        let mapping = vec![("homelab-admins".to_string(), Role::Admin)];
        let groupes = vec!["quelque-autre-groupe".to_string()];
        assert_eq!(Role::from_groups(&groupes, &mapping), Role::User);
    }

    #[test]
    fn no_group_at_all_gives_the_least_privileged() {
        assert_eq!(Role::from_groups(&[], &[]), Role::User);
    }

    #[test]
    fn destructive_operations_are_listed() {
        assert!(needs_confirmation("purge"));
        assert!(needs_confirmation("node-remove"));
        assert!(!needs_confirmation("install"));
        assert!(!needs_confirmation("backup"));
    }

    #[test]
    fn the_french_spellings_still_parse() {
        // 🔴 Rows written before the translation hold "utilisateur" and "lecteur".
        // Refusing them would make an unreadable role fall back to the least
        // privileged one, quietly demoting an administrator.
        assert_eq!(Role::parse("admin"), Some(Role::Admin));
        assert_eq!(Role::parse("OPERATOR"), Some(Role::Operator));
        assert_eq!(Role::parse("lecteur"), Some(Role::Viewer));
        assert_eq!(Role::parse("utilisateur"), Some(Role::User));
        assert_eq!(Role::parse("administrateur"), Some(Role::Admin));
        assert_eq!(Role::parse("root"), None);
    }

    #[test]
    fn a_role_survives_a_round_trip_through_its_name() {
        // `as_str` feeds the `api_tokens.role` column and `Role::parse` reads it
        // back: a mismatch would silently return every token to the default role.
        for r in Role::tous() {
            assert_eq!(Role::parse(r.as_str()), Some(r), "{}", r.as_str());
        }
    }

    #[test]
    fn every_role_is_listed_in_tous() {
        // If a role is added without being put in `all()`, it will be missing from
        // every selection menu - and nobody will be able to assign it.
        assert_eq!(Role::tous().len(), 4);
        let mut vus = Role::tous().to_vec();
        vus.sort();
        vus.dedup();
        assert_eq!(vus.len(), 4, "des doublons dans Role::tous()");
    }
}
