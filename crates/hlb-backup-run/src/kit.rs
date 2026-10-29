//! The emergency kit: what restores the vault, and therefore cannot live in it — the
//! master key, the backup repository's password, how to reach each destination, and
//! Swarm's unlock key when autolock is on — on one sheet of paper, with the restic commands that bring Homelabus's state back
//! without Homelabus.
//!
//! ## 🔴 A kit printed before a change restores nothing
//!
//! A rekey, a destination's new key, a destination added: the sheet in the drawer then
//! opens nothing, and nobody looks at it until the day it is needed. Its fingerprint
//! covers what it holds — the master key by its PUBLIC half, so the comparison needs no
//! secret — and the break-glass safeguard counts the kit only while the fingerprint
//! printed is today's.

use sha2::{Digest, Sha256};

use hlb_secrets::Vault;
use hlb_state::State;

use crate::{credentials, load_destinations, Result, RESTIC_PASSWORD_SECRET};

/// Swarm's unlock key, stored by `hlb cluster autolock`. On the kit because a manager
/// that cannot unseal its copy — a board replaced, its disk moved — stays locked, and the
/// vault holding the other copy may be on that manager.
pub const SWARM_UNLOCK_SECRET: &str = "swarm-unlock-key";

/// One destination, as the kit prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub name: String,
    pub location: String,
    /// `access_key:secret_key` for S3; `None` for a path on a machine.
    pub credentials: Option<String>,
}

/// What restores the vault.
pub struct Kit {
    pub master_key: String,
    /// `None` while no backup has ever run: the password is made by the first.
    pub restic_password: Option<String>,
    pub destinations: Vec<Destination>,
    /// `None` while autolock is off: a manager then asks for no key.
    pub swarm_unlock: Option<String>,
    pub fingerprint: String,
}

/// What the kit holds besides the master key.
struct Material {
    restic: Option<String>,
    destinations: Vec<Destination>,
    swarm_unlock: Option<String>,
}

/// The kit's material, without creating anything.
async fn material(state: &State, vault: &Vault) -> Result<Material> {
    let restic = match state.secret(RESTIC_PASSWORD_SECRET).await? {
        Some(ct) => Some(vault.decrypt(&ct)?),
        None => None,
    };
    let swarm_unlock = match state.secret(SWARM_UNLOCK_SECRET).await? {
        Some(ct) => Some(vault.decrypt(&ct)?),
        None => None,
    };
    let mut destinations = Vec::new();
    for d in load_destinations(state).await? {
        destinations.push(Destination {
            credentials: credentials(state, vault, &d).await?,
            name: d.name,
            location: d.location,
        });
    }
    Ok(Material {
        restic,
        destinations,
        swarm_unlock,
    })
}

/// What a kit printed now would carry, as a fingerprint.
pub async fn fingerprint(state: &State, vault: &Vault) -> Result<String> {
    let m = material(state, vault).await?;
    Ok(fingerprint_of(
        &vault.public_key(),
        m.restic.as_deref(),
        &m.destinations,
        m.swarm_unlock.as_deref(),
    ))
}

/// Sixteen hex digits of a SHA-256 over everything the kit holds — short enough to
/// read off a sheet and compare by eye.
pub fn fingerprint_of(
    public_key: &str,
    restic: Option<&str>,
    destinations: &[Destination],
    swarm_unlock: Option<&str>,
) -> String {
    let mut h = Sha256::new();
    for part in [public_key, restic.unwrap_or("")] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    for d in destinations {
        for part in [&d.name, &d.location, d.credentials.as_deref().unwrap_or("")] {
            h.update(part.as_bytes());
            h.update([0]);
        }
    }
    // Hashed only when there is one: the kits printed before autolock existed hold
    // everything a house without it needs, and stay current.
    if let Some(k) = swarm_unlock {
        h.update(b"swarm-unlock\0");
        h.update(k.as_bytes());
    }
    h.finalize()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The kit, as printed now.
pub async fn read(state: &State, vault: &Vault) -> Result<Kit> {
    let m = material(state, vault).await?;
    Ok(Kit {
        fingerprint: fingerprint_of(
            &vault.public_key(),
            m.restic.as_deref(),
            &m.destinations,
            m.swarm_unlock.as_deref(),
        ),
        master_key: vault.secret_key(),
        restic_password: m.restic,
        destinations: m.destinations,
        swarm_unlock: m.swarm_unlock,
    })
}

/// The sheet, in plain text: it is printed, and read by someone without Homelabus.
pub fn render(kit: &Kit, installation: &str, printed: &str) -> String {
    let mut s = String::new();
    let mut line = |l: &str| {
        s.push_str(l);
        s.push('\n');
    };
    line(&format!("HOMELABUS EMERGENCY KIT — {installation}"));
    line(&format!(
        "Printed {printed}. Fingerprint {}.",
        kit.fingerprint
    ));
    line("");
    line("Whoever holds this sheet decrypts every backup. Keep it away from the cluster:");
    line("not in a drawer of the machine it restores. The recovery screen says whether");
    line("this fingerprint is still the installation's; when it is not, print a new one");
    line("(`hlb emergency kit`) and destroy this one.");
    line("");
    line("1. The vault's master key — saved alone in a file, it is HLB_MASTER_KEY:");
    line("");
    line(&format!("   {}", kit.master_key));
    line("");
    line("2. The backup repositories' password:");
    line("");
    match &kit.restic_password {
        Some(p) => line(&format!("   {p}")),
        None => line("   (none yet: no backup has run — print the kit again after the first)"),
    }
    line("");
    line("3. Where the backups are:");
    line("");
    if kit.destinations.is_empty() {
        line("   No destination is declared. Backups go where the controller's");
        line("   --backup-repo points, if anywhere: write it here by hand.");
    }
    for d in &kit.destinations {
        line(&format!("   {} — {}", d.name, d.location));
        match d.credentials.as_deref().and_then(|c| c.split_once(':')) {
            Some((key, secret)) => {
                line(&format!("     AWS_ACCESS_KEY_ID={key}"));
                line(&format!("     AWS_SECRET_ACCESS_KEY={secret}"));
            }
            None => line("     a path on the machine that holds it"),
        }
    }
    line("");
    line("4. Homelabus's state, back with restic alone (https://restic.net), from any");
    line("   destination above:");
    line("");
    line("   export RESTIC_PASSWORD='<2.>'");
    line("   export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…   # an S3 destination");
    line("   restic -r <location> snapshots --tag app:hlb");
    line("   restic -r <location> dump latest --tag app:hlb,db:state \\");
    line("       /staging/hlb-state.snapshot > hlb.db");
    line("");
    line("   With HLB_STATE=hlb.db and HLB_MASTER_KEY naming the key file of 1.,");
    line("   `hlb backup status` lists what each destination holds, and");
    line("   `hlb backup restore <app>` puts each volume back.");
    line("");
    line("5. Each app's own administrator is in Vaultwarden, collection \"Server\": it");
    line("   comes back with the state and its volume, and opens with an owner's");
    line("   master password — which is on no sheet.");
    if let Some(k) = &kit.swarm_unlock {
        line("");
        line("6. Swarm's unlock key — a manager that cannot unseal its own copy, its");
        line("   board replaced or its disk moved, waits for it: `docker swarm unlock`.");
        line("");
        line(&format!("   {k}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(credentials: Option<&str>) -> Destination {
        Destination {
            name: "offsite".into(),
            location: "s3:https://s3.example.org/hlb".into(),
            credentials: credentials.map(str::to_string),
        }
    }

    #[test]
    fn the_fingerprint_moves_with_anything_the_kit_holds() {
        let of = |public, restic, credentials: &str, unlock| {
            fingerprint_of(public, restic, &[dest(Some(credentials))], unlock)
        };
        let base = of("age1pub", Some("pw"), "AK:SK", None);
        assert_eq!(base.len(), 16);
        assert_eq!(base, of("age1pub", Some("pw"), "AK:SK", None));
        let unlocked = of("age1pub", Some("pw"), "AK:SK", Some("SWMKEY-1-a"));
        for other in [
            of("age1other", Some("pw"), "AK:SK", None),
            of("age1pub", Some("pw2"), "AK:SK", None),
            of("age1pub", Some("pw"), "AK:SK2", None),
            fingerprint_of("age1pub", Some("pw"), &[], None),
            of("age1pub", None, "AK:SK", None),
            unlocked.clone(),
            of("age1pub", Some("pw"), "AK:SK", Some("SWMKEY-1-b")),
        ] {
            assert_ne!(
                base, other,
                "a kit printed before this change restores nothing"
            );
        }
        assert_ne!(
            unlocked,
            of("age1pub", Some("pw"), "AK:SK", Some("SWMKEY-1-b"))
        );
    }

    #[test]
    fn a_kit_printed_before_autolock_existed_stays_current_without_it() {
        // The fingerprint every kit printed until 2026-10-29 carries.
        let mut h = Sha256::new();
        for part in [
            "age1pub",
            "pw",
            "offsite",
            "s3:https://s3.example.org/hlb",
            "AK:SK",
        ] {
            h.update(part.as_bytes());
            h.update([0]);
        }
        let before: String = h
            .finalize()
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            before,
            fingerprint_of("age1pub", Some("pw"), &[dest(Some("AK:SK"))], None)
        );
    }

    #[test]
    fn the_sheet_carries_every_secret_it_exists_for() {
        let kit = Kit {
            master_key: "AGE-SECRET-KEY-1TEST".into(),
            restic_password: Some("repo-pw".into()),
            destinations: vec![dest(Some("AKIA:shh"))],
            swarm_unlock: Some("SWMKEY-1-unlock".into()),
            fingerprint: "0123456789abcdef".into(),
        };
        let sheet = render(&kit, "Turi Industries", "2026-10-18 17:00 UTC");
        for needed in [
            "AGE-SECRET-KEY-1TEST",
            "repo-pw",
            "s3:https://s3.example.org/hlb",
            "AWS_ACCESS_KEY_ID=AKIA",
            "AWS_SECRET_ACCESS_KEY=shh",
            "0123456789abcdef",
            "--tag app:hlb,db:state",
            "SWMKEY-1-unlock",
        ] {
            assert!(sheet.contains(needed), "{needed} missing from:\n{sheet}");
        }
        // Printed: a line that runs past the paper's width is cut by the printer.
        for l in sheet.lines() {
            assert!(l.chars().count() <= 84, "too wide to print: {l}");
        }
    }
}
