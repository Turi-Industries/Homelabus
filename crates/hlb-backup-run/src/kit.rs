//! The emergency kit: what restores the vault, and therefore cannot live in it — the
//! master key, the backup repository's password, how to reach each destination,
//! Swarm's unlock key when autolock is on, each encrypted disk's recovery key and each
//! storage node's dataset key — on one sheet of paper, with the restic commands that bring Homelabus's state back
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

/// A node's disk recovery key is the secret of this prefix and the node's name, made by
/// [`recovery_key`] when that disk is about to be encrypted — never earlier, so the kit
/// goes stale only then.
pub const LUKS_RECOVERY_PREFIX: &str = "luks-recovery-";

/// A storage node's dataset key is the secret of this prefix and the node's name, made
/// by [`zfs_key`] when its datasets are about to be encrypted.
pub const ZFS_KEY_PREFIX: &str = "zfs-key-";

/// The kit's split among relatives (`hlb emergency split`): its PUBLIC half and its
/// shape. The key itself was forgotten once cut — it is in nobody's hands but theirs.
pub const SPLIT_SECRET: &str = "kit-split";

/// A split, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitRecord {
    /// What the kit is sealed to.
    pub recipient: String,
    pub threshold: u8,
    pub count: u8,
}

impl SplitRecord {
    pub fn id(&self) -> String {
        hlb_secrets::split::split_id(&self.recipient)
    }
}

/// The split the kit is sealed to, if one was made.
pub async fn split(state: &State, vault: &Vault) -> Result<Option<SplitRecord>> {
    let Some(ct) = state.secret(SPLIT_SECRET).await? else {
        return Ok(None);
    };
    let text = vault.decrypt(&ct)?;
    let mut parts = text.split_whitespace();
    Ok(match (parts.next(), parts.next(), parts.next()) {
        (Some(recipient), Some(t), Some(n)) => match (t.parse(), n.parse()) {
            (Ok(threshold), Ok(count)) => Some(SplitRecord {
                recipient: recipient.to_string(),
                threshold,
                count,
            }),
            _ => None,
        },
        _ => None,
    })
}

/// Records `split` as the one the kit is sealed to, over any former one.
pub async fn record_split(state: &State, vault: &Vault, split: &SplitRecord) -> Result<()> {
    let ct = vault.encrypt(&format!(
        "{} {} {}",
        split.recipient, split.threshold, split.count
    ))?;
    if !state
        .store_secret_if_absent(SPLIT_SECRET, &ct, "the emergency kit's split, public half")
        .await?
    {
        state.rotate_secret(SPLIT_SECRET, &ct).await?;
    }
    Ok(())
}

/// The code a sealed kit carries for the family's rehearsal: read by whoever opened it,
/// given back to the owner, burned once given. Kept, so a kit sealed again after a
/// change carries the same one until it is used.
pub const REHEARSAL_SECRET: &str = "kit-rehearsal-code";

/// The rehearsal code a kit sealed now carries — the one waiting, or a new one.
pub async fn rehearsal_code(state: &State, vault: &Vault) -> Result<String> {
    if let Some(ct) = state.secret(REHEARSAL_SECRET).await? {
        return Ok(vault.decrypt(&ct)?);
    }
    let code = hlb_secrets::split::draw_code();
    if !state
        .store_secret_if_absent(REHEARSAL_SECRET, &vault.encrypt(&code)?, REHEARSAL_PURPOSE)
        .await?
    {
        return Box::pin(rehearsal_code(state, vault)).await;
    }
    Ok(code)
}

const REHEARSAL_PURPOSE: &str = "the family's rehearsal code, on the sealed kit";

/// Makes `code` the one waiting, over any other: a new split's shares were never
/// rehearsed, and a code read off a kit sealed to the old split proves nothing of them.
pub async fn set_rehearsal_code(state: &State, vault: &Vault, code: &str) -> Result<()> {
    let ct = vault.encrypt(code)?;
    if !state
        .store_secret_if_absent(REHEARSAL_SECRET, &ct, REHEARSAL_PURPOSE)
        .await?
    {
        state.rotate_secret(REHEARSAL_SECRET, &ct).await?;
    }
    Ok(())
}

/// `true` when `typed` is the code waiting — which is then burned: given once, it would
/// otherwise prove next year's rehearsal without one.
pub async fn redeem_rehearsal(state: &State, vault: &Vault, typed: &str) -> Result<bool> {
    let Some(ct) = state.secret(REHEARSAL_SECRET).await? else {
        return Ok(false);
    };
    if !hlb_secrets::split::same_code(typed, &vault.decrypt(&ct)?) {
        return Ok(false);
    }
    state.forget_secret(REHEARSAL_SECRET).await?;
    Ok(true)
}

/// The kit as sealed: the sheet, and the rehearsal its holders give back.
pub fn render_sealed(sheet: &str, code: &str) -> String {
    let mut s = sheet.to_string();
    for l in [
        "",
        "REHEARSAL — for the holders of the shares. Once a year they open this kit",
        "together, without the owner, to know they can. Having opened it, give the",
        "owner this code: `hlb emergency rehearsed <code>` records that the family",
        "can, and burns it.",
        "",
    ] {
        s.push_str(l);
        s.push('\n');
    }
    s.push_str(&format!("   {code}\n"));
    s
}

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
    /// `(node, key)`, by node: empty while no disk is encrypted.
    pub luks: Vec<(String, String)>,
    /// `(node, key)`, by node: empty while no dataset is encrypted.
    pub zfs: Vec<(String, String)>,
    pub fingerprint: String,
}

/// What the kit holds besides the master key.
struct Material {
    restic: Option<String>,
    destinations: Vec<Destination>,
    swarm_unlock: Option<String>,
    luks: Vec<(String, String)>,
    zfs: Vec<(String, String)>,
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
    // `secret_names` is ordered by name: the fingerprint does not move with the query.
    let (mut luks, mut zfs) = (Vec::new(), Vec::new());
    for (name, _) in state.secret_names().await? {
        let (keys, node) = match (
            name.strip_prefix(LUKS_RECOVERY_PREFIX),
            name.strip_prefix(ZFS_KEY_PREFIX),
        ) {
            (Some(node), _) => (&mut luks, node),
            (_, Some(node)) => (&mut zfs, node),
            (None, None) => continue,
        };
        if let Some(ct) = state.secret(&name).await? {
            keys.push((node.to_string(), vault.decrypt(&ct)?));
        }
    }
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
        luks,
        zfs,
    })
}

/// `node`'s disk recovery key, made and stored the first time — by the preview of the
/// verb that encrypts it, which then refuses until a kit printed since carries it.
/// `true` when it was made now.
pub async fn recovery_key(state: &State, vault: &Vault, node: &str) -> Result<(String, bool)> {
    let name = format!("{LUKS_RECOVERY_PREFIX}{node}");
    if let Some(ct) = state.secret(&name).await? {
        return Ok((vault.decrypt(&ct)?, false));
    }
    let key = hlb_secrets::recovery_key();
    let ct = vault.encrypt(&key)?;
    let purpose = format!("disk recovery key of {node}");
    if !state.store_secret_if_absent(&name, &ct, &purpose).await? {
        // Made meanwhile by another run: that one is the key the disk will know.
        return Box::pin(recovery_key(state, vault, node)).await;
    }
    Ok((key, true))
}

/// `node`'s dataset key, made and stored the first time, as [`recovery_key`] is: 32
/// random bytes in hex, ZFS's `keyformat=hex`. `true` when it was made now.
pub async fn zfs_key(state: &State, vault: &Vault, node: &str) -> Result<(String, bool)> {
    let name = format!("{ZFS_KEY_PREFIX}{node}");
    if let Some(ct) = state.secret(&name).await? {
        return Ok((vault.decrypt(&ct)?, false));
    }
    let mut bytes = [0u8; 32];
    hlb_secrets::fill_random(&mut bytes);
    let key: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let purpose = format!("dataset key of {node}'s storage");
    if !state
        .store_secret_if_absent(&name, &vault.encrypt(&key)?, &purpose)
        .await?
    {
        return Box::pin(zfs_key(state, vault, node)).await;
    }
    Ok((key, true))
}

/// What a kit printed now would carry, as a fingerprint.
pub async fn fingerprint(state: &State, vault: &Vault) -> Result<String> {
    let m = material(state, vault).await?;
    Ok(fingerprint_of(
        &vault.public_key(),
        m.restic.as_deref(),
        &m.destinations,
        m.swarm_unlock.as_deref(),
        &m.luks,
        &m.zfs,
    ))
}

/// Sixteen hex digits of a SHA-256 over everything the kit holds — short enough to
/// read off a sheet and compare by eye.
pub fn fingerprint_of(
    public_key: &str,
    restic: Option<&str>,
    destinations: &[Destination],
    swarm_unlock: Option<&str>,
    luks: &[(String, String)],
    zfs: &[(String, String)],
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
    // Likewise: nothing hashed until a disk, or a dataset, is encrypted.
    for (tag, keys) in [(&b"luks-recovery\0"[..], luks), (b"zfs-key\0", zfs)] {
        for (node, key) in keys {
            h.update(tag);
            for part in [node, key] {
                h.update(part.as_bytes());
                h.update([0]);
            }
        }
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
            &m.luks,
            &m.zfs,
        ),
        master_key: vault.secret_key(),
        restic_password: m.restic,
        destinations: m.destinations,
        swarm_unlock: m.swarm_unlock,
        luks: m.luks,
        zfs: m.zfs,
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
            None if d.location.starts_with("rest:") => {
                line("     a restic REST server, at this address")
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
    line("   `hlb backup status` lists what each destination holds. On a new machine:");
    line("");
    line("   hlb cluster init --apply");
    line("   hlb config exposure --node <this machine> --apply");
    line("   hlb catalog source fetch");
    line("");
    line("   Then each app, in the order `hlb order` prints. It first starts empty: a");
    line("   restore needs a service to stop, and a node holding its volume.");
    line("");
    line("   hlb install <app> --apply");
    line("   hlb backup restore <app> --from <destination> --apply");
    line("   hlb assert <app>");
    line("");
    line("5. Each app's own administrator is in Vaultwarden, collection \"Server\": it");
    line("   comes back with the state and its volume, and opens with an owner's");
    line("   master password — which is on no sheet.");
    // Numbered as printed: a house without autolock has no 6. to skip.
    let mut n = 5;
    if let Some(k) = &kit.swarm_unlock {
        n += 1;
        line("");
        line(&format!(
            "{n}. Swarm's unlock key — a manager that cannot unseal its own copy, its"
        ));
        line("   board replaced or its disk moved, waits for it: `docker swarm unlock`.");
        line("");
        line(&format!("   {k}"));
    }
    if !kit.luks.is_empty() {
        n += 1;
        line("");
        line(&format!(
            "{n}. Each encrypted disk's recovery key — typed at the boot prompt when the"
        ));
        line("   disk does not open by itself (its TPM replaced, its Tang out of reach),");
        line("   or given to `cryptsetup open` from another machine:");
        for (node, key) in &kit.luks {
            line("");
            line(&format!("   {node}"));
            line(&format!("     {key}"));
        }
    }
    if !kit.zfs.is_empty() {
        n += 1;
        line("");
        line(&format!(
            "{n}. Each storage node's dataset key — its pool's disks, in that machine or"
        ));
        line("   another, open with it alone. Saved in /etc/hlb/zfs.key (mode 0400), then:");
        line("   zfs load-key -a && zfs mount -a");
        for (node, key) in &kit.zfs {
            line("");
            line(&format!("   {node}"));
            line(&format!("     {key}"));
        }
    }
    s
}

/// A relative's sheet: their share, and how it opens the kit with the others. Printed,
/// and read by someone who never ran Homelabus.
pub fn render_share(
    share: &hlb_secrets::split::Share,
    installation: &str,
    printed: &str,
) -> String {
    let (i, n, t, id) = (
        share.index(),
        share.count(),
        share.threshold(),
        share.split_id(),
    );
    let mut s = String::new();
    let mut line = |l: &str| {
        s.push_str(l);
        s.push('\n');
    };
    line(&format!(
        "HOMELABUS — A SHARE OF THE EMERGENCY KIT — {installation}"
    ));
    line(&format!("Share {i} of {n}, split {id}, made {printed}."));
    line("");
    line(&format!(
        "Any {t} of the {n} shares open the emergency kit of {installation}; fewer say"
    ));
    line("nothing of it. The kit opens every backup: keep this sheet as you would a house");
    line(&format!(
        "key, and hand it only to whoever gathers {t} of them to bring it back."
    ));
    line("");
    line("The share — every letter counts, the spaces do not:");
    line("");
    let groups = share.groups();
    for row in groups.chunks(7) {
        line(&format!("   {}", row.join(" ")));
    }
    line("");
    line("The sealed kit is a file, kit.age, sent to every holder: it opens with the");
    line("shares only. On any machine with hlb (https://github.com/Turi-Industries/Homelabus):");
    line("");
    line("   hlb emergency combine --kit kit.age --out kit.txt");
    line("");
    line("then type each share as printed, and an empty line after the last. Without");
    line(&format!(
        "--kit, it says only whether the shares open split {id}: once a year, check they do."
    ));
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
            fingerprint_of(public, restic, &[dest(Some(credentials))], unlock, &[], &[])
        };
        let luks = |key: &str| {
            fingerprint_of(
                "age1pub",
                Some("pw"),
                &[dest(Some("AK:SK"))],
                None,
                &[("deb1".to_string(), key.to_string())],
                &[],
            )
        };
        let zfs = |key: &str| {
            fingerprint_of(
                "age1pub",
                Some("pw"),
                &[dest(Some("AK:SK"))],
                None,
                &[],
                &[("deb1".to_string(), key.to_string())],
            )
        };
        let base = of("age1pub", Some("pw"), "AK:SK", None);
        assert_eq!(base.len(), 16);
        assert_eq!(base, of("age1pub", Some("pw"), "AK:SK", None));
        let unlocked = of("age1pub", Some("pw"), "AK:SK", Some("SWMKEY-1-a"));
        for other in [
            of("age1other", Some("pw"), "AK:SK", None),
            of("age1pub", Some("pw2"), "AK:SK", None),
            of("age1pub", Some("pw"), "AK:SK2", None),
            fingerprint_of("age1pub", Some("pw"), &[], None, &[], &[]),
            zfs("cbdefghi"),
            luks("cbdefghi"),
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
        assert_ne!(luks("cbdefghi"), luks("cbdefghj"));
        assert_ne!(zfs("cbdefghi"), zfs("cbdefghj"));
        // The same key as a disk's or as a pool's is not the same kit.
        assert_ne!(luks("cbdefghi"), zfs("cbdefghi"));
    }

    #[tokio::test]
    async fn a_recovery_key_is_made_once_and_stales_the_kit_that_lacks_it() {
        let d = tempfile::tempdir().expect("temp dir");
        let vault = Vault::init(d.path().join("k")).expect("vault");
        let state = State::in_memory().await.expect("state");
        let printed = fingerprint(&state, &vault).await.expect("fingerprint");

        let (key, made) = recovery_key(&state, &vault, "deb1").await.expect("made");
        assert!(made);
        assert_eq!(
            recovery_key(&state, &vault, "deb1").await.expect("again"),
            (key.clone(), false),
            "a second preview must not change the key the disk will know"
        );
        assert_ne!(printed, fingerprint(&state, &vault).await.expect("now"));
        let kit = read(&state, &vault).await.expect("kit");
        assert_eq!(kit.luks, vec![("deb1".to_string(), key)]);
    }

    #[tokio::test]
    async fn a_dataset_key_is_made_once_in_zfs_hex_and_stales_the_kit() {
        let d = tempfile::tempdir().expect("temp dir");
        let vault = Vault::init(d.path().join("k")).expect("vault");
        let state = State::in_memory().await.expect("state");
        let printed = fingerprint(&state, &vault).await.expect("fingerprint");

        let (key, made) = zfs_key(&state, &vault, "deb2").await.expect("made");
        assert!(made);
        // `keyformat=hex` takes exactly 64 hex digits: 32 bytes.
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()), "{key}");
        assert_eq!(
            zfs_key(&state, &vault, "deb2").await.expect("again"),
            (key.clone(), false),
            "a second preview must not change the key the datasets will know"
        );
        assert_ne!(printed, fingerprint(&state, &vault).await.expect("now"));
        let kit = read(&state, &vault).await.expect("kit");
        assert_eq!(kit.zfs, vec![("deb2".to_string(), key)]);
        assert!(kit.luks.is_empty(), "a dataset key is not a disk's");
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
            fingerprint_of(
                "age1pub",
                Some("pw"),
                &[dest(Some("AK:SK"))],
                None,
                &[],
                &[]
            )
        );
    }

    #[tokio::test]
    async fn a_split_is_kept_by_its_public_half_and_replaced_whole() {
        let d = tempfile::tempdir().expect("temp dir");
        let vault = Vault::init(d.path().join("k")).expect("vault");
        let state = State::in_memory().await.expect("state");
        assert_eq!(split(&state, &vault).await.expect("read"), None);
        let printed = fingerprint(&state, &vault).await.expect("fingerprint");

        let first = hlb_secrets::split::split(3, 5).expect("split");
        let record = SplitRecord {
            recipient: first.recipient.clone(),
            threshold: 3,
            count: 5,
        };
        record_split(&state, &vault, &record)
            .await
            .expect("recorded");
        assert_eq!(split(&state, &vault).await.expect("read"), Some(record));
        // The split opens the kit; it is not part of what the kit restores.
        assert_eq!(printed, fingerprint(&state, &vault).await.expect("now"));

        let second = SplitRecord {
            recipient: hlb_secrets::split::split(2, 3).expect("split").recipient,
            threshold: 2,
            count: 3,
        };
        record_split(&state, &vault, &second)
            .await
            .expect("replaced");
        assert_eq!(split(&state, &vault).await.expect("read"), Some(second));
    }

    #[tokio::test]
    async fn a_rehearsal_code_proves_once_and_a_new_split_replaces_it() {
        let d = tempfile::tempdir().expect("temp dir");
        let vault = Vault::init(d.path().join("k")).expect("vault");
        let state = State::in_memory().await.expect("state");
        assert!(!redeem_rehearsal(&state, &vault, "").await.expect("none"));

        let code = rehearsal_code(&state, &vault).await.expect("drawn");
        assert_eq!(
            rehearsal_code(&state, &vault).await.expect("again"),
            code,
            "a kit sealed again carries the code the family may already have read"
        );
        assert!(!redeem_rehearsal(&state, &vault, "cbde-fghi-jkln-rtuv")
            .await
            .expect("wrong"));
        let typed = code.to_uppercase().replace('-', " ");
        assert!(redeem_rehearsal(&state, &vault, &typed)
            .await
            .expect("given"));
        assert!(
            !redeem_rehearsal(&state, &vault, &code)
                .await
                .expect("twice"),
            "a code given once proves nothing a second time"
        );
        let next = rehearsal_code(&state, &vault).await.expect("next");
        assert_ne!(next, code);

        let split = hlb_secrets::split::draw_code();
        set_rehearsal_code(&state, &vault, &split)
            .await
            .expect("set");
        assert!(!redeem_rehearsal(&state, &vault, &next).await.expect("old"));
        assert!(redeem_rehearsal(&state, &vault, &split).await.expect("new"));

        let sealed = render_sealed("THE KIT\n", &split);
        assert!(sealed.starts_with("THE KIT\n"));
        assert!(sealed.contains(&split) && sealed.contains("hlb emergency rehearsed"));
    }

    #[test]
    fn a_share_sheet_carries_the_share_and_how_it_opens_the_kit() {
        let split = hlb_secrets::split::split(3, 5).expect("split");
        let share = &split.shares[1];
        let sheet = render_share(share, "Turi Industries", "2026-10-30 17:00 UTC");
        for needed in [
            "Share 2 of 5",
            &format!("split {}", share.split_id()),
            "Any 3 of the 5 shares",
            "hlb emergency combine --kit kit.age --out kit.txt",
        ] {
            assert!(sheet.contains(needed), "{needed} missing from:\n{sheet}");
        }
        // Typed back from the sheet's own lines, it is the same share. The block under
        // its header, not "indented and without `hlb`": the groups are random letters,
        // and a row drawing "hlb" was dropped, failing one run in a few hundred.
        let typed: String = sheet
            .lines()
            .skip_while(|l| !l.starts_with("The share —"))
            .skip(2)
            .take_while(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!typed.is_empty(), "no share block in:\n{sheet}");
        let read = hlb_secrets::split::Share::read(&typed, 1).expect("read back");
        assert_eq!(&read, share);
        for l in sheet.lines() {
            assert!(l.chars().count() <= 84, "too wide to print: {l}");
        }
    }

    #[test]
    fn the_sheet_carries_every_secret_it_exists_for() {
        let kit = Kit {
            master_key: "AGE-SECRET-KEY-1TEST".into(),
            restic_password: Some("repo-pw".into()),
            destinations: vec![dest(Some("AKIA:shh"))],
            swarm_unlock: Some("SWMKEY-1-unlock".into()),
            luks: vec![(
                "a-storage-node-with-a-long-name".into(),
                "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv".into(),
            )],
            zfs: vec![(
                "deb2".into(),
                "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
            )],
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
            "a-storage-node-with-a-long-name",
            "cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv-cbdefghi-jklnrtuv",
            "7. Each encrypted disk's recovery key",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "8. Each storage node's dataset key",
            "/etc/hlb/zfs.key",
        ] {
            assert!(sheet.contains(needed), "{needed} missing from:\n{sheet}");
        }
        // Printed: a line that runs past the paper's width is cut by the printer.
        for l in sheet.lines() {
            assert!(l.chars().count() <= 84, "too wide to print: {l}");
        }
    }
}
