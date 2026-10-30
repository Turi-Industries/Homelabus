//! A key split among relatives: any `threshold` of `count` shares rebuild it, fewer say
//! nothing of it (Shamir, over GF(256), byte by byte).
//!
//! What is split is a fresh age identity, never the emergency kit: the kit changes with
//! every destination and key, and shares handed out again at each change would be stale
//! in a drawer. The identity is forgotten once cut — only its public half is kept, so
//! the kit can be sealed to it again after any change, and a key kept nowhere needs
//! no protection of its own.
//!
//! A share is typed by hand, by someone who is not the owner, on whatever keyboard is
//! there: modhex, whose sixteen letters sit at the same place on AZERTY, QWERTY and
//! QWERTZ, and a checksum that names the mistyped share rather than rebuilding a wrong
//! key.

use std::str::FromStr;

use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use bech32::{FromBase32, ToBase32, Variant};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// More would not fit the four bits a share gives each of the threshold and the count —
/// and fifteen relatives is already a family reunion.
pub const MAX_SHARES: u8 = 15;

const VERSION: u8 = 1;
const MODHEX: &[u8; 16] = b"cbdefghijklnrtuv";
const KEY_LEN: usize = 32;
/// Version, split id (2), threshold and count, index, the key's share, checksum (2).
const LEN: usize = 1 + 2 + 1 + 1 + KEY_LEN + 2;
/// The bech32 prefix of an age identity, lower case as the encoding wants it.
const IDENTITY_HRP: &str = "age-secret-key-";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error(
        "{threshold} of {count}: a split is opened by 2 shares or more, no more than are \
         made, and makes {MAX_SHARES} at most"
    )]
    Shape { threshold: u8, count: u8 },

    #[error("no share given")]
    NoShare,

    #[error("share {0} is not a share: {1}")]
    Malformed(usize, String),

    #[error(
        "share {0} is mistyped (its checksum does not match): read it again, letter by letter"
    )]
    Mistyped(usize),

    #[error(
        "share {at} belongs to split {theirs}, share 1 to split {ours}: shares of two \
         splits open nothing together"
    )]
    OtherSplit {
        at: usize,
        theirs: String,
        ours: String,
    },

    #[error("share {index} of {count} is given twice")]
    Twice { index: u8, count: u8 },

    #[error("{needed} shares open split {split}, {given} given")]
    TooFew {
        needed: u8,
        given: usize,
        split: String,
    },

    #[error(
        "these shares do not rebuild split {0}'s key: one was altered after it was \
         printed, or comes from another split that happens to share its id"
    )]
    WrongKey(String),

    #[error("sealing: {0}")]
    Seal(String),

    #[error("the sealed kit does not open with this key: {0}")]
    Open(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A split just made: the public half to seal to, and the shares to print. The key
/// itself is in neither.
pub struct Split {
    pub recipient: String,
    pub shares: Vec<Share>,
}

/// One relative's share.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Share {
    split: [u8; 2],
    threshold: u8,
    count: u8,
    index: u8,
    y: [u8; KEY_LEN],
}

// Without the share's value: a `Debug` reaches logs and panics.
impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Share({} of {}, split {}, any {})",
            self.index,
            self.count,
            modhex(&self.split),
            self.threshold
        )
    }
}

impl Share {
    pub fn index(&self) -> u8 {
        self.index
    }
    pub fn count(&self) -> u8 {
        self.count
    }
    pub fn threshold(&self) -> u8 {
        self.threshold
    }
    /// The split's id, as printed: four modhex letters.
    pub fn split_id(&self) -> String {
        modhex(&self.split)
    }

    fn bytes(&self) -> [u8; LEN] {
        let mut b = [0u8; LEN];
        b[0] = VERSION;
        b[1..3].copy_from_slice(&self.split);
        b[3] = self.threshold << 4 | self.count;
        b[4] = self.index;
        b[5..5 + KEY_LEN].copy_from_slice(&self.y);
        let sum = crc16(&b[..LEN - 2]);
        b[LEN - 2..].copy_from_slice(&sum.to_be_bytes());
        b
    }

    /// The share as it is typed: groups of six letters.
    pub fn groups(&self) -> Vec<String> {
        let mut b = self.bytes();
        let text = modhex(&b);
        b.zeroize();
        text.as_bytes()
            .chunks(6)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect()
    }

    /// Reads a share as typed — any case, any spaces and dashes. `at` is its place among
    /// those given, for the refusal to name it.
    pub fn read(text: &str, at: usize) -> Result<Share> {
        let letters: Vec<u8> = text
            .bytes()
            .filter(|c| !c.is_ascii_whitespace() && *c != b'-')
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if let Some(c) = letters.iter().find(|c| !MODHEX.contains(c)) {
            return Err(Error::Malformed(
                at,
                format!(
                    "\"{}\" is not one of its letters ({})",
                    *c as char,
                    String::from_utf8_lossy(MODHEX)
                ),
            ));
        }
        if letters.len() != LEN * 2 {
            return Err(Error::Malformed(
                at,
                format!("{} letters, where a share has {}", letters.len(), LEN * 2),
            ));
        }
        let nibble = |c: u8| MODHEX.iter().position(|m| *m == c).unwrap_or(0) as u8;
        let mut b = [0u8; LEN];
        for (i, pair) in letters.chunks(2).enumerate() {
            b[i] = nibble(pair[0]) << 4 | nibble(pair[1]);
        }
        if crc16(&b[..LEN - 2]).to_be_bytes() != b[LEN - 2..] {
            return Err(Error::Mistyped(at));
        }
        if b[0] != VERSION {
            return Err(Error::Malformed(
                at,
                format!("made by a newer hlb (format {})", b[0]),
            ));
        }
        let mut y = [0u8; KEY_LEN];
        y.copy_from_slice(&b[5..5 + KEY_LEN]);
        let share = Share {
            split: [b[1], b[2]],
            threshold: b[3] >> 4,
            count: b[3] & 0x0f,
            index: b[4],
            y,
        };
        b.zeroize();
        Ok(share)
    }

    fn label(&self) -> String {
        format!("{} ({} of {})", self.split_id(), self.threshold, self.count)
    }
}

/// Draws a key, cuts it into `count` shares any `threshold` of which rebuild it, and
/// forgets it.
pub fn split(threshold: u8, count: u8) -> Result<Split> {
    if threshold < 2 || threshold > count || count > MAX_SHARES {
        return Err(Error::Shape { threshold, count });
    }
    let identity = Identity::generate();
    let recipient = identity.to_public().to_string();
    let id = split_id_of(&recipient);
    let mut key = identity_bytes(&identity)?;
    let shares = blahaj::Sharks(threshold)
        .dealer(&key)
        .take(usize::from(count))
        .map(|s| {
            let raw = Vec::<u8>::from(&s);
            let mut y = [0u8; KEY_LEN];
            y.copy_from_slice(&raw[1..]);
            Share {
                split: id,
                threshold,
                count,
                index: raw[0],
                y,
            }
        })
        .collect();
    key.zeroize();
    Ok(Split { recipient, shares })
}

/// The split's id from its public half, as printed: four modhex letters.
pub fn split_id(recipient: &str) -> String {
    modhex(&split_id_of(recipient))
}

fn split_id_of(recipient: &str) -> [u8; 2] {
    let h = Sha256::digest(recipient.as_bytes());
    [h[0], h[1]]
}

/// The key the shares rebuild.
pub struct Key {
    identity: Identity,
    split: String,
}

impl Key {
    pub fn split_id(&self) -> String {
        self.split.clone()
    }

    /// Opens a kit sealed to this split.
    pub fn open(&self, sealed: &str) -> Result<String> {
        let plain = age::decrypt(&self.identity, sealed.as_bytes())
            .map_err(|e| Error::Open(e.to_string()))?;
        String::from_utf8(plain).map_err(|_| Error::Open("not text".into()))
    }
}

/// Shares as typed line by line: a share ends with the line that brings it to its
/// letters. Printed on two lines, a share typed as printed is one share, not two halves
/// each refused as too short.
pub fn gather<S: AsRef<str>>(lines: &[S]) -> Vec<String> {
    let mut shares = Vec::new();
    let mut current = String::new();
    for line in lines {
        current.push_str(line.as_ref());
        current.push(' ');
        let letters = current
            .bytes()
            .filter(|c| !c.is_ascii_whitespace() && *c != b'-')
            .count();
        if letters >= LEN * 2 {
            shares.push(std::mem::take(&mut current));
        }
    }
    if !current.trim().is_empty() {
        shares.push(current);
    }
    shares
}

/// Rebuilds the key from shares as typed, refusing what would rebuild a wrong one.
pub fn combine<S: AsRef<str>>(texts: &[S]) -> Result<Key> {
    let shares = texts
        .iter()
        .enumerate()
        .map(|(i, t)| Share::read(t.as_ref(), i + 1))
        .collect::<Result<Vec<_>>>()?;
    let first = shares.first().ok_or(Error::NoShare)?;
    for (i, s) in shares.iter().enumerate() {
        if (s.split, s.threshold, s.count) != (first.split, first.threshold, first.count) {
            return Err(Error::OtherSplit {
                at: i + 1,
                theirs: s.label(),
                ours: first.label(),
            });
        }
        // `blahaj` interpolates a repeated point as two, and rebuilds garbage.
        if shares[..i].iter().any(|o| o.index == s.index) {
            return Err(Error::Twice {
                index: s.index,
                count: s.count,
            });
        }
    }
    if shares.len() < usize::from(first.threshold) {
        return Err(Error::TooFew {
            needed: first.threshold,
            given: shares.len(),
            split: first.label(),
        });
    }
    let dealt: Vec<blahaj::Share> = shares
        .iter()
        .filter_map(|s| {
            let mut raw = Vec::with_capacity(1 + KEY_LEN);
            raw.push(s.index);
            raw.extend_from_slice(&s.y);
            let share = blahaj::Share::try_from(raw.as_slice()).ok();
            raw.zeroize();
            share
        })
        .collect();
    let mut key = blahaj::Sharks(first.threshold)
        .recover(&dealt)
        .map_err(|e| Error::WrongKey(format!("{} ({e})", first.split_id())))?;
    let identity = identity_from_bytes(&key);
    key.zeroize();
    // 🔴 Interpolation always yields 32 bytes: a share altered past its checksum, or one
    // of a split whose id collides, rebuilds a key that opens nothing. Its public half
    // says so before anything is decrypted with it.
    match identity {
        Some(identity) if split_id_of(&identity.to_public().to_string()) == first.split => {
            Ok(Key {
                identity,
                split: first.split_id(),
            })
        }
        _ => Err(Error::WrongKey(first.split_id())),
    }
}

/// Seals `plain` to a split's public half, armored: a text file anyone may keep, which
/// `threshold` shares open — `hlb emergency combine`, or `age -d` given the key.
pub fn seal(plain: &str, recipient: &str) -> Result<String> {
    let to = Recipient::from_str(recipient).map_err(|e| Error::Seal(e.to_string()))?;
    age::encrypt_and_armor(&to, plain.as_bytes()).map_err(|e| Error::Seal(e.to_string()))
}

fn identity_bytes(identity: &Identity) -> Result<Vec<u8>> {
    let text = identity.to_string();
    let (_, data, _) =
        bech32::decode(text.expose_secret()).map_err(|e| Error::Seal(e.to_string()))?;
    let bytes = Vec::<u8>::from_base32(&data).map_err(|e| Error::Seal(e.to_string()))?;
    if bytes.len() != KEY_LEN {
        return Err(Error::Seal(format!(
            "an age key of {} bytes, not {KEY_LEN}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn identity_from_bytes(bytes: &[u8]) -> Option<Identity> {
    let mut text = bech32::encode(IDENTITY_HRP, bytes.to_base32(), Variant::Bech32)
        .ok()?
        .to_uppercase();
    let identity = Identity::from_str(&text).ok();
    text.zeroize();
    identity
}

/// A short code to be read off a page and typed back: 64 bits in modhex, four groups.
pub fn draw_code() -> String {
    let mut bytes = [0u8; 8];
    crate::fill_random(&mut bytes);
    let letters = modhex(&bytes);
    letters
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// A code as typed, compared: case, spaces and dashes left out.
pub fn same_code(typed: &str, code: &str) -> bool {
    let bare = |s: &str| -> String {
        s.chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_lowercase())
            .collect()
    };
    !bare(code).is_empty() && bare(typed) == bare(code)
}

/// CRC-16/CCITT-FALSE. Not a hash: a CRC catches EVERY error shorter than its 16 bits —
/// a letter mistyped, two swapped — where a truncated hash misses one in 65 536.
fn crc16(bytes: &[u8]) -> u16 {
    bytes.iter().fold(0xffff, |crc, b| {
        (0..8).fold(crc ^ u16::from(*b) << 8, |c, _| {
            if c & 0x8000 != 0 {
                c << 1 ^ 0x1021
            } else {
                c << 1
            }
        })
    })
}

fn modhex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|b| [b >> 4, b & 0x0f])
        .map(|n| MODHEX[usize::from(n)] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(split: &Split, picked: &[usize]) -> Vec<String> {
        picked
            .iter()
            .map(|i| split.shares[*i].groups().join(" "))
            .collect()
    }

    #[test]
    fn any_three_of_five_rebuild_the_key_and_open_what_was_sealed_to_it() {
        let split = split(3, 5).expect("split");
        assert_eq!(split.shares.len(), 5);
        let sealed = seal("the kit", &split.recipient).expect("sealed");
        let mut subsets = Vec::new();
        for a in 0..5 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    subsets.push(vec![a, b, c]);
                    for d in c + 1..5 {
                        subsets.push(vec![a, b, c, d]);
                    }
                }
            }
        }
        subsets.push(vec![4, 2, 0, 3, 1]);
        assert_eq!(subsets.len(), 10 + 5 + 1);
        for picked in subsets {
            let key = combine(&texts(&split, &picked)).expect("rebuilt");
            assert_eq!(key.split_id(), split_id(&split.recipient));
            assert_eq!(key.open(&sealed).expect("opened"), "the kit", "{picked:?}");
        }
    }

    #[test]
    fn fewer_than_the_threshold_are_refused_and_would_rebuild_nothing() {
        let split = split(3, 5).expect("split");
        let two = texts(&split, &[0, 3]);
        assert!(matches!(
            combine(&two),
            Err(Error::TooFew {
                needed: 3,
                given: 2,
                ..
            })
        ));
        // Interpolated anyway, as a degree-1 polynomial: a key, and not this one.
        let dealt: Vec<blahaj::Share> = [0, 3]
            .iter()
            .map(|i| {
                let s = &split.shares[*i];
                let mut raw = vec![s.index];
                raw.extend_from_slice(&s.y);
                blahaj::Share::try_from(raw.as_slice()).expect("share")
            })
            .collect();
        let guess = blahaj::Sharks(2).recover(&dealt).expect("interpolated");
        let guessed = identity_from_bytes(&guess).expect("an age key");
        assert_ne!(guessed.to_public().to_string(), split.recipient);
    }

    #[test]
    fn a_share_of_another_split_is_refused_by_its_id() {
        let ours = split(3, 5).expect("split");
        let theirs = loop {
            let s = split(3, 5).expect("split");
            // Two bytes of id: one draw in 65 536 collides, and is caught as a wrong key.
            if split_id(&s.recipient) != split_id(&ours.recipient) {
                break s;
            }
        };
        let mut mixed = texts(&ours, &[0, 1]);
        mixed.extend(texts(&theirs, &[2]));
        match combine(&mixed) {
            Err(Error::OtherSplit { at: 3, .. }) => {}
            other => panic!("mixed splits not refused: {:?}", other.err()),
        }
    }

    #[test]
    fn a_share_altered_past_its_checksum_rebuilds_no_key() {
        let split = split(3, 5).expect("split");
        let mut forged = split.shares[1].clone();
        forged.y[7] ^= 0x01;
        let typed = vec![
            split.shares[0].groups().join(""),
            forged.groups().join(""),
            split.shares[2].groups().join(""),
        ];
        assert_eq!(
            combine(&typed).err(),
            Some(Error::WrongKey(split_id(&split.recipient)))
        );
    }

    #[test]
    fn every_single_typo_and_swap_is_refused_naming_the_share() {
        let split = split(3, 5).expect("split");
        let typed = texts(&split, &[0, 1, 2]);
        let letters: Vec<char> = split.shares[1].groups().join("").chars().collect();
        let refused = |wrong: Vec<char>| {
            let mut t = typed.clone();
            t[1] = wrong.into_iter().collect();
            combine(&t).err()
        };
        for at in 0..letters.len() {
            for c in "cbdefghijklnrtuv".chars().filter(|c| *c != letters[at]) {
                let mut wrong = letters.clone();
                wrong[at] = c;
                assert_eq!(refused(wrong), Some(Error::Mistyped(2)), "{c} at {at}");
            }
            if at + 1 < letters.len() && letters[at] != letters[at + 1] {
                let mut wrong = letters.clone();
                wrong.swap(at, at + 1);
                assert_eq!(refused(wrong), Some(Error::Mistyped(2)), "swap at {at}");
            }
        }
        // A letter outside the alphabet — a `q` where AZERTY has its `a` — is named.
        let mut wrong = letters.clone();
        wrong[0] = 'q';
        assert!(matches!(refused(wrong), Some(Error::Malformed(2, _))));
        let mut short = letters;
        short.pop();
        assert!(matches!(refused(short), Some(Error::Malformed(2, _))));
    }

    #[test]
    fn the_checksum_is_the_standard_crc() {
        // CRC-16/CCITT-FALSE's check value, from its catalogue.
        assert_eq!(crc16(b"123456789"), 0x29b1);
    }

    #[test]
    fn a_share_is_read_whatever_its_case_spacing_and_dashes() {
        let split = split(2, 3).expect("split");
        let typed = vec![
            split.shares[0].groups().join("-").to_uppercase(),
            format!("  {}\n", split.shares[2].groups().join("   ")),
        ];
        assert!(combine(&typed).is_ok());
    }

    #[test]
    fn a_share_typed_on_the_lines_it_was_printed_on_is_one_share() {
        let split = split(3, 5).expect("split");
        let mut lines = Vec::new();
        for i in [0, 2, 4] {
            let groups = split.shares[i].groups();
            if i == 2 {
                lines.push(groups.join(" "));
            } else {
                lines.push(groups[..7].join(" "));
                lines.push(groups[7..].join(" "));
            }
        }
        let shares = gather(&lines);
        assert_eq!(shares.len(), 3, "{shares:?}");
        assert!(combine(&shares).is_ok());
        // A share cut short stays one share, and is refused as one.
        let short = gather(&[&lines[0]]);
        assert_eq!(short.len(), 1);
        assert!(matches!(combine(&short), Err(Error::Malformed(1, _))));
    }

    #[test]
    fn a_share_is_typed_with_letters_every_keyboard_places_alike() {
        let split = split(3, 5).expect("split");
        for s in &split.shares {
            let text = s.groups().join("");
            assert_eq!(text.len(), LEN * 2);
            // AZERTY swaps a/q and z/w and moves m; QWERTZ swaps y/z: none is modhex.
            assert!(
                text.chars().all(|c| "cbdefghijklnrtuv".contains(c)),
                "{text}"
            );
        }
    }

    #[test]
    fn a_share_given_twice_counts_once_and_is_refused() {
        let split = split(3, 5).expect("split");
        let typed = texts(&split, &[0, 1, 1]);
        assert_eq!(
            combine(&typed).err(),
            Some(Error::Twice { index: 2, count: 5 })
        );
    }

    #[test]
    fn a_shape_nobody_could_use_is_refused() {
        for (t, n) in [(1, 5), (0, 0), (4, 3), (3, 16)] {
            assert_eq!(
                split(t, n).err(),
                Some(Error::Shape {
                    threshold: t,
                    count: n
                })
            );
        }
        assert!(split(15, 15).is_ok());
    }

    #[test]
    fn a_share_prints_its_place_and_never_its_value() {
        let split = split(3, 5).expect("split");
        let s = &split.shares[3];
        assert_eq!((s.index(), s.count(), s.threshold()), (4, 5, 3));
        let shown = format!("{s:?}");
        assert!(shown.contains("4 of 5"), "{shown}");
        assert!(!shown.contains(&s.groups()[2]), "{shown}");
    }
}
