//! The few tar entries Homelabus writes itself: a directory's attributes put back in
//! front of an archive that left the directory out.
//!
//! `restic dump` of a directory writes every entry under it and none for the directory
//! itself: unpacked into a fresh volume, the root kept the mount point's owner and mode,
//! not the app's. One ustar header in front restores them.

/// One ustar block.
pub const BLOCK: usize = 512;

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Dir,
    /// A regular file of this many bytes, its content following in whole blocks.
    File(u64),
}

fn octal(field: &mut [u8], value: u64) -> Result<(), String> {
    // Digits, then a NUL: what every reader accepts.
    let digits = format!("{value:0width$o}", width = field.len() - 1);
    if digits.len() > field.len() - 1 {
        return Err(format!("{value} does not fit a tar field"));
    }
    field[..digits.len()].copy_from_slice(digits.as_bytes());
    field[digits.len()] = 0;
    Ok(())
}

/// A ustar header. `path` is relative, at most 100 bytes; a directory's ends without
/// its slash, as GNU tar reads either.
pub fn header(
    path: &str,
    kind: Kind,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<[u8; BLOCK], String> {
    let name = match kind {
        Kind::Dir => format!("{}/", path.trim_end_matches('/')),
        Kind::File(_) => path.to_string(),
    };
    if name.len() > 100 || name.starts_with('/') {
        return Err(format!("{name}: not a short relative path"));
    }
    let mut h = [0u8; BLOCK];
    h[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut h[100..108], u64::from(mode & 0o7777))?;
    octal(&mut h[108..116], u64::from(uid))?;
    octal(&mut h[116..124], u64::from(gid))?;
    let (size, flag) = match kind {
        Kind::Dir => (0, b'5'),
        Kind::File(n) => (n, b'0'),
    };
    octal(&mut h[124..136], size)?;
    octal(&mut h[136..148], 0)?;
    h[156] = flag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    // The checksum is taken with its own field read as spaces.
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    let digits = format!("{sum:06o}");
    h[148..154].copy_from_slice(digits.as_bytes());
    h[154] = 0;
    h[155] = b' ';
    Ok(h)
}

/// Content padded to whole blocks.
pub fn padded(content: &[u8]) -> Vec<u8> {
    let mut out = content.to_vec();
    out.resize(content.len().div_ceil(BLOCK) * BLOCK, 0);
    out
}

/// The two empty blocks that end an archive.
pub fn end() -> [u8; 2 * BLOCK] {
    [0u8; 2 * BLOCK]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_checks_out_as_tar_reads_it() {
        let h = header("donnees/vol", Kind::Dir, 1000, 1001, 0o700).expect("header");
        assert_eq!(&h[..12], b"donnees/vol/");
        assert_eq!(&h[100..108], b"0000700\0");
        assert_eq!(&h[108..116], b"0001750\0");
        assert_eq!(h[156], b'5');
        // Recomputed the way a reader does: the field as spaces.
        let mut copy = h;
        copy[148..156].copy_from_slice(b"        ");
        let sum: u32 = copy.iter().map(|b| u32::from(*b)).sum();
        let stored = std::str::from_utf8(&h[148..154]).expect("ascii");
        assert_eq!(u32::from_str_radix(stored, 8), Ok(sum));
    }

    #[test]
    fn a_path_tar_cannot_hold_is_refused() {
        assert!(header(&"x".repeat(101), Kind::File(0), 0, 0, 0o644).is_err());
        assert!(header("/etc/passwd", Kind::File(0), 0, 0, 0o644).is_err());
    }

    #[test]
    fn content_ends_on_a_block() {
        assert_eq!(padded(b"hi").len(), BLOCK);
        assert_eq!(padded(&[0; BLOCK]).len(), BLOCK);
        assert!(padded(b"").is_empty());
    }
}
