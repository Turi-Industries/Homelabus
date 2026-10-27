//! Automatic alias generation, addy.io / SimpleLogin style.
//!
//! ## What this model actually buys
//!
//! People often think the point of a disposable alias is being able to throw it away.
//! That is the least of it. The real gain is **attribution**: one address per
//! recipient, and the day spam arrives at `amazon-k7m2p9@example.org`, you know *who*
//! leaked the address. With one address given everywhere, all you know is that you
//! leaked, which helps nobody.
//!
//! That is why [`Generated::for_site`] keeps a readable hint: without it you end up with fifty
//! random addresses and no idea which went where, and attribution - the only real
//! benefit - disappears.
//!
//! ## 🔴 An alias must be UNGUESSABLE
//!
//! This is the property that holds everything together, and the easiest to lose.
//!
//! If the alias given to Amazon is `amazon@example.org`, then `paypal@example.org`,
//! `tax@example.org` and `bank@example.org` probably exist too - and a bulk sender
//! tries them all for the price of one. Compartmentalisation collapses at once: each
//! alias guesses the others, and you have built a sieve believing you built
//! partitions.
//!
//! So the hint is **never** the whole address: it is always followed by a random
//! suffix. Six base32 characters is roughly a billion possibilities - enough that
//! enumeration costs more than it returns, while staying dictatable over the phone.
//!
//! ## 🔴 Disable rather than delete
//!
//! A deleted alias rejects mail and teaches nothing more. A **disabled** one rejects it
//! too, but what knocks at the door keeps being counted - which says how long a merchant
//! carried on selling the address after it was closed. See
//! [`crate::alias::Alias::actif`].

/// The suffix alphabet.
///
/// ⚠️ No `0`/`O`, no `1`/`I`/`L`: these addresses get dictated over the phone and copied
/// by hand from a screen. A misreading produces an "unknown recipient" bounce that
/// nobody traces back to the font.
const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// Length of the random suffix.
///
/// 🔴 31^6 ≈ 887 million. Enough that enumerating a domain's aliases costs more than it
/// returns, while staying short enough to dictate.
pub const SUFFIX_LEN: usize = 6;

/// ⚠️ Stalwart accepts longer local parts, but beyond this the address stops being
/// copyable by hand - which is precisely the use case.
pub const HINT_MAX: usize = 24;

/// A generated alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generated {
    /// The full local part: `amazon-k7m2p9`.
    pub local: String,
    /// The hint kept, after cleaning.
    pub hint: String,
}

/// Cleans a hint so it is usable inside an address.
///
/// ⚠️ A local part does not accept anything. An uncleaned hint would produce an address
/// some servers reject - and the bounce goes to the sender, not to us: we would not
/// even know the alias does not work.
pub fn clean_hint(raw: &str) -> String {
    let s: String = raw
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();

    // Leading, trailing or repeated hyphens are ugly and sometimes refused.
    let mut out = String::with_capacity(s.len());
    let mut dash = true; // true to start with: strips leading hyphens
    for c in s.chars() {
        if c == '-' {
            if !dash {
                out.push(c);
            }
            dash = true;
        } else {
            out.push(c);
            dash = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out.truncate(HINT_MAX);
    while out.ends_with('-') {
        out.pop();
    }
    out
}

impl Generated {
    /// An alias for a given recipient.
    ///
    /// `entropy` supplies the entropy - passed in so generation is **testable**: a
    /// generator drawing its own randomness cannot be checked, and that is precisely
    /// the part worth checking.
    ///
    /// 🔴 The hint NEVER makes the address on its own. See the module header: without a
    /// suffix, each alias guesses all the others.
    pub fn for_site(hint: &str, entropy: &[u8]) -> Self {
        let hint = clean_hint(hint);
        let suffix = suffix(entropy);

        let local = if hint.is_empty() {
            // With no usable hint the alias stays anonymous - but still random. Less
            // convenient to trace back, never less safe.
            suffix
        } else {
            format!("{hint}-{suffix}")
        };

        Self { local, hint }
    }

    /// The full address.
    pub fn address(&self, domain: &str) -> String {
        format!("{}@{}", self.local, domain)
    }
}

fn suffix(entropy: &[u8]) -> String {
    // ⚠️ The modulo introduces a negligible bias here (256 mod 31), and the point is to
    // be unguessable, not to be a perfect cryptographic source.
    entropy
        .iter()
        .take(SUFFIX_LEN)
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTROPY: &[u8] = &[7, 42, 200, 13, 99, 251, 3, 4];

    #[test]
    fn a_hint_never_makes_the_whole_address() {
        // 🔴 THE property of this module. If Amazon's alias is "amazon@example.org",
        // then "paypal@", "tax@" and "bank@" probably exist too, and a bulk sender tries
        // them all for the price of one. Compartmentalisation collapses: each alias
        // guesses the others.
        let g = Generated::for_site("amazon", ENTROPY);

        assert_ne!(g.local, "amazon", "the hint alone would be guessable");
        assert!(g.local.starts_with("amazon-"), "{}", g.local);
        assert_eq!(
            g.local.len(),
            "amazon-".len() + SUFFIX_LEN,
            "un suffix de longueur fixe : {}",
            g.local
        );
    }

    #[test]
    fn two_aliases_for_the_same_site_differ() {
        // Otherwise asking again for a merchant's alias would return the previous one,
        // and attributing a leak would become impossible.
        let a = Generated::for_site("amazon", &[1, 2, 3, 4, 5, 6]);
        let b = Generated::for_site("amazon", &[9, 8, 7, 6, 5, 4]);
        assert_ne!(a.local, b.local);
    }

    #[test]
    fn the_hint_survives_so_attribution_stays_possible() {
        // With no hint you end up with fifty random addresses and no idea which went
        // where - and attribution, the only real benefit, disappears.
        let g = Generated::for_site("Le Bon Coin", ENTROPY);
        assert_eq!(g.hint, "le-bon-coin");
        assert!(g.local.starts_with("le-bon-coin-"), "{}", g.local);
    }

    #[test]
    fn ambiguous_characters_are_never_produced() {
        // ⚠️ These addresses get dictated over the phone and copied from a screen. A
        // "0" read as "O" produces an "unknown recipient" bounce that nobody traces
        // back to the font.
        for b in 0u8..=255 {
            let g = Generated::for_site("x", &[b; SUFFIX_LEN]);
            let suffix = g.local.strip_prefix("x-").expect("prefix");
            for c in suffix.chars() {
                assert!(
                    !"01loi".contains(c),
                    "ambiguous character \"{c}\" in \"{suffix}\""
                );
            }
        }
    }

    #[test]
    fn a_dirty_hint_is_cleaned_rather_than_refused() {
        // A local part does not accept anything, and a bounce would go to the SENDER:
        // we would not even know the alias does not work.
        assert_eq!(clean_hint("Amazon.fr"), "amazon-fr");
        assert_eq!(clean_hint("  --Fnac--  "), "fnac");
        assert_eq!(clean_hint("a@@@b"), "a-b");
        assert_eq!(clean_hint("Été 2026"), "t-2026"); // accents are dropped
    }

    #[test]
    fn a_hint_is_never_long_enough_to_break_copying() {
        let long = "a".repeat(200);
        let g = Generated::for_site(&long, ENTROPY);
        assert!(g.hint.len() <= HINT_MAX);
        assert!(!g.local.contains("--"));
    }

    #[test]
    fn an_alias_without_a_usable_hint_is_still_random() {
        // Less convenient to trace back, never less safe.
        let g = Generated::for_site("!!!", ENTROPY);
        assert!(g.hint.is_empty());
        assert_eq!(g.local.len(), SUFFIX_LEN);
        assert!(!g.local.starts_with('-'), "{}", g.local);
    }

    #[test]
    fn the_address_is_built_once_and_correctly() {
        let g = Generated::for_site("amazon", ENTROPY);
        let a = g.address("example.fr");
        assert_eq!(a.matches('@').count(), 1, "{a}");
        assert!(a.ends_with("@example.fr"));
    }

    #[test]
    fn the_search_space_is_large_enough_to_discourage_enumeration() {
        // 🔴 31^6 ≈ 887 million. An alphabet or a length reduced by mistake would make
        // enumeration worthwhile, and take all the compartmentalisation with it.
        let space = (ALPHABET.len() as u64).pow(SUFFIX_LEN as u32);
        assert!(
            space > 500_000_000,
            "the search space is too small: {space}"
        );
    }
}
