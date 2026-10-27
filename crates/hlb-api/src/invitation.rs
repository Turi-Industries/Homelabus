//! What an invitation may be: the same bounds whether the interface or `hlb user invite`
//! creates it. Refused outside them, never trimmed to fit.

/// Seven days by default: time to pass the link on and wait for the person to deal
/// with it, without it lying around indefinitely in a conversation.
pub const DEFAULT_S: i64 = 7 * 86_400;

/// An hour at least — below, it expires before it is read.
pub const MIN_S: i64 = 3_600;

/// …and thirty days at most: a link lying around for a quarter is a door forgotten.
pub const MAX_S: i64 = 30 * 86_400;

/// Past fifty, an invitation is open registration, decided some other way.
pub const USES_MAX: i64 = 50;

/// Past this, the number of uses is flagged in the preview.
///
/// 🔴 Not a refusal — inviting a team of ten is legitimate. But a link with ten entries
/// that leaks lets ten people in, and that must be read before it is created.
pub const USES_WORTH_FLAGGING: i64 = 3;

/// The page that reads an invitation, and the value after it.
///
/// 🔴 The FRAGMENT, never the query string: a `?invitation=` ends up in access logs,
/// `Referer` headers and every proxy on the path; the fragment stays in the browser. On
/// `/signup`, the one screen that reads it: at `/` it would land in the console, in
/// front of someone with no account.
pub fn link_path(value: &str) -> String {
    format!("/signup#invitation={value}")
}
