//! The registry's half of a domain reading, from the registries themselves: the TLDs
//! without RDAP, read over their WHOIS through the host IANA names.
//!
//! ```sh
//! cargo test -p hlb-engine --test live_whois -- --ignored --nocapture
//! ```
//!
//! The internet answers, so what each registry holds may move: the assertions are the
//! shape each one gives, not its values.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_api::domain::Registry;
use hlb_engine::domain::{read, Public};

async fn registry(domain: &str) -> Registry {
    let r = read(&Public::default(), domain, 0).await;
    println!("{domain}: {:#?}", r.registry);
    r.registry
}

#[tokio::test]
#[ignore = "asks the registries' WHOIS over the internet"]
async fn eurid_gives_a_registrar_and_a_delegation_and_no_status() {
    let Registry::Read(r) = registry("europa.eu").await else {
        panic!("not read")
    };
    assert_eq!(r.source, "whois.eu");
    assert!(r.registrar.is_some());
    assert_eq!(r.statuses, None);
    assert!(!r.nameservers.is_empty());
}

#[tokio::test]
#[ignore = "asks the registries' WHOIS over the internet"]
async fn denic_gives_a_status_and_a_delegation() {
    let Registry::Read(r) = registry("denic.de").await else {
        panic!("not read")
    };
    assert_eq!(r.statuses, Some(vec!["connect".to_string()]));
    assert!(!r.nameservers.is_empty());
}

#[tokio::test]
#[ignore = "asks the registries' WHOIS over the internet"]
async fn dns_belgium_gives_its_locks() {
    let Registry::Read(r) = registry("dns.be").await else {
        panic!("not read")
    };
    assert!(r
        .statuses
        .is_some_and(|s| s.iter().any(|s| s.ends_with("transfer prohibited"))));
}

#[tokio::test]
#[ignore = "asks the registries' WHOIS over the internet"]
async fn switch_refuses_anyone_but_a_registrar_and_says_so() {
    let Registry::NotRead { why } = registry("switch.ch").await else {
        panic!("SWITCH answered: its WHOIS may be open now — read what it gives")
    };
    assert!(why.contains("whois.nic.ch answered"), "{why}");
}
