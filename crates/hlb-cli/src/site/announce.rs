//! `hlb site announce`: the owner's words on the site's status page, beside or instead
//! of the house's.
//!
//! The words are written by the command `hlb site sync` leaves on the VPS
//! (`hlb_engine::site_watch::ANNOUNCE_COMMAND`): the night they matter the house may be
//! down, and a phone with SSH runs that same command. This verb runs it, so both ways do
//! one thing.

use std::process::ExitCode;

use hlb_engine::site_watch;

use crate::{open_state, open_vault, Cli, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// What to do with the owner's words.
pub enum Words {
    Replace(String),
    Follow(String),
}

/// One notice as the site lists it: its id, its state, and what the page says.
struct Listed {
    id: String,
    state: String,
    says: Option<String>,
}

/// The page's message as a person reads it: the file holds it quoted, `$$` a dollar.
fn readable(quoted: &str) -> String {
    let plain = quoted.replace("$$", "$");
    serde_json::from_str::<String>(&plain).unwrap_or(plain)
}

fn parse(listed: &str) -> Vec<Listed> {
    listed
        .lines()
        .filter_map(|l| {
            let mut parts = l.splitn(3, '\t');
            Some(Listed {
                id: parts.next()?.to_string(),
                state: parts.next()?.to_string(),
                says: parts.next().map(readable),
            })
        })
        .collect()
}

pub async fn run(
    cli: &Cli,
    id: Option<&str>,
    words: Option<Words>,
    apply: bool,
) -> Result<ExitCode> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let Some(s) = super::load(&state, &vault).await? else {
        println!("The house has no site.  hlb site add <ssh-host> --apply");
        return Ok(ExitCode::SUCCESS);
    };
    if let Some(Words::Replace(w) | Words::Follow(w)) = &words {
        if let Some(why) = site_watch::refuse_words(w) {
            eprintln!("🔴 Not said: {why}.");
            return Ok(ExitCode::FAILURE);
        }
    }
    let (_key_dir, site) = super::reach(&state, &vault, &s).await?;
    if site
        .read_file(site_watch::ANNOUNCE_COMMAND)
        .await?
        .is_none()
    {
        eprintln!(
            "🔴 {} has no announcement command: its watch predates it.  hlb site sync --apply",
            s.name
        );
        return Ok(ExitCode::FAILURE);
    }
    let out = site
        .run(&[site_watch::ANNOUNCE_COMMAND.to_string()])
        .await?;
    if !out.ok() {
        eprintln!("🔴 {}: {}", s.name, out.stderr.trim());
        return Ok(ExitCode::FAILURE);
    }
    let notices = parse(&out.stdout);

    // clap asks an id for words, and words for an id.
    let (Some(id), Some(words)) = (id, words) else {
        let announced: Vec<&Listed> = notices.iter().filter(|n| n.state != "quiet").collect();
        if announced.is_empty() {
            println!(
                "No alert is open on {}: the page announces nothing.",
                s.name
            );
        }
        for n in announced {
            match &n.says {
                Some(says) => println!("{}  announced: {says}", n.id),
                None => println!("{}  open, not announced (its alert's button)", n.id),
            }
        }
        return Ok(ExitCode::SUCCESS);
    };

    let Some(notice) = notices.iter().find(|n| n.id == id) else {
        eprintln!(
            "🔴 {id}: no such notice on {}.  hlb site announce   lists them",
            s.name
        );
        return Ok(ExitCode::FAILURE);
    };
    let Some(says) = &notice.says else {
        eprintln!(
            "🔴 {id} is not on the page ({}): its alert's button announces it first.",
            notice.state
        );
        return Ok(ExitCode::FAILURE);
    };
    let (how, text) = match &words {
        Words::Replace(w) => ("replace", w.as_str()),
        Words::Follow(w) => ("follow", w.as_str()),
    };
    println!("The page says: {says}");
    match &words {
        Words::Replace(_) => println!("It would say instead: {text}"),
        Words::Follow(_) => println!("Then, after the hour: {text}"),
    }
    if !apply {
        println!("Rerun with --apply to say it.");
        return Ok(ExitCode::SUCCESS);
    }

    let out = site
        .run(&[
            site_watch::ANNOUNCE_COMMAND.to_string(),
            id.to_string(),
            how.to_string(),
            text.to_string(),
        ])
        .await;
    let (ok, detail) = match &out {
        Ok(o) => (o.ok(), o.stderr.trim().to_string()),
        Err(e) => (false, e.to_string()),
    };
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            &format!("site-announce-{how}"),
            &format!("{}:{id}", s.name),
            if ok { "ok" } else { "failed" },
            (!detail.is_empty()).then_some(detail.as_str()),
        )
        .await?;
    if ok {
        println!("✓ said on {}'s status page", s.name);
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("🔴 Not said: {detail}");
        Ok(ExitCode::FAILURE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_site_s_list_reads_as_the_page_shows_it() {
        let n = parse(
            "house-reachable\tannounced\t\"Back at 6 \\\"sharp\\\", $$5 lost [18:30 UTC] ok\"\n\
             services-budget\topen\n\
             services-mealie\tquiet\n",
        );
        assert_eq!(n.len(), 3);
        assert_eq!(
            n[0].says.as_deref(),
            Some("Back at 6 \"sharp\", $5 lost [18:30 UTC] ok")
        );
        assert_eq!((n[1].state.as_str(), n[1].says.as_deref()), ("open", None));
        assert_eq!(n[2].id, "services-mealie");
    }
}
