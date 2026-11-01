//! A manifest's `downloads`: each file fetched into the app's volume by a one-off job
//! on the node that volume is on, before the app starts.
//!
//! The volume may sit on any node, or on the pool: `hlb`'s own process reaches none of
//! them, so the fetch is the job's, with the volume mounted as the app will mount it.

use hlb_orchestrator::{ServiceSpec, VolumeBacking};

/// Where the job mounts the volume.
const VOLUME: &str = "/volume";

/// Inside the directory it fills: the hash of what it holds, so a run finding it
/// fetches nothing — an upgrade replays every action, and would otherwise depend on
/// the publisher being up to restart an app that did not change.
pub const MARK: &str = ".hlb-sha256";

/// How long a fetch is waited for.
pub const TIMEOUT_S: u64 = 600;

/// The job's script. Every value is a positional parameter, never part of the text:
/// `$1` the URL, `$2` the hash, `$3` the directory, `$4` `unzip` or not, `$5` the file
/// name kept when not.
///
/// Fetched beside the directory and moved in only once checked: a failed or refused
/// fetch leaves the previous version in place. What it writes takes the volume root's
/// owner — an app running as a user writes in its plugins' directory (Jellyfin keeps a
/// `meta.json` there), which root's files would refuse it.
const SCRIPT: &str = r#"set -euf
url=$1 sum=$2 into=$3 unzip=$4 name=$5
cd /volume
if [ -f "$into/.hlb-sha256" ] && [ "$(cat "$into/.hlb-sha256")" = "$sum" ]; then
  echo "$into already holds $sum"
  exit 0
fi
owner=$(stat -c %u:%g .)
parent=$(dirname "$into")
dir=.
IFS=/
for seg in $parent; do
  dir="$dir/$seg"
  if [ ! -d "$dir" ]; then mkdir "$dir"; chown "$owner" "$dir"; fi
done
unset IFS
new="$into.hlb-new"
rm -rf "$new" "$into.hlb-old"
mkdir "$new"
wget -q -O "$new/.download" "$url"
got=$(sha256sum "$new/.download" | cut -d ' ' -f 1)
if [ "$got" != "$sum" ]; then
  rm -rf "$new"
  echo "$url is sha256 $got, not the $sum declared: refused" >&2
  exit 1
fi
if [ "$unzip" = unzip ]; then
  unzip -q "$new/.download" -d "$new"
  rm "$new/.download"
else
  mv "$new/.download" "$new/$name"
fi
echo "$sum" > "$new/.hlb-sha256"
chown -R "$owner" "$new"
if [ -e "$into" ]; then mv "$into" "$into.hlb-old"; fi
mv "$new" "$into"
rm -rf "$into.hlb-old"
echo "$into now holds $sum"
"#;

/// What one download asks the job to do.
pub struct Fetch<'a> {
    pub app: &'a str,
    pub volume: &'a str,
    pub url: &'a str,
    pub sha256: &'a str,
    pub into: &'a str,
    pub unzip: bool,
}

/// The job fetching `f`, its volume mounted with the backing the app's will have,
/// placed by `constraints` — the app's own, once pinned to its data.
pub fn job(
    f: &Fetch<'_>,
    backing: VolumeBacking,
    constraints: &[String],
    network: &str,
) -> ServiceSpec {
    let name = f.url.rsplit('/').next().unwrap_or_default();
    let mut job = ServiceSpec::new(
        format!("hlb-download-{}", f.app),
        hlb_orchestrator::swarm::DOCKER_CLI_IMAGE,
    )
    .job()
    // The publisher is on the internet: the overlay is how a task leaves the node.
    .network(network)
    .mount_backed(f.volume, VOLUME, backing)
    .command([
        "sh",
        "-c",
        SCRIPT,
        "hlb-download",
        f.url,
        f.sha256,
        f.into,
        if f.unzip { "unzip" } else { "keep" },
        name,
    ]);
    for c in constraints {
        job = job.constraint(c);
    }
    // Root, but only what giving the files to the volume's owner takes: entering and
    // writing its directories, and the `chown`.
    job.hardening.cap_add = ["CHOWN", "DAC_OVERRIDE", "FOWNER"]
        .map(String::from)
        .to_vec();
    job
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetch() -> Fetch<'static> {
        Fetch {
            app: "jellyfin",
            volume: "jellyfin-config",
            url: "https://example.org/sso_1.zip",
            sha256: "ab",
            into: "plugins/SSO-Auth",
            unzip: true,
        }
    }

    #[test]
    fn a_download_reaches_the_shell_as_parameters_never_as_its_text() {
        let j = job(&fetch(), VolumeBacking::Docker, &[], "hlb_platform");
        assert_eq!(j.command[..3], ["sh", "-c", SCRIPT]);
        assert_eq!(
            j.command[3..],
            [
                "hlb-download",
                "https://example.org/sso_1.zip",
                "ab",
                "plugins/SSO-Auth",
                "unzip",
                "sso_1.zip"
            ]
        );
        assert!(!SCRIPT.contains("example.org"));
        // The mark the script reads is the one this module names.
        assert!(SCRIPT.contains(&format!("\"$into/{MARK}\"")));
        assert!(SCRIPT.contains(&format!("cd {VOLUME}\n")));
    }

    #[test]
    fn the_job_runs_where_the_app_will_with_its_volume_as_the_app_mounts_it() {
        let nfs = VolumeBacking::Nfs {
            server: "10.0.0.2".into(),
            export: "/tank/apps/jellyfin/config".into(),
        };
        let pinned = ["node.labels.hlb.data.jellyfin==true".to_string()];
        let j = job(&fetch(), nfs.clone(), &pinned, "hlb_platform");
        assert_eq!(j.mode, hlb_orchestrator::ServiceMode::Job);
        assert_eq!(j.constraints, pinned);
        assert_eq!(j.backing_of("jellyfin-config"), nfs);
        assert_eq!(
            j.mounts,
            [("jellyfin-config".to_string(), VOLUME.to_string())]
        );
        assert_eq!(j.networks, ["hlb_platform"]);
    }
}
