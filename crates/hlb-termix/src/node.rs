//! What each node holds for Termix: a dedicated Unix account, never root, and the
//! nodes' key in its `authorized_keys`, usable only from where Termix runs.
//!
//! The script below runs in a one-off job on the node, through `chroot` into the
//! host's root, so the host's own `useradd` and `sshd` answer. It is idempotent, says
//! what it did on lines of its own ([`Outcome::read`]), and in `check` mode writes
//! nothing — which is what a preview runs.
//!
//! 🔴 The account gets no right at all: no `sudo`, no `docker` group — both are root
//! by another name. Homelabus never writes `sudoers`; whoever wants more on a node
//! adds it there by hand.

/// The comment on every line Homelabus keeps in the account's `authorized_keys`: what
/// it filters on, so a line someone added by hand is kept.
pub fn marker(app: &str) -> String {
    format!("homelabus-managed:{app}")
}

/// The Unix account Termix signs in as, on every node.
pub fn account(app: &str) -> String {
    format!("hlb-{app}")
}

/// One `authorized_keys` line: the key, usable only from `from`.
///
/// No agent and no X11 forwarding: nothing Termix's terminal needs. Port forwarding
/// stays — Termix's tunnels are made of it, and a tunnel opens nothing a shell on the
/// node does not.
pub fn line(public_body: &str, from: &[String], marker: &str) -> String {
    format!(
        "from=\"{}\",no-agent-forwarding,no-X11-forwarding {public_body} {marker}",
        from.join(",")
    )
}

/// What a run of the script on one node found, and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// The account was made by this run, or would be.
    pub created: bool,
    /// The lines were written by this run, or would be.
    pub written: bool,
    /// The node's ed25519 host key, as `ssh-keygen -l` prints it: what Termix asks a
    /// person to accept at their first connection.
    pub host_key: Option<String>,
    /// What keeps the account out although its key is in place.
    pub refused: Vec<String>,
}

const CREATED: &str = "HLB-CREATED";
const WRITTEN: &str = "HLB-WRITTEN";
const HOST_KEY: &str = "HLB-HOSTKEY ";
const REFUSED: &str = "HLB-REFUSED ";
/// The script's last line, when it reached its end: a job's log is all that comes back,
/// and a log cut short must not read as "nothing to do".
const END: &str = "HLB-END";

impl Outcome {
    /// `None` when the script did not reach its end.
    pub fn read(output: &[String]) -> Option<Self> {
        let lines: Vec<&str> = output.iter().map(|l| l.trim()).collect();
        if !lines.contains(&END) {
            return None;
        }
        Some(Self {
            created: lines.contains(&CREATED),
            written: lines.contains(&WRITTEN),
            host_key: lines
                .iter()
                .find_map(|l| l.strip_prefix(HOST_KEY))
                .map(str::to_string),
            refused: lines
                .iter()
                .filter_map(|l| l.strip_prefix(REFUSED))
                .map(str::to_string)
                .collect(),
        })
    }
}

/// Single-quoted for `sh`: the values are Homelabus's own, but a quote in one must not
/// end the string.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The script run INSIDE the host's root (`chroot /host /bin/sh -c …`).
///
/// `lines` are the account's lines as they should be; every other line of the file is
/// kept as it is. `check`: say what would change, and change nothing.
pub fn host_script(user: &str, marker: &str, lines: &[String], check: bool) -> String {
    let want = lines.join("\n");
    format!(
        r#"set -eu
u={user}
mark={marker}
want={want}
check={check}

if ! id -u "$u" >/dev/null 2>&1; then
    echo {CREATED}
    if [ "$check" = 1 ]; then
        echo {WRITTEN}
        echo {END}
        exit 0
    fi
    shell=/bin/sh
    [ -x /bin/bash ] && shell=/bin/bash
    if command -v useradd >/dev/null 2>&1; then
        useradd -m -s "$shell" -c 'Termix, through Homelabus' "$u"
    else
        adduser -D -s "$shell" -g 'Termix, through Homelabus' "$u"
    fi
fi

# No password, and NOT locked: "!" is a locked account to sshd wherever it reads the
# lock itself (UsePAM no, Alpine's default), and it then refuses every key. "*" opens
# nothing by password and leaves keys alone. A password someone set is kept.
if [ "$check" != 1 ] && grep -q "^$u:!" /etc/shadow; then
    sed -i "s/^$u:![^:]*:/$u:*:/" /etc/shadow
fi

home=$(awk -F: -v u="$u" '$1 == u {{ print $6 }}' /etc/passwd)
group=$(id -gn "$u")
ak="$home/.ssh/authorized_keys"
have=$(grep -F -- "$mark" "$ak" 2>/dev/null || true)
if [ "$have" != "$want" ]; then
    echo {WRITTEN}
    if [ "$check" != 1 ]; then
        mkdir -p "$home/.ssh"
        # Every line not ours is kept as it is; ours are replaced whole. Written beside
        # and renamed: a cut leaves the former file, never half of one.
        {{ grep -v -F -- "$mark" "$ak" 2>/dev/null || true; printf '%s\n' "$want"; }} > "$ak.hlb-tmp"
        chown "$u:$group" "$ak.hlb-tmp"
        chmod 600 "$ak.hlb-tmp"
        mv "$ak.hlb-tmp" "$ak"
    fi
fi
if [ "$check" != 1 ]; then
    # sshd ignores a key, without a word, in a file or directory others can write.
    chown "$u:$group" "$home/.ssh"
    chmod 700 "$home/.ssh"
fi

if [ -r /etc/ssh/ssh_host_ed25519_key.pub ] && command -v ssh-keygen >/dev/null 2>&1; then
    echo "{HOST_KEY}$(ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub | awk '{{ print $2 }}')"
fi
# AllowUsers and AllowGroups refuse every account they do not name — a key in place
# and a door shut, which nothing else would say.
if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null | awk -v u="$u" -v g="$group" '
        $1 == "allowusers" {{ for (i = 2; i <= NF; i++) if ($i == u || $i ~ "^" u "@") ok = 1; if (!ok) print "{REFUSED}sshd allows only: " $0 }}
        $1 == "allowgroups" {{ for (i = 2; i <= NF; i++) if ($i == g) okg = 1; if (!okg) print "{REFUSED}sshd allows only: " $0 }}
        $1 == "denyusers" {{ for (i = 2; i <= NF; i++) if ($i == u) print "{REFUSED}sshd denies it: " $0 }}
    ' || true
fi
echo {END}
"#,
        user = quote(user),
        marker = quote(marker),
        want = quote(&want),
        check = u8::from(check),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_names_where_it_may_be_used_from() {
        let l = line(
            "ssh-ed25519 AAAA",
            &["10.42.0.1".into(), "172.18.0.0/16".into()],
            "homelabus-managed:termix",
        );
        assert_eq!(
            l,
            "from=\"10.42.0.1,172.18.0.0/16\",no-agent-forwarding,no-X11-forwarding \
             ssh-ed25519 AAAA homelabus-managed:termix"
        );
    }

    #[test]
    fn a_cut_log_is_not_read_as_nothing_to_do() {
        assert_eq!(Outcome::read(&["HLB-WRITTEN".into()]), None);
        let o = Outcome::read(&[
            "HLB-WRITTEN".into(),
            "HLB-HOSTKEY SHA256:abc".into(),
            "HLB-REFUSED sshd allows only: allowusers root".into(),
            "HLB-END".into(),
        ])
        .expect("read");
        assert!(o.written && !o.created);
        assert_eq!(o.host_key.as_deref(), Some("SHA256:abc"));
        assert_eq!(o.refused, vec!["sshd allows only: allowusers root"]);
    }

    #[test]
    fn a_quote_in_a_value_stays_inside_its_string() {
        let s = host_script("hlb-termix", "m", &["it's".into()], true);
        assert!(s.contains(r"want='it'\''s'"), "{s}");
    }

    #[test]
    fn the_script_never_grants_more_than_a_shell() {
        // 🔴 sudo and the docker group are root by other names.
        let s = host_script("hlb-termix", "m", &[], false);
        for word in ["sudoers", "usermod -aG", "gpasswd", "docker"] {
            assert!(!s.contains(word), "{word}");
        }
    }
}
