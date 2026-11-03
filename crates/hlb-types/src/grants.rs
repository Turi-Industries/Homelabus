//! What an app receives beyond its own container, said before it is installed.
//!
//! The defaults are closed — a read-only root, every capability dropped, no new
//! privileges, no port on the host, reachable from the VPN only — so what the preview
//! names is exactly what the manifest opened. An app from a third-party source is
//! installed on its author's word: this is where the owner reads what that word asks.
//!
//! The host's network, Docker's socket, `privileged` and devices have no field in the
//! schema: no manifest can ask for them, so there is nothing here to say.

use crate::capability::{Capability, SmtpSender};
use crate::manifest::{ExposePolicy, Manifest, Protocol, Runtime, SecuritySpec};

impl Manifest {
    /// Each thing the app is given that the defaults keep shut, one sentence each; its
    /// hosts under `domain`, the one chosen at install time, when it is known.
    pub fn grants(&self, domain: Option<&str>) -> Vec<String> {
        let mut out = Vec::new();
        for i in &self.spec.ingress {
            let host = match domain {
                Some(d) => i.host.replace("{{ domain }}", d).replace("{{domain}}", d),
                None => i.host.clone(),
            };
            match i.expose {
                ExposePolicy::Public => out.push(format!("reachable from the internet at {host}")),
                ExposePolicy::AfterGuide => out.push(format!(
                    "reachable from the internet at {host} once its guide is done"
                )),
                ExposePolicy::Private => {}
            }
            if !i.open_paths.is_empty() {
                out.push(format!(
                    "{} on {host} reached by anyone: no portal, no private range",
                    i.open_paths.join(", ")
                ));
            }
        }
        match self.spec.runtime {
            Runtime::Compose => out.push(
                "runs outside the Swarm, under docker compose on a host of its own driven \
                 over SSH"
                    .into(),
            ),
            Runtime::Swarm => {}
        }
        for c in &self.spec.requires {
            match c {
                Capability::Smtp {
                    sender: SmtpSender::Person,
                } => out.push(
                    "signs in to the mail server with each person's own mailbox password".into(),
                ),
                Capability::MailAccount { .. }
                | Capability::Smtp {
                    sender: SmtpSender::App,
                }
                | Capability::Database { .. }
                | Capability::Cache { .. }
                | Capability::Sso { .. }
                | Capability::ObjectStorage { .. }
                | Capability::Storage { .. } => {}
            }
        }
        let name = &self.metadata.name;
        security(name, &self.spec.security, &mut out);
        for c in &self.spec.companions {
            security(&format!("{name}'s {}", c.name), &c.security, &mut out);
        }
        out
    }
}

fn security(who: &str, s: &SecuritySpec, out: &mut Vec<String>) {
    // Destructured whole: a field added to the spec is a question this must answer.
    let SecuritySpec {
        read_only_rootfs,
        no_new_privileges,
        cap_drop,
        cap_add,
        user: _,
        tmpfs: _,
        published_ports,
    } = s;
    if !published_ports.is_empty() {
        let ports: Vec<String> = published_ports
            .iter()
            .map(|p| match p.protocol {
                Protocol::Tcp => format!("{}/tcp", p.port),
                Protocol::Udp => format!("{}/udp", p.port),
            })
            .collect();
        out.push(format!(
            "{who}: ports {} published on its node, past the proxy",
            ports.join(", ")
        ));
    }
    if !cap_drop.iter().any(|c| c.eq_ignore_ascii_case("ALL")) {
        out.push(format!("{who}: keeps the Linux capabilities its image has"));
    }
    if !cap_add.is_empty() {
        out.push(format!(
            "{who}: Linux capabilities given back: {}",
            cap_add.join(", ")
        ));
    }
    if !no_new_privileges {
        out.push(format!(
            "{who}: may gain privileges through a setuid program"
        ));
    }
    if !read_only_rootfs {
        out.push(format!("{who}: writes anywhere in its own filesystem"));
    }
}

#[cfg(test)]
mod tests {
    use crate::Manifest;

    fn manifest(spec: &str) -> Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: a }}\nspec:\n  \
             image: {{ repo: a/a, tag: \"1\" }}\n{spec}"
        );
        serde_yaml_ng::from_str(&y).expect("manifest")
    }

    #[test]
    fn the_defaults_grant_nothing() {
        let m = manifest("  ingress: [ { host: \"a.{{ domain }}\", port: 80 } ]\n");
        assert_eq!(m.grants(Some("x")), Vec::<String>::new());
    }

    #[test]
    fn what_a_manifest_opens_is_named() {
        let m = manifest(
            "  ingress: [ { host: \"a.{{ domain }}\", port: 80, expose: public, openPaths: [\"/hook/*\"] } ]\n  \
             requires: [ { kind: smtp, sender: person } ]\n  \
             security: { readOnlyRootfs: false, capAdd: [NET_BIND_SERVICE], publishedPorts: [25, \"7882/udp\"] }\n  \
             companions:\n    - name: w\n      image: { repo: a/w, tag: \"1\" }\n      \
             security: { noNewPrivileges: false, capDrop: [] }\n",
        );
        let g = m.grants(Some("x")).join("\n");
        for said in [
            "reachable from the internet at a.x",
            "/hook/* on a.x reached by anyone",
            "each person's own mailbox password",
            "a: ports 25/tcp, 7882/udp published",
            "a: Linux capabilities given back: NET_BIND_SERVICE",
            "a: writes anywhere",
            "a's w: may gain privileges",
            "a's w: keeps the Linux capabilities",
        ] {
            assert!(g.contains(said), "{said} not in:\n{g}");
        }
        assert!(!g.contains("a: may gain"), "{g}");
    }
}
