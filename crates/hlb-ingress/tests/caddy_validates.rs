//! Vérifie que Caddy accepte réellement la configuration générée.
//!
//! Générer du texte qui *ressemble* à un Caddyfile ne prouve rien. Ce test le soumet
//! au vrai binaire Caddy — c'est la seule façon d'attraper une directive mal placée,
//! un matcher invalide ou une syntaxe qui a changé de version.
//!
//! ```sh
//! export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
//! cargo test -p hlb-ingress -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::Write;
use std::process::Command;

use hlb_ingress::{render_backend, render_frontend, Config, Route};

const CADDY_IMAGE: &str = "caddy:2-alpine";

/// Soumet un Caddyfile à `caddy validate` dans un conteneur jetable.
///
/// La config passe par **stdin**, pas par un montage : sur macOS, le dossier temporaire
/// de l'hôte n'est pas partagé dans la VM Docker, et le bind mount échoue.
fn caddy_validate(caddyfile: &str, label: &str) {
    let mut child = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-i",
            "--entrypoint",
            "sh",
            CADDY_IMAGE,
            "-c",
            "cat > /tmp/Caddyfile && caddy validate --config /tmp/Caddyfile --adapter caddyfile",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("docker doit être joignable (DOCKER_HOST ?)");

    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(caddyfile.as_bytes())
        .expect("envoi de la config");

    let out = child.wait_with_output().expect("attente de caddy");

    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "Caddy a refusé le Caddyfile « {label} » :\n\
         ───── sortie de caddy ─────\n{stderr}\n\
         ───── config générée ─────\n{caddyfile}"
    );

    println!("✓ {label} accepté par Caddy");
}

fn routes() -> Vec<Route> {
    vec![
        // Gitea : pas d'Anubis (casserait `git clone`), public.
        Route {
            host: "git.example.fr".into(),
            service: "gitea".into(),
            port: 3000,
            through_anubis: false,
            public: true,
            sso_paths: vec!["/user/oauth2/PocketID/callback".into()],
            needs_forward_auth: false,
        },
        // Vikunja : derrière Anubis, avec exclusion du callback OIDC.
        Route {
            host: "tasks.example.fr".into(),
            service: "vikunja".into(),
            port: 3456,
            through_anubis: true,
            public: true,
            sso_paths: vec!["/auth/openid/pocketid".into()],
            needs_forward_auth: false,
        },
        // Vaultwarden : privé, accessible seulement depuis le VPN.
        Route {
            host: "vault.example.fr".into(),
            service: "vaultwarden".into(),
            port: 80,
            through_anubis: false,
            public: false,
            sso_paths: vec!["/identity/connect/oidc-signin".into()],
            needs_forward_auth: false,
        },
    ]
}

#[test]
#[ignore = "nécessite Docker"]
fn frontend_config_is_accepted_by_caddy() {
    caddy_validate(&render_frontend(&routes(), &Config::default()), "frontend");
}

#[test]
#[ignore = "nécessite Docker"]
fn backend_config_is_accepted_by_caddy() {
    caddy_validate(&render_backend(&routes(), &Config::default()), "backend");
}

#[test]
#[ignore = "nécessite Docker"]
fn an_empty_catalog_still_produces_valid_configs() {
    // Cas du premier démarrage : aucune app installée.
    let cfg = Config::default();
    caddy_validate(&render_frontend(&[], &cfg), "frontend vide");
    caddy_validate(&render_backend(&[], &cfg), "backend vide");
}

#[test]
#[ignore = "nécessite Docker"]
fn hosts_with_dashes_produce_valid_matchers() {
    // Les noms de matcher Caddy n'acceptent ni points ni tirets.
    let r = Route {
        host: "mon-app.sous-domaine.example.fr".into(),
        service: "mon-app".into(),
        port: 8080,
        through_anubis: true,
        public: true,
        sso_paths: vec!["/oidc/callback".into()],
        needs_forward_auth: false,
    };
    caddy_validate(&render_frontend(std::slice::from_ref(&r), &Config::default()), "hôte avec tirets");
    caddy_validate(&render_backend(&[r], &Config::default()), "backend avec tirets");
}

/// Le forward-auth produit-il une configuration que Caddy accepte ? (§5.0)
///
/// 🔴 Ce test compte plus que les autres : le bloc forward-auth mélange
/// `request_header`, `handle`, `forward_auth` et `handle_response`, dont l'ordre
/// d'évaluation dans Caddy n'est pas celui de l'écriture. Une erreur ici donnerait un
/// Caddy qui refuse de démarrer — ou pire, qui démarre en n'authentifiant rien.
#[test]
#[ignore = "nécessite Docker"]
fn forward_auth_config_is_accepted_by_caddy() {
    let mut r = Route::new("vieux.example.fr", "vieux-truc", 80);
    r.public = true;
    r.needs_forward_auth = true;

    let cfg = Config {
        forward_auth: Some(hlb_ingress::caddyfile::ForwardAuth::default()),
        ..Config::default()
    };

    let out = render_frontend(&[r], &cfg);
    caddy_validate(&out, "frontend avec portail");
}

/// Un mélange réaliste : une app à SSO natif et une app derrière portail.
#[test]
#[ignore = "nécessite Docker"]
fn a_mixed_frontend_is_accepted_by_caddy() {
    let mut native = Route::new("git.example.fr", "gitea", 3000);
    native.public = true;
    native.sso_paths = vec!["/user/oauth2/PocketID/callback".into()];

    let mut portail = Route::new("vieux.example.fr", "vieux-truc", 80);
    portail.public = true;
    portail.needs_forward_auth = true;
    portail.through_anubis = true;

    let cfg = Config {
        forward_auth: Some(hlb_ingress::caddyfile::ForwardAuth::default()),
        ..Config::default()
    };

    caddy_validate(&render_frontend(&[native, portail], &cfg), "frontend mixte");
}

/// Le bloc ACME wildcard est-il syntaxiquement valide ? (§6.4)
///
/// ⚠️ `caddy validate` ne peut PAS vérifier la directive `dns` : elle vient d'un
/// module absent de l'image standard. On valide donc la structure sans elle — c'est
/// une vérification partielle, et c'est dit plutôt que sous-entendu.
#[test]
#[ignore = "nécessite Docker"]
fn the_wildcard_site_block_is_structurally_valid() {
    use hlb_ingress::caddyfile::Acme;

    // Sans jeton ni fournisseur, `tls` seul est accepté par un Caddy standard : ça
    // valide la structure du bloc (noms, imbrication, respond) sans exiger le module.
    let a = Acme {
        provider: "internal".into(),
        api_token: String::new(),
        base_domain: "example.fr".into(),
        staging: false,
    };

    // On REMPLACE la ligne `dns` par une sous-directive standard plutôt que de la
    // retirer : un bloc `tls { }` vide est refusé par Caddy, et le test échouerait
    // sur son propre montage au lieu de vérifier le générateur.
    let out = render_frontend(&[], &Config { acme: Some(a), ..Config::default() })
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("dns ") {
                "\t\tprotocols tls1.2 tls1.3"
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    caddy_validate(&out, "bloc wildcard");
}
