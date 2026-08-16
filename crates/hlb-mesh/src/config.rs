//! Adressage et génération des configurations WireGuard.
//!
//! Le mesh est **complet** : chaque nœud connaît tous les autres. Sur un homelab de
//! trois à dix machines, c'est le bon choix — pas de point de passage unique, et un
//! nœud qui tombe n'isole personne. Une topologie en étoile serait plus économe en
//! configuration, mais ferait du hub un point de défaillance pour tout le trafic
//! inter-nœuds, ce qui est exactement ce qu'on cherche à éviter.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::keys::KeyPair;
use crate::{Error, Result};

/// Un nœud du mesh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub name: String,
    /// Adresse dans le réseau du mesh.
    pub mesh_ip: Ipv4Addr,
    pub public_key: String,
    /// Adresse joignable pour établir le tunnel. Absente pour un nœud derrière NAT :
    /// il devra initier la connexion lui-même.
    pub endpoint: Option<String>,
}

/// Le mesh dans son ensemble.
#[derive(Debug, Clone)]
pub struct MeshConfig {
    /// Réseau privé du mesh, en /24. `10.42.0.0` par défaut.
    network: [u8; 3],
    port: u16,
    peers: BTreeMap<String, Peer>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            // 10.42.0.0/24 : peu susceptible d'entrer en conflit avec le réseau
            // domestique (souvent 192.168.1.0/24) ni avec les réseaux Docker
            // (172.17-31.0.0/16 et 10.0.0.0/24 pour l'overlay ingress).
            network: [10, 42, 0],
            port: 51820,
            peers: BTreeMap::new(),
        }
    }
}

impl MeshConfig {
    pub fn new(network: [u8; 3], port: u16) -> Self {
        Self {
            network,
            port,
            peers: BTreeMap::new(),
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values()
    }

    pub fn get(&self, name: &str) -> Option<&Peer> {
        self.peers.get(name)
    }

    /// Le réseau du mesh en notation CIDR.
    pub fn cidr(&self) -> String {
        format!("{}.{}.{}.0/24", self.network[0], self.network[1], self.network[2])
    }

    /// Ajoute un nœud, en lui attribuant la première adresse libre.
    ///
    /// L'attribution est **déterministe et stable** : un nœud garde son adresse tant
    /// qu'il est dans le mesh. Une adresse qui changerait au gré des ajouts casserait
    /// les configurations déjà déployées sur les autres nœuds.
    pub fn add_node(
        &mut self,
        name: &str,
        public_key: &str,
        endpoint: Option<String>,
    ) -> Result<Peer> {
        if self.peers.contains_key(name) {
            return Err(Error::DuplicateNode(name.to_string()));
        }

        // .1 est réservé par convention (passerelle), .0 et .255 le sont par le
        // protocole. Restent .2 à .254.
        let occupees: std::collections::BTreeSet<u8> =
            self.peers.values().map(|p| p.mesh_ip.octets()[3]).collect();

        let libre = (2u8..=254)
            .find(|o| !occupees.contains(o))
            .ok_or_else(|| Error::AddressPoolExhausted(253, self.cidr()))?;

        let peer = Peer {
            name: name.to_string(),
            mesh_ip: Ipv4Addr::new(self.network[0], self.network[1], self.network[2], libre),
            public_key: public_key.to_string(),
            endpoint,
        };

        self.peers.insert(name.to_string(), peer.clone());
        Ok(peer)
    }

    /// La configuration `wg-quick` d'un nœud donné.
    ///
    /// La clé privée est passée à part : elle vit au coffre et ne doit jamais
    /// transiter par la structure qui décrit le mesh.
    pub fn render_for(&self, node: &str, private_key: &str) -> Option<String> {
        let moi = self.peers.get(node)?;
        let mut s = String::new();

        s.push_str("# Généré par HomelabUS — ne pas éditer à la main.\n");
        s.push_str(&format!("# nœud : {}\n\n", moi.name));
        s.push_str("[Interface]\n");
        s.push_str(&format!("PrivateKey = {private_key}\n"));
        s.push_str(&format!("Address = {}/24\n", moi.mesh_ip));

        // Un nœud sans endpoint est derrière NAT : il n'a pas à écouter, il
        // initiera les connexions.
        if moi.endpoint.is_some() {
            s.push_str(&format!("ListenPort = {}\n", self.port));
        }

        for p in self.peers.values() {
            if p.name == node {
                continue;
            }
            s.push_str(&format!("\n[Peer]\n# {}\n", p.name));
            s.push_str(&format!("PublicKey = {}\n", p.public_key));
            // /32 : chaque pair ne route que sa propre adresse. Un /24 ici ferait
            // que le dernier pair déclaré capterait tout le trafic du mesh.
            s.push_str(&format!("AllowedIPs = {}/32\n", p.mesh_ip));

            if let Some(e) = &p.endpoint {
                s.push_str(&format!("Endpoint = {e}:{}\n", self.port));
            }
            // Maintient la correspondance NAT ouverte. Sans ça, un nœud derrière
            // box devient injoignable après quelques minutes de silence.
            s.push_str("PersistentKeepalive = 25\n");
        }

        Some(s)
    }

    /// Les adresses mesh de tous les nœuds — ce sur quoi Swarm doit écouter.
    pub fn advertise_addr_for(&self, node: &str) -> Option<String> {
        self.peers.get(node).map(|p| p.mesh_ip.to_string())
    }
}

/// Crée un nœud avec une paire de clés fraîche.
pub fn provision_node(
    mesh: &mut MeshConfig,
    name: &str,
    endpoint: Option<String>,
) -> Result<(Peer, KeyPair)> {
    let kp = KeyPair::generate();
    let peer = mesh.add_node(name, &kp.public, endpoint)?;
    Ok((peer, kp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mesh_avec(noms: &[&str]) -> MeshConfig {
        let mut m = MeshConfig::default();
        for n in noms {
            m.add_node(n, &format!("cle-{n}"), Some(format!("{n}.example.fr")))
                .expect("ajout");
        }
        m
    }

    #[test]
    fn addresses_start_at_two() {
        // .0 et .255 sont réservés par le protocole, .1 par convention.
        let m = mesh_avec(&["n1", "n2"]);
        assert_eq!(m.get("n1").expect("n1").mesh_ip, Ipv4Addr::new(10, 42, 0, 2));
        assert_eq!(m.get("n2").expect("n2").mesh_ip, Ipv4Addr::new(10, 42, 0, 3));
    }

    #[test]
    fn an_address_is_stable_across_additions() {
        // 🔴 Une adresse qui changerait au gré des ajouts casserait toutes les
        // configurations déjà déployées sur les autres nœuds.
        let mut m = mesh_avec(&["n1", "n2"]);
        let avant = m.get("n1").expect("n1").mesh_ip;

        m.add_node("n3", "cle-n3", None).expect("ajout");
        assert_eq!(m.get("n1").expect("n1").mesh_ip, avant);
    }

    #[test]
    fn a_duplicate_node_is_refused() {
        let mut m = mesh_avec(&["n1"]);
        assert!(matches!(
            m.add_node("n1", "autre-cle", None),
            Err(Error::DuplicateNode(_))
        ));
    }

    #[test]
    fn the_default_network_avoids_common_collisions() {
        // 192.168.1.0/24 est le réseau domestique le plus répandu, et Docker
        // utilise 172.17-31.0.0/16 ainsi que 10.0.0.0/24 pour l'overlay ingress.
        let c = MeshConfig::default().cidr();
        assert_eq!(c, "10.42.0.0/24");
        assert!(!c.starts_with("192.168."));
        assert!(!c.starts_with("172."));
    }

    #[test]
    fn a_configuration_lists_every_other_peer() {
        let m = mesh_avec(&["n1", "n2", "n3"]);
        let c = m.render_for("n1", "MA-CLE-PRIVEE").expect("config");

        assert!(c.contains("PrivateKey = MA-CLE-PRIVEE"));
        assert!(c.contains("Address = 10.42.0.2/24"));
        // Les deux autres, et pas soi-même.
        assert_eq!(c.matches("[Peer]").count(), 2, "{c}");
        assert!(c.contains("cle-n2"));
        assert!(c.contains("cle-n3"));
        assert!(!c.contains("cle-n1"), "un nœud ne doit pas être son propre pair");
    }

    #[test]
    fn each_peer_routes_only_its_own_address() {
        // 🔴 Un /24 ici ferait que le dernier pair déclaré capterait tout le trafic
        // du mesh — les autres deviendraient injoignables sans erreur visible.
        let m = mesh_avec(&["n1", "n2"]);
        let c = m.render_for("n1", "x").expect("config");

        assert!(c.contains("AllowedIPs = 10.42.0.3/32"), "{c}");
        assert!(!c.contains("AllowedIPs = 10.42.0.0/24"));
    }

    #[test]
    fn a_natted_node_does_not_listen_but_keeps_alive() {
        let mut m = MeshConfig::default();
        m.add_node("public", "cle-pub", Some("public.example.fr".into())).expect("ajout");
        m.add_node("derriere-nat", "cle-nat", None).expect("ajout");

        let c = m.render_for("derriere-nat", "x").expect("config");
        assert!(!c.contains("ListenPort"), "un nœud NATé n'a pas à écouter :\n{c}");
        // Mais il doit maintenir la correspondance NAT ouverte, sinon il devient
        // injoignable après quelques minutes de silence.
        assert!(c.contains("PersistentKeepalive = 25"));
        assert!(c.contains("Endpoint = public.example.fr:51820"));
    }

    #[test]
    fn a_public_node_listens() {
        let m = mesh_avec(&["n1"]);
        assert!(m.render_for("n1", "x").expect("config").contains("ListenPort = 51820"));
    }

    #[test]
    fn an_unknown_node_has_no_configuration() {
        assert!(mesh_avec(&["n1"]).render_for("inconnu", "x").is_none());
    }

    #[test]
    fn the_generated_file_warns_against_hand_editing() {
        let c = mesh_avec(&["n1"]).render_for("n1", "x").expect("config");
        assert!(c.contains("ne pas éditer à la main"));
    }

    #[test]
    fn swarm_advertises_on_the_mesh_address() {
        // 🔴 C'est tout l'objet du mesh : Swarm ne doit pas écouter sur l'IP
        // publique, où ses ports 2377/7946/4789 seraient exposés.
        let m = mesh_avec(&["n1"]);
        assert_eq!(m.advertise_addr_for("n1").as_deref(), Some("10.42.0.2"));
    }

    #[test]
    fn provisioning_generates_a_usable_pair() {
        let mut m = MeshConfig::default();
        let (peer, kp) = provision_node(&mut m, "n1", None).expect("provisionnement");

        assert_eq!(peer.public_key, kp.public);
        // La configuration doit être rendue avec la clé privée correspondante.
        let c = m.render_for("n1", &kp.private).expect("config");
        assert!(c.contains(&kp.private));
        // Et surtout PAS la clé privée dans la structure partagée du mesh.
        assert!(!peer.public_key.contains(&kp.private));
    }

    #[test]
    fn the_pool_is_bounded() {
        let mut m = MeshConfig::default();
        for i in 0..253 {
            m.add_node(&format!("n{i}"), "k", None).expect("ajout");
        }
        assert!(matches!(
            m.add_node("de-trop", "k", None),
            Err(Error::AddressPoolExhausted(..))
        ));
    }
}
