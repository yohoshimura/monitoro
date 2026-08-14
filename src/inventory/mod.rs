//! Le modèle de domaine : ce qu'on a appris des machines du réseau.
//!
//! Ces types ne savent ni sonder ni afficher. Ils accumulent des observations
//! venues de plusieurs sondes et les fusionnent en une vue cohérente.

pub mod mac;
pub mod oui;

pub use mac::{MacAddr, MacParseError};
pub use oui::Vendor;

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Une machine observée sur le réseau.
///
/// Tous les champs sauf `ip` sont optionnels : une sonde ARP apporte la MAC
/// sans les ports, une sonde TCP l'inverse, et l'enrichissement complète le
/// nom plus tard. C'est la fusion qui reconstitue l'ensemble.
#[derive(Debug, Clone, PartialEq)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub mac: Option<MacAddr>,
    pub hostname: Option<String>,
    pub vendor: Option<Vendor>,
    pub open_ports: Vec<u16>,
    pub rtt: Option<Duration>,
    /// Noms des sondes qui ont vu cet hôte, dans l'ordre de découverte.
    pub sources: Vec<&'static str>,
}

impl Host {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            mac: None,
            hostname: None,
            vendor: None,
            open_ports: Vec::new(),
            rtt: None,
            sources: Vec::new(),
        }
    }

    /// Vrai si l'adresse matérielle est randomisée (téléphone moderne, en
    /// général). Distinct d'un constructeur simplement absent du registre.
    pub fn mac_is_randomized(&self) -> bool {
        self.mac.is_some_and(MacAddr::is_locally_administered)
    }

    /// Intègre une nouvelle observation du même hôte.
    ///
    /// Les informations déjà connues ne sont jamais écrasées : une sonde qui
    /// ne sait rien d'un champ ne doit pas effacer ce qu'une autre a trouvé.
    /// Retourne `true` si quelque chose a effectivement changé.
    pub fn merge_from(&mut self, other: Host) -> bool {
        debug_assert_eq!(self.ip, other.ip, "fusion de deux hôtes distincts");
        let mut changed = false;

        if self.mac.is_none() && other.mac.is_some() {
            self.mac = other.mac;
            changed = true;
        }
        if self.hostname.is_none() && other.hostname.is_some() {
            self.hostname = other.hostname;
            changed = true;
        }
        if self.vendor.is_none() && other.vendor.is_some() {
            self.vendor = other.vendor;
            changed = true;
        }

        for port in other.open_ports {
            if let Err(index) = self.open_ports.binary_search(&port) {
                self.open_ports.insert(index, port);
                changed = true;
            }
        }

        // Le temps de réponse le plus court est le plus représentatif : les
        // autres incluent l'attente derrière un sémaphore saturé.
        if let Some(rtt) = other.rtt
            && self.rtt.is_none_or(|current| rtt < current)
        {
            self.rtt = Some(rtt);
            changed = true;
        }

        for source in other.sources {
            if !self.sources.contains(&source) {
                self.sources.push(source);
                changed = true;
            }
        }

        changed
    }
}

/// Résultat de l'insertion d'une observation dans l'inventaire.
///
/// Le moteur s'en sert pour choisir entre un événement « hôte découvert » et
/// « hôte complété », ce qui évite à la TUI de redessiner sans raison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upsert {
    Inserted,
    Updated,
    Unchanged,
}

/// Les hôtes connus, indexés par adresse IP.
///
/// `BTreeMap` plutôt que `HashMap` : l'itération suit l'ordre numérique des
/// adresses, ce qui est l'ordre d'affichage attendu et rend les tests
/// déterministes.
#[derive(Debug, Default, Clone)]
pub struct Inventory {
    hosts: BTreeMap<Ipv4Addr, Host>,
}

impl Inventory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, host: Host) -> Upsert {
        match self.hosts.entry(host.ip) {
            Entry::Vacant(slot) => {
                slot.insert(host);
                Upsert::Inserted
            }
            Entry::Occupied(mut slot) => {
                if slot.get_mut().merge_from(host) {
                    Upsert::Updated
                } else {
                    Upsert::Unchanged
                }
            }
        }
    }

    pub fn get(&self, ip: Ipv4Addr) -> Option<&Host> {
        self.hosts.get(&ip)
    }

    /// Les hôtes, par adresse croissante.
    pub fn hosts(&self) -> impl ExactSizeIterator<Item = &Host> {
        self.hosts.values()
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const MAC: MacAddr = MacAddr::new([0x3C, 0x22, 0xFB, 0x01, 0x02, 0x03]);

    fn host_with_mac() -> Host {
        Host {
            mac: Some(MAC),
            sources: vec!["arp"],
            ..Host::new(IP)
        }
    }

    fn host_with_ports() -> Host {
        Host {
            open_ports: vec![80, 443],
            rtt: Some(Duration::from_millis(12)),
            sources: vec!["tcp"],
            ..Host::new(IP)
        }
    }

    #[test]
    fn la_fusion_combine_des_observations_complementaires() {
        let mut host = host_with_mac();
        assert!(host.merge_from(host_with_ports()));

        assert_eq!(host.mac, Some(MAC));
        assert_eq!(host.open_ports, vec![80, 443]);
        assert_eq!(host.rtt, Some(Duration::from_millis(12)));
        assert_eq!(host.sources, vec!["arp", "tcp"]);
    }

    #[test]
    fn la_fusion_n_ecrase_jamais_une_information_connue() {
        let mut host = host_with_mac();
        let autre_mac = MacAddr::new([0xAA, 0xBB, 0xCC, 0, 0, 0]);

        host.merge_from(Host {
            mac: Some(autre_mac),
            ..Host::new(IP)
        });

        assert_eq!(host.mac, Some(MAC), "la première MAC devait être conservée");
    }

    #[test]
    fn les_ports_restent_tries_et_sans_doublon() {
        let mut host = Host {
            open_ports: vec![443],
            ..Host::new(IP)
        };

        host.merge_from(Host {
            open_ports: vec![80, 443, 22],
            ..Host::new(IP)
        });

        assert_eq!(host.open_ports, vec![22, 80, 443]);
    }

    #[test]
    fn la_fusion_retient_le_temps_de_reponse_le_plus_court() {
        let mut host = Host {
            rtt: Some(Duration::from_millis(50)),
            ..Host::new(IP)
        };

        host.merge_from(Host {
            rtt: Some(Duration::from_millis(8)),
            ..Host::new(IP)
        });
        assert_eq!(host.rtt, Some(Duration::from_millis(8)));

        host.merge_from(Host {
            rtt: Some(Duration::from_millis(30)),
            ..Host::new(IP)
        });
        assert_eq!(host.rtt, Some(Duration::from_millis(8)), "régression");
    }

    #[test]
    fn une_fusion_sans_nouveaute_ne_signale_aucun_changement() {
        let mut host = host_with_mac();
        assert!(!host.merge_from(host_with_mac()));
    }

    #[test]
    fn l_inventaire_distingue_insertion_mise_a_jour_et_statu_quo() {
        let mut inventory = Inventory::new();

        assert_eq!(inventory.upsert(host_with_mac()), Upsert::Inserted);
        assert_eq!(inventory.upsert(host_with_ports()), Upsert::Updated);
        assert_eq!(inventory.upsert(host_with_ports()), Upsert::Unchanged);
        assert_eq!(inventory.len(), 1, "un seul hôte, fusionné");
    }

    #[test]
    fn l_inventaire_itere_par_adresse_croissante() {
        let mut inventory = Inventory::new();
        for last in [30u8, 2, 200, 9] {
            inventory.upsert(Host::new(Ipv4Addr::new(192, 168, 1, last)));
        }

        let ordre: Vec<u8> = inventory.hosts().map(|h| h.ip.octets()[3]).collect();
        assert_eq!(ordre, vec![2, 9, 30, 200]);
    }

    #[test]
    fn une_mac_randomisee_est_signalee_au_niveau_de_l_hote() {
        let randomisee = Host {
            mac: Some(MacAddr::new([0xDA, 0x22, 0xFB, 0, 0, 1])),
            ..Host::new(IP)
        };

        assert!(randomisee.mac_is_randomized());
        assert!(!host_with_mac().mac_is_randomized());
        assert!(!Host::new(IP).mac_is_randomized(), "aucune MAC connue");
    }
}
