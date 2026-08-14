//! Détection du réseau local, pour que `monitoro` sans argument fasse la
//! bonne chose.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::error::{Error, Result};

/// L'interface retenue et le réseau qu'elle dessert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNetwork {
    /// Nom lisible de l'interface, pour l'affichage.
    pub interface: String,
    /// Adresse de cette machine sur ce réseau.
    pub address: Ipv4Addr,
    /// Le réseau lui-même, bits d'hôte remis à zéro.
    pub network: Ipv4Net,
}

/// Détermine le réseau à scanner par défaut.
///
/// On part de l'interface portant la route par défaut : sur une machine
/// chargée d'adaptateurs virtuels (machines virtuelles, VPN, conteneurs), c'est
/// la seule heuristique qui désigne de façon fiable le réseau où se trouvent
/// réellement les autres appareils.
pub fn detect() -> Result<LocalNetwork> {
    let candidates = netdev::get_default_interface()
        .map(|interface| vec![interface])
        .unwrap_or_else(|_| netdev::get_interfaces());

    candidates
        .into_iter()
        .filter(|interface| !interface.is_loopback())
        .find_map(|interface| {
            let label = interface
                .friendly_name
                .clone()
                .or_else(|| interface.description.clone())
                .unwrap_or_else(|| interface.name.clone());

            interface
                .ipv4
                .iter()
                .find(|net| usable(net.addr()))
                .map(|net| LocalNetwork {
                    interface: label,
                    address: net.addr(),
                    network: net.trunc(),
                })
        })
        .ok_or(Error::NoLocalInterface)
}

/// Une adresse depuis laquelle il est sensé de scanner.
///
/// Le lien-local (169.254/16) signale une configuration automatique ratée :
/// balayer ce réseau ne trouverait rien.
fn usable(addr: Ipv4Addr) -> bool {
    !addr.is_loopback() && !addr.is_link_local() && !addr.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_adresses_inexploitables_sont_ecartees() {
        assert!(usable(Ipv4Addr::new(192, 168, 1, 10)));
        assert!(usable(Ipv4Addr::new(10, 0, 0, 96)));

        assert!(!usable(Ipv4Addr::LOCALHOST));
        assert!(!usable(Ipv4Addr::UNSPECIFIED));
        assert!(!usable(Ipv4Addr::new(169, 254, 3, 7)), "lien-local");
    }

    #[test]
    fn la_detection_decrit_un_reseau_coherent() {
        // Dépend de la machine : on ne vérifie que la cohérence interne du
        // résultat, jamais une adresse particulière.
        let Ok(local) = detect() else {
            return; // machine sans réseau : rien à vérifier
        };

        assert!(!local.interface.is_empty());
        assert!(usable(local.address));
        assert!(
            local.network.contains(&local.address),
            "{} devrait appartenir à {}",
            local.address,
            local.network
        );
        assert_eq!(local.network, local.network.trunc(), "réseau non normalisé");
    }
}
