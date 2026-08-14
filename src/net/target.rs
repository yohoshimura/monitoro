//! Analyse d'une cible de scan et énumération des adresses à sonder.
//!
//! Accepte une notation CIDR (`192.168.1.0/24`) ou une adresse seule
//! (`10.0.0.5`, équivalente à `/32`).

use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;

use crate::error::{Error, Result};

/// Préfixe le plus large accepté sans confirmation explicite.
///
/// Un /16 représente déjà 65 534 adresses. Au-delà, la durée du balayage se
/// compte en heures : mieux vaut supposer une faute de frappe et demander
/// confirmation que lancer le scan.
pub const MIN_PREFIX_WITHOUT_CONFIRM: u8 = 16;

/// Un ensemble d'adresses IPv4 à sonder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetSet {
    net: Ipv4Net,
}

impl TargetSet {
    /// Analyse une cible fournie par l'utilisateur.
    ///
    /// `allow_large` correspond au drapeau `--yes` : il lève le garde-fou sur
    /// les préfixes très larges.
    pub fn parse(input: &str, allow_large: bool) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidTarget {
                input: input.to_owned(),
                reason: "cible vide".to_owned(),
            });
        }

        let net = if trimmed.contains('/') {
            Ipv4Net::from_str(trimmed).map_err(|e| Error::InvalidTarget {
                input: trimmed.to_owned(),
                reason: e.to_string(),
            })?
        } else {
            let addr = Ipv4Addr::from_str(trimmed).map_err(|e| Error::InvalidTarget {
                input: trimmed.to_owned(),
                reason: e.to_string(),
            })?;
            Ipv4Net::new(addr, 32).expect("/32 est toujours un préfixe valide")
        };

        Self::from_net(net, allow_large)
    }

    /// Construit un ensemble depuis un réseau déjà analysé.
    ///
    /// Les bits d'hôte sont ignorés : `192.168.1.5/24` désigne le réseau
    /// `192.168.1.0/24` tout entier.
    pub fn from_net(net: Ipv4Net, allow_large: bool) -> Result<Self> {
        let set = Self { net: net.trunc() };

        if !allow_large && set.net.prefix_len() < MIN_PREFIX_WITHOUT_CONFIRM {
            return Err(Error::TargetTooLarge {
                prefix: set.net.prefix_len(),
                hosts: set.len(),
            });
        }

        Ok(set)
    }

    /// Nombre d'adresses qui seront réellement sondées.
    pub fn len(&self) -> u64 {
        match self.net.prefix_len() {
            32 => 1,
            // Un /31 est un lien point à point (RFC 3021) : les deux adresses
            // sont utilisables, il n'y a ni réseau ni diffusion.
            31 => 2,
            // Ailleurs, l'adresse de réseau et celle de diffusion sont exclues.
            p => (1u64 << (32 - p)) - 2,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Les adresses à sonder, dans l'ordre croissant.
    pub fn iter(&self) -> impl Iterator<Item = Ipv4Addr> + use<> {
        self.net.hosts()
    }

    pub fn network(&self) -> Ipv4Net {
        self.net
    }

    /// Vrai si la cible relève d'un réseau privé, de la boucle locale ou du
    /// lien-local.
    ///
    /// monitoro est un outil d'administration de son propre réseau : scanner
    /// hors de ces plages est légitime mais mérite un avertissement visible.
    pub fn is_private(&self) -> bool {
        let addr = self.net.network();
        addr.is_private() || addr.is_loopback() || addr.is_link_local()
    }
}

impl std::fmt::Display for TargetSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.net.prefix_len() == 32 {
            write!(f, "{}", self.net.network())
        } else {
            write!(f, "{}", self.net)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> TargetSet {
        TargetSet::parse(input, false).expect("cible valide")
    }

    #[test]
    fn un_slash_24_exclut_reseau_et_diffusion() {
        let target = parse("192.168.1.0/24");
        let hosts: Vec<_> = target.iter().collect();

        assert_eq!(target.len(), 254);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn une_adresse_seule_vaut_slash_32() {
        let target = parse("10.0.0.5");
        let hosts: Vec<_> = target.iter().collect();

        assert_eq!(target.len(), 1);
        assert_eq!(hosts, vec![Ipv4Addr::new(10, 0, 0, 5)]);
    }

    #[test]
    fn les_bits_d_hote_sont_ignores() {
        let target = parse("192.168.1.5/24");

        assert_eq!(target.network().network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(target.len(), 254);
    }

    #[test]
    fn un_slash_31_designe_les_deux_extremites() {
        let target = parse("10.0.0.0/31");

        assert_eq!(target.len(), 2);
        assert_eq!(target.iter().count(), 2);
    }

    #[test]
    fn la_longueur_annoncee_correspond_toujours_a_l_iteration() {
        for prefix in 20..=32u8 {
            let target = TargetSet::parse(&format!("10.0.0.0/{prefix}"), false).unwrap();
            assert_eq!(
                target.len() as usize,
                target.iter().count(),
                "désaccord sur /{prefix}"
            );
        }
    }

    #[test]
    fn une_plage_trop_large_est_refusee_sans_confirmation() {
        let err = TargetSet::parse("10.0.0.0/8", false).unwrap_err();

        assert!(
            matches!(err, Error::TargetTooLarge { prefix: 8, .. }),
            "erreur inattendue : {err}"
        );
    }

    #[test]
    fn une_plage_trop_large_est_acceptee_avec_confirmation() {
        assert!(TargetSet::parse("10.0.0.0/8", true).is_ok());
    }

    #[test]
    fn le_seuil_lui_meme_est_accepte() {
        assert!(TargetSet::parse("10.0.0.0/16", false).is_ok());
    }

    #[test]
    fn une_saisie_incoherente_est_rejetee() {
        for input in ["", "  ", "pas-une-ip", "192.168.1.0/33", "999.1.1.1", "::1"] {
            assert!(
                TargetSet::parse(input, false).is_err(),
                "« {input} » aurait dû être rejetée"
            );
        }
    }

    #[test]
    fn les_plages_privees_sont_reconnues() {
        for input in [
            "192.168.1.0/24",
            "10.0.0.0/16",
            "172.16.0.0/16",
            "127.0.0.1",
        ] {
            assert!(parse(input).is_private(), "{input} devrait être privée");
        }

        for input in ["8.8.8.8", "1.1.1.0/24"] {
            assert!(!parse(input).is_private(), "{input} devrait être publique");
        }
    }

    #[test]
    fn l_affichage_omet_le_prefixe_pour_une_adresse_seule() {
        assert_eq!(parse("10.0.0.5").to_string(), "10.0.0.5");
        assert_eq!(parse("192.168.1.0/24").to_string(), "192.168.1.0/24");
    }
}
