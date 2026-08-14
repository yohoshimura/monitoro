//! Adresse matérielle (MAC) et ce qu'on peut en déduire.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("adresse MAC invalide « {0} »")]
pub struct MacParseError(String);

/// Une adresse MAC 48 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const ZERO: Self = Self([0; 6]);

    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// Le préfixe constructeur sur 24 bits, tel qu'il est enregistré à l'IEEE.
    pub const fn oui(self) -> u32 {
        u32::from_be_bytes([0, self.0[0], self.0[1], self.0[2]])
    }

    /// Vrai si le bit « localement administré » est positionné.
    ///
    /// C'est le marqueur des adresses randomisées, que tous les téléphones
    /// modernes utilisent pour éviter d'être pistés d'un réseau à l'autre. Une
    /// telle adresse n'appartient à aucun constructeur : la chercher dans le
    /// registre IEEE n'a pas de sens.
    pub const fn is_locally_administered(self) -> bool {
        self.0[0] & 0b0000_0010 != 0
    }

    /// Vrai si le bit de diffusion groupée est positionné.
    ///
    /// Ces adresses ne désignent jamais une machine : elles ne devraient pas
    /// apparaître comme réponse à une requête ARP.
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 0b0000_0001 != 0
    }

    /// Vrai pour `00:00:00:00:00:00`, que certaines API renvoient en guise
    /// d'échec silencieux.
    pub const fn is_zero(self) -> bool {
        matches!(self.0, [0, 0, 0, 0, 0, 0])
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{g:02X}")
    }
}

impl FromStr for MacAddr {
    type Err = MacParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let invalid = || MacParseError(s.to_owned());

        // Deux notations circulent : séparée (`aa:bb:cc:dd:ee:ff`, avec `:` ou
        // `-`) et compacte (`aabbccddeeff`). On accepte les deux.
        let compact: String = trimmed.chars().filter(|c| *c != ':' && *c != '-').collect();

        let separators = trimmed.chars().filter(|c| *c == ':' || *c == '-').count();
        if separators != 0 && separators != 5 {
            return Err(invalid());
        }
        if compact.len() != 12 || !compact.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(invalid());
        }

        let mut octets = [0u8; 6];
        for (i, octet) in octets.iter_mut().enumerate() {
            *octet = u8::from_str_radix(&compact[i * 2..i * 2 + 2], 16).map_err(|_| invalid())?;
        }

        Ok(Self(octets))
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl serde::Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPLE: MacAddr = MacAddr::new([0x3C, 0x22, 0xFB, 0x01, 0x02, 0x03]);

    #[test]
    fn l_affichage_est_en_majuscules_separees_par_deux_points() {
        assert_eq!(APPLE.to_string(), "3C:22:FB:01:02:03");
    }

    #[test]
    fn les_notations_courantes_sont_toutes_acceptees() {
        for input in [
            "3C:22:FB:01:02:03",
            "3c:22:fb:01:02:03",
            "3C-22-FB-01-02-03",
            "3c22fb010203",
            "  3C:22:FB:01:02:03  ",
        ] {
            assert_eq!(
                input.parse::<MacAddr>().unwrap(),
                APPLE,
                "échec sur {input}"
            );
        }
    }

    #[test]
    fn une_notation_incoherente_est_rejetee() {
        for input in [
            "",
            "3C:22:FB:01:02",       // trop court
            "3C:22:FB:01:02:03:04", // trop long
            "3C:22:FB:01:02:ZZ",    // pas hexadécimal
            "3C:22FB:01:02:03",     // séparateurs incohérents
        ] {
            assert!(
                input.parse::<MacAddr>().is_err(),
                "« {input} » aurait dû être rejetée"
            );
        }
    }

    #[test]
    fn l_analyse_est_l_inverse_de_l_affichage() {
        assert_eq!(APPLE.to_string().parse::<MacAddr>().unwrap(), APPLE);
    }

    #[test]
    fn le_prefixe_oui_reprend_les_trois_premiers_octets() {
        assert_eq!(APPLE.oui(), 0x3C_22_FB);
    }

    #[test]
    fn le_bit_localement_administre_est_detecte() {
        // 0x02 : deuxième bit de poids faible du premier octet.
        assert!(MacAddr::new([0x02, 0, 0, 0, 0, 0]).is_locally_administered());
        assert!(MacAddr::new([0xDA, 0, 0, 0, 0, 0]).is_locally_administered());
        assert!(!APPLE.is_locally_administered());
    }

    #[test]
    fn le_bit_de_diffusion_groupee_est_distinct_du_precedent() {
        assert!(MacAddr::new([0x01, 0, 0, 0, 0, 0]).is_multicast());
        assert!(!MacAddr::new([0x02, 0, 0, 0, 0, 0]).is_multicast());
        assert!(!APPLE.is_multicast());
    }

    #[test]
    fn l_adresse_nulle_est_reconnue() {
        assert!(MacAddr::ZERO.is_zero());
        assert!(!APPLE.is_zero());
    }

    #[test]
    fn la_serialisation_json_produit_une_chaine() {
        let json = serde_json::to_string(&APPLE).unwrap();
        assert_eq!(json, "\"3C:22:FB:01:02:03\"");
    }
}
