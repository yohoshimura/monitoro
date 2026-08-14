//! Résolution du constructeur à partir du préfixe IEEE de l'adresse MAC.
//!
//! La table est générée à la compilation par `build.rs` depuis
//! `assets/oui.csv` : rien n'est lu ni téléchargé à l'exécution.

use std::fmt;

use super::MacAddr;

include!(concat!(env!("OUT_DIR"), "/oui_table.rs"));

/// Ce que le registre IEEE permet de dire d'une adresse MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vendor {
    /// Préfixe trouvé dans le registre.
    Known(&'static str),
    /// Adresse localement administrée : elle est randomisée et n'appartient à
    /// aucun constructeur. À distinguer d'`Unknown`, sans quoi la moitié d'un
    /// réseau domestique paraît non identifiée à tort.
    Randomized,
    /// Préfixe globalement unique, mais absent du registre embarqué.
    Unknown,
}

impl Vendor {
    /// Le nom du constructeur, s'il y en a un.
    pub fn name(self) -> Option<&'static str> {
        match self {
            Self::Known(name) => Some(name),
            Self::Randomized | Self::Unknown => None,
        }
    }

    pub fn is_randomized(self) -> bool {
        matches!(self, Self::Randomized)
    }
}

impl fmt::Display for Vendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(name) => f.write_str(name),
            Self::Randomized => f.write_str("(MAC randomisée)"),
            Self::Unknown => f.write_str("(inconnu)"),
        }
    }
}

/// Cherche le constructeur correspondant à une adresse MAC.
pub fn lookup(mac: MacAddr) -> Vendor {
    if mac.is_locally_administered() {
        return Vendor::Randomized;
    }

    match OUI_TABLE.binary_search_by_key(&mac.oui(), |(prefix, _)| *prefix) {
        Ok(index) => Vendor::Known(OUI_TABLE[index].1),
        Err(_) => Vendor::Unknown,
    }
}

/// Nombre de préfixes embarqués. Utile au diagnostic et aux tests.
pub fn table_len() -> usize {
    OUI_TABLE.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_table_embarquee_n_est_pas_vide() {
        assert!(
            table_len() > 10_000,
            "table anormalement courte ({}) : assets/oui.csv est-il présent ?",
            table_len()
        );
    }

    #[test]
    fn la_table_est_triee_et_sans_doublon() {
        // La recherche binaire en dépend entièrement.
        assert!(
            OUI_TABLE.windows(2).all(|w| w[0].0 < w[1].0),
            "la table doit être strictement croissante"
        );
    }

    #[test]
    fn un_prefixe_du_registre_est_retrouve() {
        // 00:00:5E appartient à l'IANA, qui y réserve la plage
        // 00:00:5E:00:53:00–FF aux exemples de documentation (RFC 7042).
        // Doublement pratique ici : l'adresse est à la fois publiable et
        // réellement présente dans le registre.
        let vendor = lookup("00:00:5E:00:53:01".parse().unwrap());
        let name = vendor.name().expect("préfixe attendu dans le registre");
        assert!(name.contains("IANA"), "constructeur inattendu : {name}");
    }

    #[test]
    fn une_adresse_randomisee_n_est_pas_cherchee_dans_le_registre() {
        // Bit localement administré positionné : le préfixe ne veut rien dire,
        // même s'il coïncide avec une entrée du registre.
        let vendor = lookup("02:00:5E:00:53:01".parse().unwrap());

        assert_eq!(vendor, Vendor::Randomized);
        assert!(vendor.is_randomized());
        assert_eq!(vendor.name(), None);
    }

    #[test]
    fn un_prefixe_absent_du_registre_reste_inconnu() {
        // On cherche le trou dans la table plutôt que de coder en dur un
        // préfixe « libre » : le registre IEEE grossit, et une constante figée
        // finirait par être assignée, rendant le test instable au premier
        // rafraîchissement d'assets/oui.csv.
        let libre = (0..=0x00FF_FFFFu32)
            .find(|prefix| {
                let premier_octet = (prefix >> 16) as u8;
                // Ni diffusion groupée, ni localement administré : sans quoi on
                // testerait un autre chemin que la recherche dans la table.
                premier_octet & 0b11 == 0
                    && OUI_TABLE.binary_search_by_key(prefix, |(p, _)| *p).is_err()
            })
            .expect("le registre ne couvre pas tout l'espace des préfixes");

        let mac = MacAddr::new([
            (libre >> 16) as u8,
            (libre >> 8) as u8,
            libre as u8,
            0x00,
            0x00,
            0x01,
        ]);

        assert_eq!(lookup(mac), Vendor::Unknown, "préfixe testé : {mac}");
    }

    #[test]
    fn l_adresse_nulle_appartient_bien_a_un_constructeur() {
        // Piège classique : 00:00:00 *est* une assignation MA-L historique
        // (Xerox). Le traiter comme « inconnu » serait faux.
        assert!(lookup(MacAddr::ZERO).name().is_some());
    }

    #[test]
    fn chaque_variante_a_un_affichage_lisible() {
        assert_eq!(Vendor::Known("Acme").to_string(), "Acme");
        assert_eq!(Vendor::Randomized.to_string(), "(MAC randomisée)");
        assert_eq!(Vendor::Unknown.to_string(), "(inconnu)");
    }
}
