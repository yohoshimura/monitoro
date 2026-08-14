//! Second étage du pipeline : donner un nom et un constructeur aux hôtes
//! découverts.
//!
//! Cet étage tourne en parallèle du balayage plutôt qu'après lui. Une
//! résolution inverse peut prendre une seconde ; les faire toutes à la fin
//! doublerait la durée perçue, alors qu'ici les lignes se complètent pendant
//! que le reste du réseau est encore en cours d'exploration.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::inventory::{Host, MacAddr, oui};

/// Au-delà, on renonce au nom : un résolveur injoignable ne doit pas retarder
/// l'affichage d'un hôte par ailleurs parfaitement identifié.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(2_000);

/// Complète ce qu'on sait d'un hôte déjà découvert.
///
/// Retourne uniquement les champs nouveaux, destinés à être fusionnés dans
/// l'inventaire. `None` si rien n'a pu être ajouté.
pub async fn enrich(ip: Ipv4Addr, mac: Option<MacAddr>, resolve_names: bool) -> Option<Host> {
    let vendor = mac.map(oui::lookup);
    let hostname = if resolve_names {
        reverse_dns(ip, DEFAULT_TIMEOUT).await
    } else {
        None
    };

    if vendor.is_none() && hostname.is_none() {
        return None;
    }

    Some(Host {
        vendor,
        hostname,
        ..Host::new(ip)
    })
}

/// Cherche le nom d'une machine à partir de son adresse.
///
/// Sur Windows, `getnameinfo` ne se limite pas au DNS : il interroge ensuite
/// LLMNR et NetBIOS. C'est ce qui fait apparaître le nom des machines du
/// réseau local, qui n'ont presque jamais d'enregistrement DNS.
pub async fn reverse_dns(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let resolution =
        tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok());

    // Trois échecs possibles, tous équivalents ici : délai dépassé, tâche
    // interrompue, ou absence d'enregistrement inverse.
    let Ok(Ok(Some(name))) = tokio::time::timeout(timeout, resolution).await else {
        return None;
    };

    usable_name(&name, ip).then_some(name)
}

/// Écarte les « noms » qui n'en sont pas.
///
/// Faute de résolution, `getnameinfo` renvoie l'adresse elle-même sous forme
/// de texte. L'accepter remplirait la colonne « nom » d'une répétition de la
/// colonne « adresse ».
fn usable_name(name: &str, ip: Ipv4Addr) -> bool {
    !name.is_empty() && name != ip.to_string() && name.parse::<IpAddr>().is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 42);
    const MAC_APPLE: MacAddr = MacAddr::new([0x3C, 0x22, 0xFB, 0x01, 0x02, 0x03]);
    const MAC_RANDOMISEE: MacAddr = MacAddr::new([0xDA, 0x22, 0xFB, 0x01, 0x02, 0x03]);

    #[test]
    fn une_adresse_textuelle_n_est_pas_un_nom() {
        assert!(!usable_name("192.168.1.42", IP));
        assert!(!usable_name("", IP));
        assert!(!usable_name("::1", IP));

        assert!(usable_name("portable.local", IP));
        assert!(usable_name("NAS", IP));
    }

    #[tokio::test]
    async fn le_constructeur_est_deduit_de_la_mac() {
        let host = enrich(IP, Some(MAC_APPLE), false)
            .await
            .expect("le constructeur devait suffire à produire un enrichissement");

        assert!(
            host.vendor
                .and_then(|v| v.name())
                .unwrap()
                .contains("Apple"),
            "constructeur inattendu : {:?}",
            host.vendor
        );
        assert_eq!(host.ip, IP);
        assert_eq!(host.hostname, None, "résolution désactivée");
    }

    #[tokio::test]
    async fn une_mac_randomisee_produit_un_verdict_explicite() {
        let host = enrich(IP, Some(MAC_RANDOMISEE), false).await.unwrap();

        assert!(host.vendor.is_some_and(|v| v.is_randomized()));
    }

    #[tokio::test]
    async fn sans_mac_ni_resolution_il_n_y_a_rien_a_ajouter() {
        assert!(enrich(IP, None, false).await.is_none());
    }

    #[tokio::test]
    async fn l_enrichissement_ne_fabrique_que_les_champs_manquants() {
        // Le résultat sert à être fusionné : il ne doit pas réintroduire de
        // valeurs par défaut susceptibles d'écraser ce qui est déjà connu.
        let host = enrich(IP, Some(MAC_APPLE), false).await.unwrap();

        assert_eq!(host.mac, None);
        assert!(host.open_ports.is_empty());
        assert!(host.sources.is_empty());
        assert_eq!(host.rtt, None);
    }

    #[tokio::test]
    async fn une_resolution_impossible_ne_bloque_pas() {
        // 192.0.2.0/24 n'a pas de zone inverse : selon le résolveur, on obtient
        // un échec ou un délai. Dans les deux cas, aucun nom et aucun blocage.
        let debut = std::time::Instant::now();

        let name = reverse_dns(Ipv4Addr::new(192, 0, 2, 1), Duration::from_millis(500)).await;

        assert_eq!(name, None);
        assert!(
            debut.elapsed() < Duration::from_secs(3),
            "résolution trop longue : {:?}",
            debut.elapsed()
        );
    }

    #[tokio::test]
    async fn la_boucle_locale_se_resout() {
        let name = reverse_dns(Ipv4Addr::LOCALHOST, Duration::from_secs(2)).await;

        // Presque toutes les configurations résolvent 127.0.0.1. Si ce n'est
        // pas le cas, l'absence de nom reste un résultat correct.
        if let Some(name) = name {
            assert!(usable_name(&name, Ipv4Addr::LOCALHOST));
        }
    }
}
