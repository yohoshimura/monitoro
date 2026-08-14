//! Sonde ARP via l'API IP Helper de Windows.
//!
//! C'est le cœur de Monitoro. `SendARP` résout une adresse IPv4 en adresse
//! matérielle **sans aucun privilège** et sans pilote de capture : la fonction
//! demande à la pile du système d'émettre la requête ARP à notre place.
//!
//! Son avantage sur une sonde TCP est décisif. Un appareil qui n'expose aucun
//! service — téléphone, objet connecté, imprimante en veille — reste invisible
//! à un balayage de ports, mais **doit** répondre à ARP pour communiquer sur le
//! lien. Et la réponse apporte l'adresse MAC, donc le constructeur.
//!
//! Deux limites inhérentes : IPv4 uniquement, et le sous-réseau local
//! uniquement. ARP ne franchit pas les routeurs — ce qui correspond
//! exactement au périmètre de l'outil.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use windows::Win32::NetworkManagement::IpHelper::SendARP;

use super::{Probe, ProbeOutcome};
use crate::inventory::MacAddr;

/// Délai au-delà duquel on cesse d'attendre une résolution.
///
/// `SendARP` ne prend aucun paramètre de délai : Windows applique le sien,
/// de l'ordre de la seconde pour une adresse inoccupée.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1_500);

pub struct ArpProbe {
    timeout: Duration,
}

impl ArpProbe {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for ArpProbe {
    fn default() -> Self {
        Self::new(DEFAULT_TIMEOUT)
    }
}

#[async_trait]
impl Probe for ArpProbe {
    fn name(&self) -> &'static str {
        "arp"
    }

    async fn probe(&self, target: Ipv4Addr) -> ProbeOutcome {
        let started = Instant::now();

        // `SendARP` est synchrone et peut bloquer près d'une seconde sur une
        // adresse inoccupée. L'appeler directement sur le runtime figerait
        // l'exécuteur — et donc l'affichage.
        let resolution = tokio::task::spawn_blocking(move || send_arp(target));

        // Filet de sécurité : si l'appel ne rendait jamais la main, le fil
        // bloqué survivrait à ce délai, mais le balayage, lui, continuerait.
        match tokio::time::timeout(self.timeout, resolution).await {
            Ok(Ok(Some(mac))) => ProbeOutcome::alive()
                .with_mac(mac)
                .with_rtt(started.elapsed()),
            Ok(Ok(None)) => ProbeOutcome::unknown(),
            Ok(Err(_join_error)) => ProbeOutcome::unknown(),
            Err(_elapsed) => ProbeOutcome::unknown(),
        }
    }
}

/// Résout une adresse IPv4 en adresse MAC. `None` si personne ne répond.
fn send_arp(target: Ipv4Addr) -> Option<MacAddr> {
    // La documentation Win32 exige un tampon aligné sur ULONG : d'où `[u32; 2]`
    // plutôt qu'un `[u8; 6]`, qui n'offrirait aucune garantie d'alignement.
    let mut buffer = [0u32; 2];
    let mut length: u32 = 6;

    // `IPAddr` attend les quatre octets dans l'ordre du réseau, empaquetés dans
    // un u32. `from_ne_bytes` reproduit exactement la disposition mémoire
    // voulue ; `from_be_bytes` ou un `as u32` inverseraient les octets et
    // interrogeraient une tout autre adresse.
    let destination = u32::from_ne_bytes(target.octets());

    // `srcip` à zéro laisse la pile choisir l'interface d'émission.
    let status = unsafe { SendARP(destination, 0, buffer.as_mut_ptr().cast(), &raw mut length) };

    const NO_ERROR: u32 = 0;
    if status != NO_ERROR || length != 6 {
        return None;
    }

    let mut octets = [0u8; 8];
    octets[..4].copy_from_slice(&buffer[0].to_ne_bytes());
    octets[4..].copy_from_slice(&buffer[1].to_ne_bytes());

    let mac = MacAddr::new([
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
    ]);

    // Certaines configurations renvoient un succès avec une adresse nulle ou
    // de diffusion groupée. Ce ne sont pas des machines.
    (!mac.is_zero() && !mac.is_multicast()).then_some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_nom_de_la_sonde_sert_d_identifiant_de_source() {
        assert_eq!(ArpProbe::default().name(), "arp");
    }

    #[test]
    fn l_adresse_est_convertie_dans_l_ordre_du_reseau() {
        // Le piège classique de cette API. 192.168.1.10 doit produire les
        // octets C0 A8 01 0A dans cet ordre en mémoire.
        let destination = u32::from_ne_bytes(Ipv4Addr::new(192, 168, 1, 10).octets());

        assert_eq!(destination.to_ne_bytes(), [0xC0, 0xA8, 0x01, 0x0A]);
    }

    #[tokio::test]
    async fn une_adresse_hors_du_lien_local_ne_resout_pas() {
        // ARP ne franchit pas les routeurs : une adresse publique ne peut pas
        // être résolue, quelle que soit la machine qui exécute ce test.
        let outcome = ArpProbe::new(Duration::from_millis(800))
            .probe(Ipv4Addr::new(8, 8, 8, 8))
            .await;

        assert!(!outcome.is_alive(), "résultat inattendu : {outcome:?}");
        assert_eq!(outcome.mac, None);
    }

    #[tokio::test]
    async fn la_sonde_rend_la_main_meme_sur_une_adresse_muette() {
        // Vérifie que le délai est bien appliqué : sans `spawn_blocking`, une
        // adresse inoccupée gèlerait l'exécuteur.
        let debut = Instant::now();

        let outcome = ArpProbe::new(Duration::from_millis(400))
            .probe(Ipv4Addr::new(192, 0, 2, 1))
            .await;

        assert!(!outcome.is_alive());
        assert!(
            debut.elapsed() < Duration::from_secs(3),
            "la sonde a mis {:?} à rendre la main",
            debut.elapsed()
        );
    }

    /// Nécessite un vrai réseau local : exécuté à la demande.
    #[tokio::test]
    #[ignore = "dépend du réseau : `cargo test -- --ignored arp_resout`"]
    async fn arp_resout_la_passerelle() {
        let local = crate::net::local::detect().expect("réseau local détecté");
        let passerelle = local
            .network
            .hosts()
            .next()
            .expect("le réseau contient au moins une adresse");

        let outcome = ArpProbe::default().probe(passerelle).await;

        assert!(
            outcome.is_alive() && outcome.mac.is_some(),
            "aucune réponse ARP de {passerelle} : {outcome:?}"
        );
    }
}
