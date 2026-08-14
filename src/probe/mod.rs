//! Les sondes : savoir si une adresse répond, et ce qu'on peut en apprendre.
//!
//! Toute technique de découverte se ramène au trait [`Probe`]. C'est la
//! couture qui permet trois choses : combiner plusieurs techniques dans un même
//! scan, tester le moteur sans réseau, et brancher plus tard des sondes
//! privilégiées (ICMP brut, ARP fabriqué) sans toucher à l'orchestration.

pub mod tcp;

#[cfg(windows)]
pub mod arp_win;

use std::net::Ipv4Addr;
use std::time::Duration;

use async_trait::async_trait;

use crate::inventory::MacAddr;

/// Ce qu'une sonde peut conclure sur l'existence d'un hôte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// L'hôte a répondu — d'une manière ou d'une autre.
    Alive,
    /// Le réseau a répondu à sa place que l'hôte est injoignable.
    Unreachable,
    /// Silence. Un hôte pare-feuté et un hôte absent se ressemblent : on ne
    /// prétend pas trancher.
    Unknown,
}

impl Liveness {
    pub fn is_alive(self) -> bool {
        matches!(self, Self::Alive)
    }
}

/// Le résultat d'une sonde sur une adresse.
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeOutcome {
    pub liveness: Liveness,
    pub mac: Option<MacAddr>,
    pub open_ports: Vec<u16>,
    pub rtt: Option<Duration>,
}

impl ProbeOutcome {
    pub fn new(liveness: Liveness) -> Self {
        Self {
            liveness,
            mac: None,
            open_ports: Vec::new(),
            rtt: None,
        }
    }

    pub fn alive() -> Self {
        Self::new(Liveness::Alive)
    }

    pub fn unreachable() -> Self {
        Self::new(Liveness::Unreachable)
    }

    pub fn unknown() -> Self {
        Self::new(Liveness::Unknown)
    }

    pub fn with_mac(mut self, mac: MacAddr) -> Self {
        self.mac = Some(mac);
        self
    }

    pub fn with_rtt(mut self, rtt: Duration) -> Self {
        self.rtt = Some(rtt);
        self
    }

    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.open_ports = ports;
        self
    }

    pub fn is_alive(&self) -> bool {
        self.liveness.is_alive()
    }
}

/// Une technique de découverte.
///
/// `async_trait` est nécessaire ici : le moteur détient un
/// `Vec<Box<dyn Probe>>` dont le contenu est choisi à l'exécution, et les
/// méthodes asynchrones natives ne sont pas encore utilisables derrière `dyn`.
#[async_trait]
pub trait Probe: Send + Sync {
    /// Identifiant court, repris tel quel dans `Host::sources`.
    fn name(&self) -> &'static str;

    /// Interroge une adresse. Ne doit jamais échouer : une erreur réseau est
    /// une information (`Unreachable`/`Unknown`), pas une raison d'interrompre
    /// le scan.
    async fn probe(&self, target: Ipv4Addr) -> ProbeOutcome;
}
