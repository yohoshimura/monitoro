//! Sonde par connexion TCP.
//!
//! Portable et sans privilèges : c'est le plus petit dénominateur commun de la
//! découverte. Son intérêt dépasse le simple relevé de ports ouverts, grâce à
//! une propriété qu'on oublie souvent : **un refus de connexion prouve que
//! l'hôte est vivant**. Une machine sans aucun service ouvert répond `RST` sur
//! chaque port, ce qui la rend parfaitement détectable. Seul le silence est
//! ambigu.

use std::io;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::{Liveness, Probe, ProbeOutcome};

/// Ports interrogés par défaut : un compromis entre couverture et durée.
///
/// On y trouve le web (80/443/8080), l'administration à distance (22/3389) et
/// le partage de fichiers Windows (445), qui couvrent l'essentiel de ce qui
/// écoute sur un réseau domestique ou de bureau.
pub const DEFAULT_PORTS: &[u16] = &[80, 443, 22, 445, 3389, 8080];

pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(600);

/// Ce qu'une tentative sur un port unique nous apprend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortOutcome {
    /// Connexion établie : le port écoute.
    Open(Duration),
    /// `RST` reçu : le port est fermé, mais l'hôte existe.
    Refused(Duration),
    /// Le réseau a signalé l'hôte comme injoignable.
    Unreachable,
    /// Aucune réponse avant expiration du délai.
    Silent,
}

pub struct TcpProbe {
    ports: Vec<u16>,
    timeout: Duration,
}

impl TcpProbe {
    pub fn new(ports: Vec<u16>, timeout: Duration) -> Self {
        Self { ports, timeout }
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }
}

impl Default for TcpProbe {
    fn default() -> Self {
        Self::new(DEFAULT_PORTS.to_vec(), DEFAULT_TIMEOUT)
    }
}

#[async_trait]
impl Probe for TcpProbe {
    fn name(&self) -> &'static str {
        "tcp"
    }

    async fn probe(&self, target: Ipv4Addr) -> ProbeOutcome {
        if self.ports.is_empty() {
            return ProbeOutcome::unknown();
        }

        // Les ports sont interrogés en parallèle : les tenter l'un après
        // l'autre coûterait `ports × délai` sur chaque hôte absent, ce qui
        // domine complètement la durée d'un balayage.
        let mut attempts = JoinSet::new();
        for &port in &self.ports {
            let limit = self.timeout;
            attempts.spawn(async move { (port, connect(target, port, limit).await) });
        }

        let mut open_ports = Vec::new();
        let mut best_rtt: Option<Duration> = None;
        let mut alive = false;
        let mut unreachable = false;

        while let Some(joined) = attempts.join_next().await {
            // Une tâche qui panique ne doit pas faire disparaître l'hôte : on
            // ignore le résultat et on continue avec les autres ports.
            let Ok((port, outcome)) = joined else {
                continue;
            };

            match outcome {
                PortOutcome::Open(rtt) => {
                    open_ports.push(port);
                    alive = true;
                    best_rtt = min_option(best_rtt, rtt);
                }
                PortOutcome::Refused(rtt) => {
                    alive = true;
                    best_rtt = min_option(best_rtt, rtt);
                }
                PortOutcome::Unreachable => unreachable = true,
                PortOutcome::Silent => {}
            }
        }

        open_ports.sort_unstable();

        let liveness = match (alive, unreachable) {
            (true, _) => Liveness::Alive,
            (false, true) => Liveness::Unreachable,
            (false, false) => Liveness::Unknown,
        };

        let mut outcome = ProbeOutcome::new(liveness).with_ports(open_ports);
        outcome.rtt = best_rtt;
        outcome
    }
}

async fn connect(target: Ipv4Addr, port: u16, limit: Duration) -> PortOutcome {
    let started = Instant::now();

    match timeout(limit, TcpStream::connect((target, port))).await {
        Ok(Ok(_stream)) => PortOutcome::Open(started.elapsed()),
        Ok(Err(error)) => classify(&error, started.elapsed()),
        // Le délai a expiré : port filtré, ou hôte absent. Indiscernable.
        Err(_elapsed) => PortOutcome::Silent,
    }
}

fn classify(error: &io::Error, elapsed: Duration) -> PortOutcome {
    match error.kind() {
        // `RST` : quelqu'un est là pour refuser.
        io::ErrorKind::ConnectionRefused => PortOutcome::Refused(elapsed),
        io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
            PortOutcome::Unreachable
        }
        _ => PortOutcome::Silent,
    }
}

fn min_option(current: Option<Duration>, candidate: Duration) -> Option<Duration> {
    Some(match current {
        Some(existing) => existing.min(candidate),
        None => candidate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::net::TcpListener;

    const LOCALHOST: Ipv4Addr = Ipv4Addr::LOCALHOST;

    /// Ouvre un port d'écoute éphémère et renvoie son numéro.
    async fn listening_port() -> (TcpListener, u16) {
        let listener = TcpListener::bind((LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    /// Un port de la plage éphémère que personne n'écoute.
    ///
    /// On réserve puis on libère : rien ne garantit formellement que le port
    /// reste libre, mais sur la boucle locale la fenêtre est négligeable.
    async fn closed_port() -> u16 {
        let (listener, port) = listening_port().await;
        drop(listener);
        port
    }

    #[tokio::test]
    async fn un_port_ouvert_est_detecte() {
        let (_listener, port) = listening_port().await;
        let probe = TcpProbe::new(vec![port], DEFAULT_TIMEOUT);

        let outcome = probe.probe(LOCALHOST).await;

        assert_eq!(outcome.liveness, Liveness::Alive);
        assert_eq!(outcome.open_ports, vec![port]);
        assert!(outcome.rtt.is_some(), "un temps de réponse était attendu");
    }

    #[tokio::test]
    #[ignore = "dépend d'un pare-feu qui renvoie RST plutôt que d'ignorer le paquet"]
    async fn un_port_ferme_prouve_quand_meme_que_l_hote_existe() {
        // Le cœur de cette sonde : un `RST` est une preuve de vie.
        //
        // Ce test valide un comportement du système, pas du code : bien des
        // configurations de pare-feu ignorent silencieusement les paquets au
        // lieu de les refuser, y compris sur la boucle locale. On obtient
        // alors `Unknown`, ce qui est le résultat correct.
        // La logique de classification elle-même est couverte sans réseau par
        // `seul_un_refus_de_connexion_vaut_preuve_de_vie`.
        let port = closed_port().await;
        let probe = TcpProbe::new(vec![port], DEFAULT_TIMEOUT);

        let outcome = probe.probe(LOCALHOST).await;

        assert_eq!(
            outcome.liveness,
            Liveness::Alive,
            "un refus de connexion doit compter comme une preuve de vie"
        );
        assert!(
            outcome.open_ports.is_empty(),
            "aucun port ne devrait être signalé ouvert"
        );
    }

    #[tokio::test]
    async fn les_ports_ouverts_sont_rapportes_tries() {
        let (_a, port_a) = listening_port().await;
        let (_b, port_b) = listening_port().await;
        let ferme = closed_port().await;

        let probe = TcpProbe::new(vec![port_a, ferme, port_b], DEFAULT_TIMEOUT);
        let outcome = probe.probe(LOCALHOST).await;

        let mut attendus = vec![port_a, port_b];
        attendus.sort_unstable();
        assert_eq!(outcome.open_ports, attendus);
    }

    #[tokio::test]
    async fn une_adresse_muette_ne_passe_pas_pour_vivante() {
        // 192.0.2.0/24 est réservé à la documentation (RFC 5737) : aucun hôte
        // réel n'y répond. Selon la configuration réseau on obtient un silence
        // ou un « injoignable » — jamais une preuve de vie.
        //
        // On évite délibérément 80 et 443 : les proxys transparents, très
        // répandus, acceptent la connexion à la place de la destination et
        // feraient passer n'importe quelle adresse pour vivante.
        let probe = TcpProbe::new(vec![12345], Duration::from_millis(300));

        let outcome = probe.probe(Ipv4Addr::new(192, 0, 2, 1)).await;

        assert!(
            !outcome.is_alive(),
            "une adresse de documentation ne devrait pas répondre : {outcome:?}"
        );
        assert!(outcome.open_ports.is_empty());
    }

    #[tokio::test]
    async fn une_liste_de_ports_vide_ne_conclut_rien() {
        let probe = TcpProbe::new(Vec::new(), DEFAULT_TIMEOUT);

        assert_eq!(probe.probe(LOCALHOST).await.liveness, Liveness::Unknown);
    }

    #[test]
    fn le_nom_de_la_sonde_sert_d_identifiant_de_source() {
        assert_eq!(TcpProbe::default().name(), "tcp");
    }

    #[test]
    fn le_temps_de_reponse_retenu_est_le_plus_court() {
        let court = Duration::from_millis(5);
        let long = Duration::from_millis(80);

        assert_eq!(min_option(None, long), Some(long));
        assert_eq!(min_option(Some(long), court), Some(court));
        assert_eq!(min_option(Some(court), long), Some(court));
    }

    #[test]
    fn seul_un_refus_de_connexion_vaut_preuve_de_vie() {
        let elapsed = Duration::from_millis(3);

        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::ConnectionRefused), elapsed),
            PortOutcome::Refused(elapsed)
        );
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::HostUnreachable), elapsed),
            PortOutcome::Unreachable
        );
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::PermissionDenied), elapsed),
            PortOutcome::Silent
        );
    }
}
