//! Orchestration : appliquer les sondes à toutes les cibles, sans saturer le
//! réseau ni bloquer l'affichage.

pub mod enrich;
pub mod event;

pub use event::ScanEvent;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::inventory::{Host, Inventory};
use crate::net::TargetSet;
use crate::probe::Probe;

/// Nombre d'adresses sondées simultanément par défaut.
///
/// Assez pour qu'un /24 se balaye en quelques secondes, assez peu pour ne pas
/// inonder le réseau ni déclencher les protections anti-rafale des
/// équipements.
pub const DEFAULT_CONCURRENCY: usize = 64;

/// Capacité du canal d'événements.
///
/// Le moteur ralentit tout seul si le consommateur prend du retard : la TUI ne
/// peut donc pas se faire distancer au point d'afficher des données périmées.
const EVENT_BUFFER: usize = 256;

pub struct Scanner {
    probes: Vec<Arc<dyn Probe>>,
    concurrency: usize,
    resolve_names: bool,
}

/// Bilan d'un balayage terminé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSummary {
    pub total: u64,
    pub alive: usize,
    pub elapsed: Duration,
    pub warnings: Vec<String>,
}

impl Scanner {
    pub fn new(probes: Vec<Arc<dyn Probe>>, concurrency: usize) -> Self {
        Self {
            probes,
            concurrency: concurrency.max(1),
            resolve_names: true,
        }
    }

    /// Active ou coupe la résolution inverse des noms.
    ///
    /// La couper accélère nettement le balayage d'un réseau dont le résolveur
    /// est lent ou absent.
    pub fn resolve_names(mut self, enabled: bool) -> Self {
        self.resolve_names = enabled;
        self
    }

    /// Lance le balayage et retourne le flux d'événements.
    ///
    /// Le travail démarre immédiatement en tâche de fond. Abandonner le
    /// récepteur interrompt proprement le scan.
    pub fn run(self, targets: TargetSet) -> mpsc::Receiver<ScanEvent> {
        let (tx, rx) = mpsc::channel(EVENT_BUFFER);
        tokio::spawn(self.drive(targets, tx));
        rx
    }

    async fn drive(self, targets: TargetSet, tx: mpsc::Sender<ScanEvent>) {
        let started = Instant::now();
        let total = targets.len();

        if tx.send(ScanEvent::Started { total }).await.is_err() {
            return;
        }

        let resolve_names = self.resolve_names;
        let semaphore = Arc::new(Semaphore::new(self.concurrency));
        let probes = Arc::new(self.probes);
        let mut tasks = JoinSet::new();
        let mut enrichments = JoinSet::new();
        let mut progress = Progress { done: 0, total };
        let mut alive = 0usize;

        for ip in targets.iter() {
            // Acquérir le jeton *avant* de créer la tâche borne le nombre de
            // sondes en vol, mais aussi la mémoire : sans cela, un /16
            // matérialiserait 65 000 tâches d'un coup.
            let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                break;
            };

            // Un jeton vient de se libérer : au moins une tâche est terminée.
            // On la récolte tout de suite pour que l'avancement continue de
            // s'afficher pendant que le reste tourne.
            while let Some(joined) = tasks.try_join_next() {
                if !report(
                    &tx,
                    joined,
                    &mut progress,
                    &mut alive,
                    &mut enrichments,
                    resolve_names,
                )
                .await
                {
                    return;
                }
            }
            while let Some(joined) = enrichments.try_join_next() {
                if !report_enrichment(&tx, joined).await {
                    return;
                }
            }

            let probes = Arc::clone(&probes);
            tasks.spawn(async move {
                let _permit = permit;
                probe_all(&probes, ip).await
            });
        }

        while let Some(joined) = tasks.join_next().await {
            if !report(
                &tx,
                joined,
                &mut progress,
                &mut alive,
                &mut enrichments,
                resolve_names,
            )
            .await
            {
                return;
            }
        }

        // Le balayage est fini, mais des enrichissements peuvent encore
        // tourner : les abandonner ferait disparaître des noms déjà résolus.
        while let Some(joined) = enrichments.join_next().await {
            if !report_enrichment(&tx, joined).await {
                return;
            }
        }

        let _ = tx
            .send(ScanEvent::Finished {
                elapsed: started.elapsed(),
                alive,
            })
            .await;
    }
}

struct Progress {
    done: u64,
    total: u64,
}

/// Traduit le résultat d'une tâche en événements.
///
/// Retourne `false` si le consommateur a disparu, auquel cas le scan s'arrête.
async fn report(
    tx: &mpsc::Sender<ScanEvent>,
    joined: Result<Option<Host>, tokio::task::JoinError>,
    progress: &mut Progress,
    alive: &mut usize,
    enrichments: &mut JoinSet<Option<Host>>,
    resolve_names: bool,
) -> bool {
    match joined {
        Ok(Some(host)) => {
            *alive += 1;
            let (ip, mac) = (host.ip, host.mac);

            if tx.send(ScanEvent::HostFound(host)).await.is_err() {
                return false;
            }

            // L'hôte est déjà affichable ; son nom et son constructeur
            // arriveront par un événement séparé.
            enrichments.spawn(enrich::enrich(ip, mac, resolve_names));
        }
        Ok(None) => {}
        // Une sonde qui panique fait perdre un hôte, jamais le balayage. On
        // compte quand même l'adresse comme traitée, sans quoi l'avancement
        // n'atteindrait jamais son total.
        Err(error) => {
            let message = format!("une sonde a échoué et son résultat est perdu : {error}");
            if tx.send(ScanEvent::Warning(message)).await.is_err() {
                return false;
            }
        }
    }

    progress.done += 1;
    tx.send(ScanEvent::Progress {
        done: progress.done,
        total: progress.total,
    })
    .await
    .is_ok()
}

/// Publie le résultat d'un enrichissement.
///
/// Un échec est sans conséquence : l'hôte reste affiché tel qu'il a été
/// découvert, simplement sans nom ni constructeur.
async fn report_enrichment(
    tx: &mpsc::Sender<ScanEvent>,
    joined: Result<Option<Host>, tokio::task::JoinError>,
) -> bool {
    match joined {
        Ok(Some(host)) => tx.send(ScanEvent::HostUpdated(host)).await.is_ok(),
        Ok(None) | Err(_) => true,
    }
}

/// Applique toutes les sondes à une adresse et fusionne ce qu'elles trouvent.
///
/// Retourne `None` si aucune n'a pu établir que l'hôte existe.
async fn probe_all(probes: &[Arc<dyn Probe>], ip: Ipv4Addr) -> Option<Host> {
    let mut host = Host::new(ip);
    let mut found = false;

    // Séquentiel et non parallèle : les sondes se complètent plus qu'elles ne
    // se concurrencent, et la parallélisation utile se joue entre adresses.
    for probe in probes {
        let outcome = probe.probe(ip).await;
        if !outcome.is_alive() {
            continue;
        }

        found = true;
        host.merge_from(Host {
            mac: outcome.mac,
            open_ports: outcome.open_ports,
            rtt: outcome.rtt,
            sources: vec![probe.name()],
            ..Host::new(ip)
        });
    }

    found.then_some(host)
}

/// Consomme tout le flux d'événements et en fait un inventaire.
///
/// C'est le chemin non interactif : la sortie JSON n'a rien à afficher au fil
/// de l'eau, elle attend simplement le résultat complet.
pub async fn drain(mut events: mpsc::Receiver<ScanEvent>) -> (Inventory, ScanSummary) {
    let mut inventory = Inventory::new();
    let mut summary = ScanSummary {
        total: 0,
        alive: 0,
        elapsed: Duration::ZERO,
        warnings: Vec::new(),
    };

    while let Some(event) = events.recv().await {
        match event {
            ScanEvent::Started { total } => summary.total = total,
            ScanEvent::HostFound(host) | ScanEvent::HostUpdated(host) => {
                inventory.upsert(host);
            }
            ScanEvent::Warning(message) => summary.warnings.push(message),
            ScanEvent::Finished { elapsed, alive } => {
                summary.elapsed = elapsed;
                summary.alive = alive;
            }
            ScanEvent::Progress { .. } => {}
        }
    }

    (inventory, summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;

    use crate::inventory::MacAddr;
    use crate::probe::ProbeOutcome;

    /// Sonde scriptée : aucun réseau, comportement entièrement déterminé par
    /// le test.
    struct FakeProbe {
        name: &'static str,
        alive: HashSet<Ipv4Addr>,
        panic_on: Option<Ipv4Addr>,
        delay: Duration,
        in_flight: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    impl FakeProbe {
        fn new(name: &'static str, alive: impl IntoIterator<Item = Ipv4Addr>) -> Self {
            Self {
                name,
                alive: alive.into_iter().collect(),
                panic_on: None,
                delay: Duration::ZERO,
                in_flight: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl Probe for FakeProbe {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn probe(&self, target: Ipv4Addr) -> ProbeOutcome {
            let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(current, Ordering::SeqCst);

            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }

            if self.panic_on == Some(target) {
                panic!("panique volontaire sur {target}");
            }

            self.in_flight.fetch_sub(1, Ordering::SeqCst);

            if self.alive.contains(&target) {
                ProbeOutcome::alive()
                    .with_ports(vec![80])
                    .with_rtt(Duration::from_millis(3))
            } else {
                ProbeOutcome::unknown()
            }
        }
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, last)
    }

    /// Les tests du moteur ne doivent dépendre d'aucun résolveur : la
    /// résolution inverse est systématiquement coupée.
    fn build_scanner(probes: Vec<Arc<dyn Probe>>, concurrency: usize) -> Scanner {
        Scanner::new(probes, concurrency).resolve_names(false)
    }

    async fn collect_events(scanner: Scanner, cidr: &str) -> Vec<ScanEvent> {
        let targets = TargetSet::parse(cidr, false).unwrap();
        let mut events = scanner.run(targets);

        let mut collected = Vec::new();
        while let Some(event) = events.recv().await {
            collected.push(event);
        }
        collected
    }

    #[tokio::test]
    async fn seuls_les_hotes_repondants_sont_signales() {
        let probe = FakeProbe::new("fake", [ip(1), ip(7)]);
        let scanner = build_scanner(vec![Arc::new(probe)], 8);

        let events = collect_events(scanner, "192.168.1.0/28").await;

        let trouves: Vec<Ipv4Addr> = events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::HostFound(host) => Some(host.ip),
                _ => None,
            })
            .collect();

        assert_eq!(trouves, vec![ip(1), ip(7)]);
    }

    #[tokio::test]
    async fn le_balayage_s_annonce_et_se_conclut() {
        let scanner = build_scanner(vec![Arc::new(FakeProbe::new("fake", [ip(1)]))], 4);
        let events = collect_events(scanner, "192.168.1.0/28").await;

        assert!(
            matches!(events.first(), Some(ScanEvent::Started { total: 14 })),
            "premier événement inattendu : {:?}",
            events.first()
        );
        assert!(
            matches!(events.last(), Some(ScanEvent::Finished { alive: 1, .. })),
            "dernier événement inattendu : {:?}",
            events.last()
        );
    }

    #[tokio::test]
    async fn l_avancement_est_croissant_et_atteint_le_total() {
        let scanner = build_scanner(vec![Arc::new(FakeProbe::new("fake", [ip(3)]))], 4);
        let events = collect_events(scanner, "192.168.1.0/28").await;

        let avancement: Vec<(u64, u64)> = events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Progress { done, total } => Some((*done, *total)),
                _ => None,
            })
            .collect();

        assert_eq!(avancement.len(), 14, "une étape par adresse sondée");
        assert!(
            avancement.windows(2).all(|w| w[0].0 + 1 == w[1].0),
            "l'avancement doit progresser d'une unité à la fois : {avancement:?}"
        );
        assert_eq!(avancement.last(), Some(&(14, 14)));
    }

    #[tokio::test]
    async fn la_concurrence_ne_depasse_jamais_la_limite() {
        const LIMITE: usize = 5;

        let probe = FakeProbe {
            delay: Duration::from_millis(20),
            ..FakeProbe::new("fake", [])
        };
        let peak = Arc::clone(&probe.peak);

        let scanner = build_scanner(vec![Arc::new(probe)], LIMITE);
        collect_events(scanner, "192.168.1.0/26").await;

        let observe = peak.load(Ordering::SeqCst);
        assert!(observe > 1, "le test n'a pas réellement mis en concurrence");
        assert!(
            observe <= LIMITE,
            "{observe} sondes simultanées pour une limite de {LIMITE}"
        );
    }

    #[tokio::test]
    async fn une_sonde_qui_panique_n_interrompt_pas_le_balayage() {
        let probe = FakeProbe {
            panic_on: Some(ip(5)),
            ..FakeProbe::new("fake", [ip(2), ip(9)])
        };
        let scanner = build_scanner(vec![Arc::new(probe)], 4);

        let events = collect_events(scanner, "192.168.1.0/28").await;

        let trouves = events
            .iter()
            .filter(|e| matches!(e, ScanEvent::HostFound(_)))
            .count();
        let alertes = events
            .iter()
            .filter(|e| matches!(e, ScanEvent::Warning(_)))
            .count();

        assert_eq!(trouves, 2, "les autres hôtes devaient être trouvés");
        assert_eq!(alertes, 1, "la panique devait produire un avertissement");
        assert!(
            matches!(events.last(), Some(ScanEvent::Finished { .. })),
            "le balayage devait se conclure normalement"
        );

        // L'adresse perdue est tout de même comptée : sans cela, la barre de
        // progression n'atteindrait jamais 100 %.
        let dernier = events.iter().rev().find_map(|e| match e {
            ScanEvent::Progress { done, total } => Some((*done, *total)),
            _ => None,
        });
        assert_eq!(dernier, Some((14, 14)));
    }

    #[tokio::test]
    async fn plusieurs_sondes_voient_leurs_resultats_fusionnes() {
        let arp = FakeProbeAvecMac {
            inner: FakeProbe::new("arp", [ip(4)]),
        };
        let tcp = FakeProbe::new("tcp", [ip(4)]);

        let scanner = build_scanner(vec![Arc::new(arp), Arc::new(tcp)], 4);
        let events = collect_events(scanner, "192.168.1.0/28").await;

        let host = events
            .iter()
            .find_map(|e| match e {
                ScanEvent::HostFound(host) => Some(host),
                _ => None,
            })
            .expect("un hôte devait être trouvé");

        assert_eq!(host.mac, Some(MacAddr::new([1, 2, 3, 4, 5, 6])));
        assert_eq!(host.open_ports, vec![80]);
        assert_eq!(host.sources, vec!["arp", "tcp"]);
    }

    struct FakeProbeAvecMac {
        inner: FakeProbe,
    }

    #[async_trait]
    impl Probe for FakeProbeAvecMac {
        fn name(&self) -> &'static str {
            self.inner.name()
        }

        async fn probe(&self, target: Ipv4Addr) -> ProbeOutcome {
            let outcome = self.inner.probe(target).await;
            if outcome.is_alive() {
                ProbeOutcome::alive().with_mac(MacAddr::new([1, 2, 3, 4, 5, 6]))
            } else {
                outcome
            }
        }
    }

    #[tokio::test]
    async fn le_constructeur_arrive_par_un_evenement_de_mise_a_jour() {
        // La MAC est fournie par la sonde ; le constructeur, lui, provient de
        // l'étage d'enrichissement et arrive donc séparément.
        let arp = FakeProbeAvecMac {
            inner: FakeProbe::new("arp", [ip(4)]),
        };
        let scanner = build_scanner(vec![Arc::new(arp)], 4);

        let events = collect_events(scanner, "192.168.1.0/28").await;

        let complete = events
            .iter()
            .find_map(|e| match e {
                ScanEvent::HostUpdated(host) => Some(host),
                _ => None,
            })
            .expect("aucun enrichissement publié");

        assert_eq!(complete.ip, ip(4));
        assert!(
            complete.vendor.is_some(),
            "l'enrichissement devait résoudre un constructeur"
        );
    }

    #[tokio::test]
    async fn sans_mac_aucun_enrichissement_n_est_publie() {
        let scanner = build_scanner(vec![Arc::new(FakeProbe::new("tcp", [ip(4)]))], 4);

        let events = collect_events(scanner, "192.168.1.0/28").await;

        assert!(
            !events
                .iter()
                .any(|e| matches!(e, ScanEvent::HostUpdated(_))),
            "rien à enrichir sans MAC ni résolution de nom"
        );
    }

    #[tokio::test]
    async fn l_inventaire_final_combine_decouverte_et_enrichissement() {
        let arp = FakeProbeAvecMac {
            inner: FakeProbe::new("arp", [ip(4)]),
        };
        let targets = TargetSet::parse("192.168.1.0/28", false).unwrap();
        let scanner = build_scanner(vec![Arc::new(arp)], 4);

        let (inventory, _) = drain(scanner.run(targets)).await;
        let host = inventory.get(ip(4)).expect("hôte absent de l'inventaire");

        assert!(host.mac.is_some(), "la MAC vient de la sonde");
        assert!(
            host.vendor.is_some(),
            "le constructeur vient de l'enrichissement"
        );
    }

    #[tokio::test]
    async fn le_drainage_produit_un_inventaire_et_un_bilan() {
        let scanner = build_scanner(vec![Arc::new(FakeProbe::new("fake", [ip(1), ip(2)]))], 4);
        let targets = TargetSet::parse("192.168.1.0/28", false).unwrap();

        let (inventory, summary) = drain(scanner.run(targets)).await;

        assert_eq!(inventory.len(), 2);
        assert_eq!(summary.total, 14);
        assert_eq!(summary.alive, 2);
        assert!(summary.warnings.is_empty());
    }

    #[tokio::test]
    async fn abandonner_le_recepteur_arrete_le_balayage() {
        let probe = FakeProbe {
            delay: Duration::from_millis(10),
            ..FakeProbe::new("fake", [])
        };
        let in_flight = Arc::clone(&probe.in_flight);

        let scanner = build_scanner(vec![Arc::new(probe)], 2);
        let targets = TargetSet::parse("10.0.0.0/16", true).unwrap();

        drop(scanner.run(targets));
        tokio::time::sleep(Duration::from_millis(120)).await;

        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            0,
            "plus aucune sonde ne devrait tourner après abandon du récepteur"
        );
    }
}
