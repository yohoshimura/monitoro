use std::io::{IsTerminal, stdout};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use monitoro::net::{TargetSet, local};
use monitoro::probe::{Probe, tcp::TcpProbe};
use monitoro::scan::{DEFAULT_CONCURRENCY, Scanner, drain};
use monitoro::ui::{AppState, json::ScanReport, plain, tui};

/// Découverte et inventaire du réseau local.
#[derive(Debug, Parser)]
#[command(name = "monitoro", version, about, long_about = None)]
struct Cli {
    /// Cible : CIDR (192.168.1.0/24) ou adresse unique (10.0.0.5).
    /// Par défaut, le sous-réseau de l'interface principale.
    target: Option<String>,

    /// Publie le résultat en JSON au lieu d'ouvrir l'interface.
    #[arg(long)]
    json: bool,

    /// Affiche un tableau texte au lieu d'ouvrir l'interface.
    #[arg(long, conflicts_with = "json")]
    plain: bool,

    /// Nombre d'adresses sondées simultanément.
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY, value_name = "N")]
    concurrency: usize,

    /// Délai d'attente par tentative de connexion TCP, en millisecondes.
    #[arg(long, default_value_t = 600, value_name = "MS")]
    timeout: u64,

    /// Ports TCP à interroger, séparés par des virgules.
    #[arg(long, value_delimiter = ',', value_name = "PORTS")]
    ports: Option<Vec<u16>>,

    /// N'utilise que la résolution ARP, sans interroger les ports.
    #[arg(long, conflicts_with = "ports")]
    no_tcp: bool,

    /// N'essaie pas de résoudre les noms des machines.
    #[arg(long)]
    no_resolve: bool,

    /// Confirme le balayage d'une plage plus large qu'un /16.
    #[arg(long)]
    yes: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Sortie redirigée : ouvrir une interface plein écran n'aurait aucun sens,
    // et produirait des séquences d'échappement dans le fichier de sortie.
    let interactive = !cli.json && !cli.plain && stdout().is_terminal();

    let (targets, interface) = resolve_targets(&cli, interactive)?;

    if !targets.is_private() {
        eprintln!(
            "attention : {targets} sort des plages privées. \
             Ne scannez que des réseaux dont vous avez la responsabilité."
        );
    }

    let scanner = Scanner::new(build_probes(&cli), cli.concurrency).resolve_names(!cli.no_resolve);
    let events = scanner.run(targets);

    if interactive {
        let state = AppState::new(targets.to_string(), interface);
        tui::run(state, events).await?;
        return Ok(());
    }

    let (inventory, summary) = drain(events).await;
    if cli.json {
        let report = ScanReport::new(targets.to_string(), &inventory, &summary);
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", plain::render(&inventory, &summary));
    }

    Ok(())
}

/// Détermine ce qu'il faut scanner, et sur quelle interface.
fn resolve_targets(cli: &Cli, interactive: bool) -> Result<(TargetSet, Option<String>)> {
    match &cli.target {
        Some(target) => {
            let targets = TargetSet::parse(target, cli.yes)
                .with_context(|| format!("cible « {target} » inutilisable"))?;
            Ok((targets, None))
        }
        None => {
            let local = local::detect().context(
                "impossible de déterminer le réseau local ; précisez une cible explicitement",
            )?;

            // En mode interactif, l'interface est affichée dans l'en-tête :
            // l'annoncer aussi sur la sortie d'erreur ferait doublon.
            if !interactive {
                eprintln!(
                    "interface « {} » ({}) : balayage de {}",
                    local.interface, local.address, local.network
                );
            }

            let targets = TargetSet::from_net(local.network, cli.yes)?;
            Ok((targets, Some(local.interface)))
        }
    }
}

/// Assemble les sondes à appliquer.
///
/// ARP en premier : c'est la seule qui détecte un appareil n'exposant aucun
/// service, et la seule qui rapporte une adresse matérielle.
fn build_probes(cli: &Cli) -> Vec<Arc<dyn Probe>> {
    let mut probes: Vec<Arc<dyn Probe>> = Vec::new();

    #[cfg(windows)]
    probes.push(Arc::new(monitoro::probe::arp_win::ArpProbe::default()));

    if !cli.no_tcp {
        probes.push(Arc::new(TcpProbe::new(
            cli.ports
                .clone()
                .unwrap_or_else(|| monitoro::probe::tcp::DEFAULT_PORTS.to_vec()),
            Duration::from_millis(cli.timeout),
        )));
    }

    probes
}
