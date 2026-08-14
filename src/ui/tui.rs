//! Boucle d'affichage interactive.
//!
//! Trois sources d'événements se rejoignent ici : le moteur de scan, le
//! clavier, et une horloge de rafraîchissement. Aucune ne doit pouvoir bloquer
//! les autres — d'où le `select!` plutôt qu'une lecture séquentielle.

use std::io;
use std::time::{Duration, Instant};

use ratatui::Terminal;
use ratatui::backend::Backend;
use ratatui::crossterm::event::{self, Event};
use tokio::sync::mpsc;

use super::app::AppState;
use super::render::render;
use crate::scan::ScanEvent;

/// Cadence de rafraîchissement.
///
/// Assez rapide pour que le chronomètre paraisse continu, assez lente pour ne
/// pas redessiner inutilement pendant qu'il ne se passe rien.
const TICK: Duration = Duration::from_millis(200);

/// Attente maximale d'une touche avant de rendre la main au fil de lecture.
///
/// Borne aussi le délai de sortie de ce fil une fois l'application terminée.
const INPUT_POLL: Duration = Duration::from_millis(100);

/// Prend le contrôle du terminal, affiche le scan, puis rend le terminal
/// intact.
pub async fn run(state: AppState, events: mpsc::Receiver<ScanEvent>) -> io::Result<AppState> {
    install_panic_hook();

    let mut terminal = ratatui::init();
    let outcome = event_loop(&mut terminal, state, events, spawn_input_reader()).await;

    // La restauration doit avoir lieu même si la boucle a échoué : un terminal
    // laissé en mode brut est inutilisable pour l'utilisateur.
    ratatui::restore();
    outcome
}

/// Rétablit le terminal avant d'afficher un message de panique.
///
/// Sans cela, la trace s'afficherait dans l'écran alterné, en mode brut, et
/// disparaîtrait aussitôt.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        previous(info);
    }));
}

/// Le clavier arrive par paramètre plutôt que d'être lu ici : c'est ce qui
/// permet d'exercer la boucle avec des touches scriptées et un terminal en
/// mémoire, sans qu'aucun vrai terminal ne soit nécessaire.
async fn event_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    mut state: AppState,
    mut events: mpsc::Receiver<ScanEvent>,
    mut input: mpsc::Receiver<Event>,
) -> Result<AppState, B::Error> {
    let mut ticker = tokio::time::interval(TICK);
    let started = Instant::now();
    let mut scan_done = false;
    let mut dirty = true;

    loop {
        if dirty {
            terminal.draw(|frame| render(&state, frame))?;
            dirty = false;
        }

        tokio::select! {
            event = events.recv(), if !scan_done => match event {
                Some(event) => {
                    state.apply(event);
                    dirty = true;
                }
                None => scan_done = true,
            },

            key = input.recv() => match key {
                Some(Event::Key(key)) => {
                    state.on_key(key);
                    dirty = true;
                }
                Some(Event::Resize(_, _)) => dirty = true,
                Some(_) => {}
                // Le fil de lecture a disparu : plus personne ne peut agir sur
                // l'interface, la garder ouverte n'aurait pas de sens.
                None => break,
            },

            _ = ticker.tick() => {
                if !state.finished {
                    state.elapsed = started.elapsed();
                    dirty = true;
                }
            }
        }

        if state.should_quit {
            break;
        }
    }

    Ok(state)
}

/// Lit le clavier dans un fil dédié.
///
/// `crossterm` n'offre pas de lecture asynchrone sans dépendance
/// supplémentaire ; un fil bloquant qui alimente un canal fait le même travail
/// et reste lisible.
fn spawn_input_reader() -> mpsc::Receiver<Event> {
    let (tx, rx) = mpsc::channel(32);

    std::thread::spawn(move || {
        loop {
            match event::poll(INPUT_POLL) {
                Ok(true) => match event::read() {
                    // Un envoi qui échoue signifie que le récepteur a été
                    // abandonné : l'application s'arrête.
                    Ok(event) => {
                        if tx.blocking_send(event).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                Ok(false) => {
                    if tx.is_closed() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use crate::inventory::Host;

    /// Laisse la boucle consommer ce qui vient d'être envoyé.
    ///
    /// `send` ne fait que déposer dans le canal ; sans cette pause, la touche
    /// de sortie pourrait être traitée avant les événements de scan.
    async fn laisser_consommer() {
        tokio::time::sleep(Duration::from_millis(80)).await;
    }

    fn touche(code: KeyCode) -> Event {
        Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    /// Lance la boucle sur un terminal en mémoire.
    fn lancer(
        events: mpsc::Receiver<ScanEvent>,
        input: mpsc::Receiver<Event>,
    ) -> tokio::task::JoinHandle<AppState> {
        tokio::spawn(async move {
            let mut terminal = Terminal::new(TestBackend::new(90, 12)).unwrap();
            let state = AppState::new("192.168.1.0/24".to_owned(), None);
            // `TestBackend` ne peut pas échouer : son type d'erreur est
            // `Infallible`.
            event_loop(&mut terminal, state, events, input)
                .await
                .unwrap()
        })
    }

    #[tokio::test]
    async fn les_evenements_du_scan_alimentent_l_affichage_puis_q_termine() {
        let (scan_tx, scan_rx) = mpsc::channel(8);
        let (input_tx, input_rx) = mpsc::channel(8);
        let boucle = lancer(scan_rx, input_rx);

        scan_tx
            .send(ScanEvent::Started { total: 254 })
            .await
            .unwrap();
        for last in [10u8, 20] {
            scan_tx
                .send(ScanEvent::HostFound(Host::new(Ipv4Addr::new(
                    192, 168, 1, last,
                ))))
                .await
                .unwrap();
        }
        laisser_consommer().await;

        input_tx.send(touche(KeyCode::Char('q'))).await.unwrap();
        let state = boucle.await.unwrap();

        assert!(state.should_quit);
        assert_eq!(state.inventory.len(), 2, "les deux hôtes devaient arriver");
        assert_eq!(state.total, 254);
    }

    #[tokio::test]
    async fn la_fin_du_scan_ne_ferme_pas_l_interface() {
        // L'utilisateur doit pouvoir consulter le résultat après le balayage :
        // la fermeture du canal d'événements ne doit surtout pas quitter.
        let (scan_tx, scan_rx) = mpsc::channel(8);
        let (input_tx, input_rx) = mpsc::channel(8);
        let boucle = lancer(scan_rx, input_rx);

        scan_tx
            .send(ScanEvent::Finished {
                elapsed: Duration::from_secs(2),
                alive: 0,
            })
            .await
            .unwrap();
        drop(scan_tx);
        laisser_consommer().await;

        assert!(!boucle.is_finished(), "l'interface devait rester ouverte");

        input_tx.send(touche(KeyCode::Char('q'))).await.unwrap();
        let state = boucle.await.unwrap();

        assert!(state.finished);
        assert!(state.should_quit);
    }

    #[tokio::test]
    async fn la_disparition_du_clavier_termine_la_boucle() {
        // Si le fil de lecture meurt, plus personne ne peut quitter :
        // rester ouvert immobiliserait le terminal.
        let (_scan_tx, scan_rx) = mpsc::channel(8);
        let (input_tx, input_rx) = mpsc::channel(8);
        let boucle = lancer(scan_rx, input_rx);

        drop(input_tx);

        let state = tokio::time::timeout(Duration::from_secs(2), boucle)
            .await
            .expect("la boucle devait se terminer")
            .unwrap();

        assert!(!state.should_quit, "sortie subie, pas demandée");
    }
}
