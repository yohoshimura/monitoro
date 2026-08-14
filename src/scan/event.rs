//! Ce que le moteur raconte pendant qu'il travaille.

use std::time::Duration;

use crate::inventory::Host;

/// Un événement émis au fil du balayage.
///
/// Le moteur n'imprime jamais : il émet. C'est ce qui permet à la TUI
/// d'afficher les hôtes au fur et à mesure, à la sortie JSON de tout accumuler
/// silencieusement, et aux tests d'observer le déroulement sans terminal.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanEvent {
    /// Émis une fois, avant tout le reste.
    Started { total: u64 },

    /// Un hôte vient d'être découvert.
    HostFound(Host),

    /// Un hôte déjà connu a été complété (nom, constructeur…).
    HostUpdated(Host),

    /// Avancement. `done` compte les adresses traitées, répondantes ou non.
    Progress { done: u64, total: u64 },

    /// Un incident non fatal. Le balayage continue.
    Warning(String),

    /// Émis une fois, en dernier.
    Finished { elapsed: Duration, alive: usize },
}
