//! monitoro — découverte et inventaire du réseau local.
//!
//! L'organisation suit le flux de données :
//!
//! - [`net`] détermine *quoi* scanner (cibles, sous-réseau local) ;
//! - [`probe`] sait *interroger* une adresse et dire si elle répond ;
//! - [`scan`] *orchestre* les sondes et émet des événements ;
//! - [`inventory`] *agrège* ces résultats en hôtes identifiés ;
//! - [`ui`] *présente* le tout, sans jamais être consulté par le moteur.
//!
//! Cette dernière frontière est structurante : le moteur n'imprime rien, il
//! émet des [`scan::ScanEvent`]. C'est ce qui permet à la TUI d'afficher les
//! hôtes au fil de l'eau, et aux tests de piloter le moteur sans terminal.

pub mod error;
pub mod inventory;
pub mod net;
pub mod probe;
pub mod scan;
pub mod ui;

pub use error::{Error, Result};
