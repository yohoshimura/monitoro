//! Présentation des résultats.
//!
//! Rien ici n'est consulté par le moteur : l'affichage dépend du modèle, jamais
//! l'inverse.

pub mod app;
pub mod json;
pub mod plain;
pub mod render;
pub mod tui;

pub use app::AppState;
