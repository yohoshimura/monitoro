//! Type d'erreur de la bibliothèque.
//!
//! Convention du projet : la bibliothèque expose des erreurs typées
//! (`thiserror`), le binaire les remonte avec du contexte (`anyhow`).

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cible invalide « {input} » : {reason}")]
    InvalidTarget { input: String, reason: String },

    #[error(
        "plage trop large : /{prefix} représente {hosts} hôtes. \
         Relancez avec --yes si c'est bien l'intention."
    )]
    TargetTooLarge { prefix: u8, hosts: u64 },

    #[error("aucune interface réseau IPv4 utilisable n'a été détectée")]
    NoLocalInterface,

    #[error("erreur d'entrée/sortie : {0}")]
    Io(#[from] std::io::Error),
}
