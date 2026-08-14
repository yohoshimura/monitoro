//! Sortie texte alignée, pour les usages non interactifs.

use std::fmt::Write as _;

use crate::inventory::Inventory;
use crate::scan::ScanSummary;

/// Compose le tableau des hôtes découverts.
///
/// Rend une chaîne plutôt que d'imprimer : c'est ce qui rend la mise en forme
/// vérifiable par un test.
pub fn render(inventory: &Inventory, summary: &ScanSummary) -> String {
    let mut out = String::new();

    if inventory.is_empty() {
        out.push_str("Aucun hôte n'a répondu.\n");
    } else {
        let largeur_ip = width(inventory.hosts().map(|h| h.ip.to_string().len()), 15);
        let largeur_nom = width(
            inventory
                .hosts()
                .map(|h| h.hostname.as_deref().unwrap_or("-").chars().count()),
            12,
        );
        let largeur_vendor = width(
            inventory.hosts().map(|h| vendor_label(h).chars().count()),
            10,
        );

        writeln!(
            out,
            "{:<largeur_ip$}  {:<17}  {:<largeur_vendor$}  {:<largeur_nom$}  PORTS",
            "ADRESSE", "MAC", "CONSTRUCTEUR", "NOM"
        )
        .unwrap();

        for host in inventory.hosts() {
            let mac = host.mac.map_or_else(|| "-".to_owned(), |m| m.to_string());
            let nom = host.hostname.as_deref().unwrap_or("-");
            let ports = if host.open_ports.is_empty() {
                "-".to_owned()
            } else {
                host.open_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            };

            writeln!(
                out,
                "{:<largeur_ip$}  {mac:<17}  {:<largeur_vendor$}  {nom:<largeur_nom$}  {ports}",
                host.ip.to_string(),
                vendor_label(host)
            )
            .unwrap();
        }
    }

    writeln!(
        out,
        "\n{} hôte(s) sur {} adresse(s) en {:.1} s",
        summary.alive,
        summary.total,
        summary.elapsed.as_secs_f64()
    )
    .unwrap();

    for warning in &summary.warnings {
        writeln!(out, "attention : {warning}").unwrap();
    }

    out
}

fn vendor_label(host: &crate::inventory::Host) -> String {
    match host.vendor {
        Some(vendor) => vendor.to_string(),
        None => "-".to_owned(),
    }
}

fn width(lengths: impl Iterator<Item = usize>, minimum: usize) -> usize {
    lengths.max().unwrap_or(0).max(minimum)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::inventory::{Host, Vendor};

    fn summary(alive: usize) -> ScanSummary {
        ScanSummary {
            total: 254,
            alive,
            elapsed: Duration::from_millis(2400),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn un_inventaire_vide_le_dit_explicitement() {
        let rendu = render(&Inventory::new(), &summary(0));

        assert!(rendu.contains("Aucun hôte n'a répondu"));
        assert!(rendu.contains("0 hôte(s) sur 254 adresse(s)"));
    }

    #[test]
    fn chaque_hote_occupe_une_ligne_avec_ses_informations() {
        let mut inventory = Inventory::new();
        inventory.upsert(Host {
            mac: Some("3C:22:FB:01:02:03".parse().unwrap()),
            vendor: Some(Vendor::Known("Apple, Inc.")),
            hostname: Some("portable".to_owned()),
            open_ports: vec![22, 443],
            ..Host::new(Ipv4Addr::new(192, 168, 1, 42))
        });

        let rendu = render(&inventory, &summary(1));
        let ligne = rendu
            .lines()
            .find(|l| l.starts_with("192.168.1.42"))
            .expect("la ligne de l'hôte est absente");

        assert!(ligne.contains("3C:22:FB:01:02:03"));
        assert!(ligne.contains("Apple, Inc."));
        assert!(ligne.contains("portable"));
        assert!(ligne.contains("22,443"));
    }

    #[test]
    fn les_informations_absentes_sont_remplacees_par_un_tiret() {
        let mut inventory = Inventory::new();
        inventory.upsert(Host::new(Ipv4Addr::new(10, 0, 0, 1)));

        let rendu = render(&inventory, &summary(1));
        let ligne = rendu.lines().find(|l| l.starts_with("10.0.0.1")).unwrap();

        assert_eq!(ligne.matches('-').count(), 4, "ligne rendue : {ligne:?}");
    }

    #[test]
    fn les_avertissements_sont_repris_en_fin_de_rapport() {
        let mut bilan = summary(0);
        bilan.warnings.push("sonde interrompue".to_owned());

        let rendu = render(&Inventory::new(), &bilan);

        assert!(rendu.contains("attention : sonde interrompue"));
    }
}
