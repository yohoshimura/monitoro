//! Sortie JSON, destinée à être redirigée vers un autre outil.
//!
//! Les types du domaine ne portent volontairement aucune annotation de
//! sérialisation : la forme publiée est décrite ici, et peut évoluer sans
//! contraindre le modèle interne.

use serde::Serialize;

use crate::inventory::{Host, Inventory, MacAddr};
use crate::scan::ScanSummary;

#[derive(Debug, Serialize)]
pub struct ScanReport<'a> {
    pub target: String,
    pub scanned: u64,
    pub alive: usize,
    pub elapsed_ms: f64,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub warnings: &'a [String],
    pub hosts: Vec<HostReport<'a>>,
}

#[derive(Debug, Serialize)]
pub struct HostReport<'a> {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<&'a str>,
    /// Adresse localement administrée : elle ne désigne aucun constructeur.
    pub mac_randomized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<&'a str>,
    pub open_ports: &'a [u16],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    pub sources: &'a [&'static str],
}

impl<'a> From<&'a Host> for HostReport<'a> {
    fn from(host: &'a Host) -> Self {
        Self {
            ip: host.ip.to_string(),
            mac: host.mac,
            vendor: host.vendor.and_then(|v| v.name()),
            mac_randomized: host.mac_is_randomized(),
            hostname: host.hostname.as_deref(),
            open_ports: &host.open_ports,
            rtt_ms: host.rtt.map(|d| d.as_secs_f64() * 1000.0),
            sources: &host.sources,
        }
    }
}

impl<'a> ScanReport<'a> {
    pub fn new(target: String, inventory: &'a Inventory, summary: &'a ScanSummary) -> Self {
        Self {
            target,
            scanned: summary.total,
            alive: summary.alive,
            elapsed_ms: summary.elapsed.as_secs_f64() * 1000.0,
            warnings: &summary.warnings,
            hosts: inventory.hosts().map(HostReport::from).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::inventory::Vendor;

    fn rapport_json(host: Host) -> serde_json::Value {
        let mut inventory = Inventory::new();
        inventory.upsert(host);

        let summary = ScanSummary {
            total: 254,
            alive: 1,
            elapsed: Duration::from_millis(1500),
            warnings: Vec::new(),
        };

        serde_json::to_value(ScanReport::new(
            "192.168.1.0/24".to_owned(),
            &inventory,
            &summary,
        ))
        .unwrap()
    }

    #[test]
    fn le_rapport_expose_les_champs_attendus() {
        let host = Host {
            mac: Some("3C:22:FB:01:02:03".parse().unwrap()),
            vendor: Some(Vendor::Known("Apple, Inc.")),
            hostname: Some("portable".to_owned()),
            open_ports: vec![22, 443],
            rtt: Some(Duration::from_millis(4)),
            sources: vec!["arp", "tcp"],
            ..Host::new(Ipv4Addr::new(192, 168, 1, 42))
        };

        let json = rapport_json(host);

        assert_eq!(json["target"], "192.168.1.0/24");
        assert_eq!(json["scanned"], 254);
        assert_eq!(json["alive"], 1);

        let host = &json["hosts"][0];
        assert_eq!(host["ip"], "192.168.1.42");
        assert_eq!(host["mac"], "3C:22:FB:01:02:03");
        assert_eq!(host["vendor"], "Apple, Inc.");
        assert_eq!(host["mac_randomized"], false);
        assert_eq!(host["hostname"], "portable");
        assert_eq!(host["open_ports"][1], 443);
        assert_eq!(host["sources"][0], "arp");
    }

    #[test]
    fn les_champs_inconnus_sont_omis_plutot_que_nuls() {
        let json = rapport_json(Host::new(Ipv4Addr::new(10, 0, 0, 1)));
        let host = &json["hosts"][0];

        for absent in ["mac", "vendor", "hostname", "rtt_ms"] {
            assert!(
                host.get(absent).is_none(),
                "« {absent} » aurait dû être omis : {host}"
            );
        }
        assert!(
            json.get("warnings").is_none(),
            "aucun avertissement à publier"
        );
        assert_eq!(host["open_ports"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn une_mac_randomisee_est_signalee_sans_constructeur() {
        let host = Host {
            mac: Some("DA:22:FB:01:02:03".parse().unwrap()),
            vendor: Some(Vendor::Randomized),
            ..Host::new(Ipv4Addr::new(192, 168, 1, 9))
        };

        let json = rapport_json(host);
        let host = &json["hosts"][0];

        assert_eq!(host["mac_randomized"], true);
        assert!(
            host.get("vendor").is_none(),
            "une adresse randomisée n'a pas de constructeur"
        );
    }
}
