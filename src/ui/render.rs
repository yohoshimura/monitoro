//! Dessin de l'interface.
//!
//! Fonction pure de l'état vers l'écran : aucune décision n'est prise ici, ce
//! qui permet de vérifier le rendu dans un tampon mémoire plutôt que dans un
//! vrai terminal.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Gauge, Paragraph, Row, Table, TableState};

use super::app::AppState;
use crate::inventory::Host;

const HEADERS: [&str; 5] = ["ADRESSE", "MAC", "CONSTRUCTEUR", "NOM", "PORTS"];

pub fn render(state: &AppState, frame: &mut Frame) {
    let [title, body, gauge, hints] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    render_title(state, frame, title);
    render_hosts(state, frame, body);
    render_gauge(state, frame, gauge);
    render_hints(state, frame, hints);
}

fn render_title(state: &AppState, frame: &mut Frame, area: Rect) {
    let mut spans = vec![
        Span::styled(" monitoro ", Style::new().bg(Color::Cyan).fg(Color::Black)),
        Span::raw(" "),
        Span::styled(&state.target, Style::new().add_modifier(Modifier::BOLD)),
    ];

    if let Some(interface) = &state.interface {
        spans.push(Span::styled(
            format!("  via {interface}"),
            Style::new().dim(),
        ));
    }

    frame.render_widget(Line::from(spans), area);
}

fn render_hosts(state: &AppState, frame: &mut Frame, area: Rect) {
    let hosts = state.visible_hosts();

    if hosts.is_empty() {
        let message = if state.inventory.is_empty() {
            if state.finished {
                "Aucun hôte n'a répondu."
            } else {
                "Balayage en cours…"
            }
        } else {
            "Aucun hôte ne correspond au filtre."
        };

        frame.render_widget(Paragraph::new(message).dim(), area);
        return;
    }

    let rows = hosts.iter().map(|host| host_row(host));
    let widths = [
        Constraint::Length(15),
        Constraint::Length(17),
        Constraint::Min(18),
        Constraint::Length(16),
        Constraint::Length(22),
    ];

    let header = Row::new(HEADERS.map(Cell::from)).style(Style::new().dim().bold());
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(2)
        .row_highlight_style(
            Style::new()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    let mut table_state = TableState::default().with_selected(Some(state.selected));
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn host_row(host: &Host) -> Row<'_> {
    let mac = match host.mac {
        Some(mac) => Span::raw(mac.to_string()),
        None => Span::styled("-", Style::new().dim()),
    };

    // Une adresse randomisée est une information, pas une lacune : elle mérite
    // un traitement visuel distinct de « constructeur inconnu ».
    let vendor = match host.vendor {
        Some(vendor) => match vendor.name() {
            Some(name) => Span::raw(name),
            None if vendor.is_randomized() => {
                Span::styled("(MAC randomisée)", Style::new().fg(Color::Magenta))
            }
            None => Span::styled("(inconnu)", Style::new().dim()),
        },
        None => Span::styled("-", Style::new().dim()),
    };

    let hostname = match host.hostname.as_deref() {
        Some(name) => Span::raw(name),
        None => Span::styled("-", Style::new().dim()),
    };

    let ports = if host.open_ports.is_empty() {
        Span::styled("-", Style::new().dim())
    } else {
        Span::styled(
            host.open_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
            Style::new().fg(Color::Green),
        )
    };

    Row::new(vec![
        Cell::from(host.ip.to_string()),
        Cell::from(mac),
        Cell::from(vendor),
        Cell::from(hostname),
        Cell::from(ports),
    ])
}

fn render_gauge(state: &AppState, frame: &mut Frame, area: Rect) {
    let ratio = if state.total == 0 {
        0.0
    } else {
        (state.done as f64 / state.total as f64).clamp(0.0, 1.0)
    };

    let label = format!(
        "{}/{} · {} hôte(s) · {:.1}s{}",
        state.done,
        state.total,
        state.inventory.len(),
        state.elapsed.as_secs_f64(),
        if state.finished { " · terminé" } else { "" }
    );

    let gauge = Gauge::default()
        .ratio(ratio)
        .label(label)
        .gauge_style(Style::new().fg(if state.finished {
            Color::Green
        } else {
            Color::Cyan
        }))
        .block(Block::new());

    frame.render_widget(gauge, area);
}

fn render_hints(state: &AppState, frame: &mut Frame, area: Rect) {
    if state.editing_filter {
        let line = Line::from(vec![
            Span::styled("filtre: ", Style::new().fg(Color::Yellow)),
            Span::raw(&state.filter),
            Span::styled("_", Style::new().slow_blink()),
            Span::styled("   Entrée valider · Échap effacer", Style::new().dim()),
        ]);
        frame.render_widget(line, area);
        return;
    }

    let mut spans = vec![Span::styled(
        format!(
            "q quitter · s tri ({}) · / filtrer · ↑↓ naviguer",
            state.sort.label()
        ),
        Style::new().dim(),
    )];

    if !state.filter.is_empty() {
        spans.push(Span::styled(
            format!("  filtre: {}", state.filter),
            Style::new().fg(Color::Yellow),
        ));
    }

    if let Some(warning) = state.warnings.last() {
        spans.push(Span::styled(
            format!("  ⚠ {warning}"),
            Style::new().fg(Color::Red),
        ));
    }

    frame.render_widget(Line::from(spans), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::time::Duration;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crate::inventory::{MacAddr, Vendor};
    use crate::scan::ScanEvent;

    /// Dessine l'état dans un tampon mémoire et en rend le texte, ligne à ligne.
    fn draw(state: &AppState) -> Vec<String> {
        let mut terminal = Terminal::new(TestBackend::new(100, 12)).unwrap();
        terminal.draw(|frame| render(state, frame)).unwrap();

        let buffer = terminal.backend().buffer().clone();
        let width = buffer.area.width as usize;

        buffer
            .content()
            .chunks(width)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .map(|line| line.trim_end().to_owned())
            .collect()
    }

    fn app_peuple() -> AppState {
        let mut app = AppState::new("192.168.1.0/24".to_owned(), Some("Ethernet".to_owned()));

        app.apply(ScanEvent::Started { total: 254 });
        app.apply(ScanEvent::HostFound(Host {
            mac: Some(MacAddr::new([0x3C, 0x22, 0xFB, 0x01, 0x02, 0x03])),
            vendor: Some(Vendor::Known("Apple, Inc.")),
            hostname: Some("portable".to_owned()),
            open_ports: vec![22, 443],
            ..Host::new(Ipv4Addr::new(192, 168, 1, 10))
        }));
        app.apply(ScanEvent::HostFound(Host {
            mac: Some(MacAddr::new([0xDA, 0x22, 0xFB, 0x01, 0x02, 0x03])),
            vendor: Some(Vendor::Randomized),
            ..Host::new(Ipv4Addr::new(192, 168, 1, 77))
        }));
        app.apply(ScanEvent::Progress {
            done: 120,
            total: 254,
        });

        app
    }

    #[test]
    fn l_entete_annonce_la_cible_et_l_interface() {
        let rendu = draw(&app_peuple());

        assert!(rendu[0].contains("monitoro"));
        assert!(rendu[0].contains("192.168.1.0/24"));
        assert!(rendu[0].contains("Ethernet"));
    }

    #[test]
    fn chaque_hote_apparait_avec_ses_colonnes() {
        let rendu = draw(&app_peuple()).join("\n");

        assert!(rendu.contains("ADRESSE"), "en-tête du tableau absent");
        assert!(rendu.contains("192.168.1.10"));
        assert!(rendu.contains("3C:22:FB:01:02:03"));
        assert!(rendu.contains("Apple, Inc."));
        assert!(rendu.contains("portable"));
        assert!(rendu.contains("22,443"));
    }

    #[test]
    fn une_mac_randomisee_est_annoncee_comme_telle() {
        let rendu = draw(&app_peuple()).join("\n");

        assert!(
            rendu.contains("(MAC randomisée)"),
            "l'utilisateur doit pouvoir distinguer randomisée d'inconnue"
        );
    }

    #[test]
    fn l_avancement_est_affiche_puis_marque_termine() {
        let mut app = app_peuple();
        assert!(draw(&app).join("\n").contains("120/254"));
        assert!(!draw(&app).join("\n").contains("terminé"));

        app.apply(ScanEvent::Finished {
            elapsed: Duration::from_millis(4200),
            alive: 2,
        });

        let rendu = draw(&app).join("\n");
        assert!(rendu.contains("terminé"));
        assert!(rendu.contains("4.2s"));
    }

    #[test]
    fn un_balayage_sans_resultat_le_dit_selon_son_etat() {
        let mut app = AppState::new("10.0.0.0/24".to_owned(), None);
        assert!(draw(&app).join("\n").contains("Balayage en cours"));

        app.apply(ScanEvent::Finished {
            elapsed: Duration::from_secs(1),
            alive: 0,
        });
        assert!(draw(&app).join("\n").contains("Aucun hôte n'a répondu"));
    }

    #[test]
    fn un_filtre_sans_correspondance_est_distingue_d_un_scan_vide() {
        let mut app = app_peuple();
        app.filter = "introuvable".to_owned();

        assert!(
            draw(&app).join("\n").contains("Aucun hôte ne correspond"),
            "le message doit distinguer « rien trouvé » de « rien ne passe le filtre »"
        );
    }

    #[test]
    fn la_saisie_du_filtre_remplace_la_ligne_d_aide() {
        let mut app = app_peuple();
        app.editing_filter = true;
        app.filter = "appl".to_owned();

        let bas = draw(&app).last().unwrap().clone();

        assert!(bas.contains("filtre: appl"));
        assert!(bas.contains("Entrée valider"));
        assert!(!bas.contains("q quitter"));
    }

    #[test]
    fn la_ligne_d_aide_rappelle_le_tri_courant() {
        let mut app = app_peuple();
        app.sort = super::super::app::SortKey::Ports;

        let bas = draw(&app).last().unwrap().clone();

        assert!(bas.contains("q quitter"));
        assert!(bas.contains("tri (ports)"));
    }

    #[test]
    fn un_avertissement_remonte_dans_la_barre_du_bas() {
        let mut app = app_peuple();
        app.apply(ScanEvent::Warning("sonde interrompue".to_owned()));

        assert!(draw(&app).last().unwrap().contains("sonde interrompue"));
    }

    #[test]
    fn le_rendu_survit_a_un_terminal_minuscule() {
        // Un redimensionnement agressif ne doit jamais faire paniquer le dessin.
        let mut terminal = Terminal::new(TestBackend::new(12, 3)).unwrap();
        terminal
            .draw(|frame| render(&app_peuple(), frame))
            .expect("le rendu doit rester possible sur un terminal étroit");
    }
}
