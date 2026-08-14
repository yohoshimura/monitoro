//! L'état de l'interface, séparé de son dessin.
//!
//! Tout ce qui décide *quoi* montrer vit ici : agrégation des événements, tri,
//! filtre, sélection, raccourcis clavier. Aucun terminal n'est nécessaire pour
//! l'exercer, donc tout est testable directement.

use std::time::Duration;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::inventory::{Host, Inventory};
use crate::scan::ScanEvent;

/// Critère de tri du tableau.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Address,
    Vendor,
    Ports,
}

impl SortKey {
    pub fn label(self) -> &'static str {
        match self {
            Self::Address => "adresse",
            Self::Vendor => "constructeur",
            Self::Ports => "ports",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Address => Self::Vendor,
            Self::Vendor => Self::Ports,
            Self::Ports => Self::Address,
        }
    }
}

#[derive(Debug)]
pub struct AppState {
    pub target: String,
    pub interface: Option<String>,
    pub inventory: Inventory,
    pub done: u64,
    pub total: u64,
    pub elapsed: Duration,
    pub finished: bool,
    pub warnings: Vec<String>,
    pub sort: SortKey,
    pub filter: String,
    pub editing_filter: bool,
    pub selected: usize,
    pub should_quit: bool,
}

impl AppState {
    pub fn new(target: String, interface: Option<String>) -> Self {
        Self {
            target,
            interface,
            inventory: Inventory::new(),
            done: 0,
            total: 0,
            elapsed: Duration::ZERO,
            finished: false,
            warnings: Vec::new(),
            sort: SortKey::Address,
            filter: String::new(),
            editing_filter: false,
            selected: 0,
            should_quit: false,
        }
    }

    /// Intègre un événement du moteur.
    pub fn apply(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Started { total } => self.total = total,
            ScanEvent::HostFound(host) | ScanEvent::HostUpdated(host) => {
                self.inventory.upsert(host);
            }
            ScanEvent::Progress { done, total } => {
                self.done = done;
                self.total = total;
            }
            ScanEvent::Warning(message) => self.warnings.push(message),
            ScanEvent::Finished { elapsed, .. } => {
                self.elapsed = elapsed;
                self.finished = true;
            }
        }

        self.clamp_selection();
    }

    /// Les hôtes réellement affichés, filtrés puis triés.
    pub fn visible_hosts(&self) -> Vec<&Host> {
        let needle = self.filter.to_lowercase();

        let mut hosts: Vec<&Host> = self
            .inventory
            .hosts()
            .filter(|host| needle.is_empty() || matches(host, &needle))
            .collect();

        match self.sort {
            // L'inventaire itère déjà par adresse croissante.
            SortKey::Address => {}
            SortKey::Vendor => hosts.sort_by(|a, b| {
                vendor_key(a)
                    .cmp(&vendor_key(b))
                    .then_with(|| a.ip.cmp(&b.ip))
            }),
            // Les hôtes les plus « bavards » d'abord : c'est ce qu'on cherche
            // quand on trie par ports.
            SortKey::Ports => hosts.sort_by(|a, b| {
                b.open_ports
                    .len()
                    .cmp(&a.open_ports.len())
                    .then_with(|| a.ip.cmp(&b.ip))
            }),
        }

        hosts
    }

    pub fn selected_host(&self) -> Option<&Host> {
        self.visible_hosts().get(self.selected).copied()
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        // Sous Windows, chaque touche produit un appui *et* un relâchement :
        // sans ce filtre, chaque commande serait exécutée deux fois.
        if key.kind != KeyEventKind::Press {
            return;
        }

        if self.editing_filter {
            self.edit_filter(key);
            return;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c') if ctrl => self.should_quit = true,
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('s') => self.sort = self.sort.next(),
            KeyCode::Char('/') => self.editing_filter = true,
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Home => self.selected = 0,
            KeyCode::End => self.selected = self.visible_hosts().len().saturating_sub(1),
            _ => {}
        }
    }

    fn edit_filter(&mut self, key: KeyEvent) {
        match key.code {
            // On sort du mode saisie sans effacer : le filtre reste appliqué.
            KeyCode::Enter => self.editing_filter = false,
            KeyCode::Esc => {
                self.filter.clear();
                self.editing_filter = false;
            }
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Char(c) => self.filter.push(c),
            _ => {}
        }

        self.clamp_selection();
    }

    fn move_selection(&mut self, delta: isize) {
        let count = self.visible_hosts().len();
        if count == 0 {
            self.selected = 0;
            return;
        }

        let next = self.selected as isize + delta;
        self.selected = next.clamp(0, count as isize - 1) as usize;
    }

    /// Empêche la sélection de sortir de la liste quand celle-ci rétrécit.
    fn clamp_selection(&mut self) {
        let count = self.visible_hosts().len();
        self.selected = self.selected.min(count.saturating_sub(1));
    }
}

fn matches(host: &Host, needle: &str) -> bool {
    host.ip.to_string().contains(needle)
        || host
            .mac
            .is_some_and(|mac| mac.to_string().to_lowercase().contains(needle))
        || host
            .vendor
            .and_then(|v| v.name())
            .is_some_and(|name| name.to_lowercase().contains(needle))
        || host
            .hostname
            .as_deref()
            .is_some_and(|name| name.to_lowercase().contains(needle))
}

/// Clé de tri par constructeur, les hôtes sans constructeur en dernier.
fn vendor_key(host: &Host) -> (bool, String) {
    match host.vendor.and_then(|v| v.name()) {
        Some(name) => (false, name.to_lowercase()),
        None => (true, String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    use crate::inventory::{MacAddr, Vendor};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn host(last: u8, vendor: Option<&'static str>, ports: Vec<u16>) -> Host {
        Host {
            mac: Some(MacAddr::new([0x3C, 0x22, 0xFB, 0, 0, last])),
            vendor: vendor.map(Vendor::Known),
            open_ports: ports,
            ..Host::new(Ipv4Addr::new(192, 168, 1, last))
        }
    }

    fn app_avec_hotes() -> AppState {
        let mut app = AppState::new("192.168.1.0/24".to_owned(), None);
        for host in [
            host(30, Some("Zyxel"), vec![80]),
            host(10, Some("Apple"), vec![22, 80, 443]),
            host(20, None, vec![]),
        ] {
            app.apply(ScanEvent::HostFound(host));
        }
        app
    }

    fn adresses(app: &AppState) -> Vec<u8> {
        app.visible_hosts()
            .iter()
            .map(|h| h.ip.octets()[3])
            .collect()
    }

    #[test]
    fn l_avancement_et_la_conclusion_sont_enregistres() {
        let mut app = AppState::new("cible".to_owned(), None);

        app.apply(ScanEvent::Started { total: 254 });
        app.apply(ScanEvent::Progress {
            done: 42,
            total: 254,
        });
        assert_eq!((app.done, app.total), (42, 254));
        assert!(!app.finished);

        app.apply(ScanEvent::Finished {
            elapsed: Duration::from_secs(3),
            alive: 2,
        });
        assert!(app.finished);
        assert_eq!(app.elapsed, Duration::from_secs(3));
    }

    #[test]
    fn une_mise_a_jour_complete_l_hote_sans_le_dupliquer() {
        let mut app = AppState::new("cible".to_owned(), None);
        let ip = Ipv4Addr::new(192, 168, 1, 5);

        app.apply(ScanEvent::HostFound(Host {
            mac: Some(MacAddr::new([1, 2, 3, 4, 5, 6])),
            ..Host::new(ip)
        }));
        app.apply(ScanEvent::HostUpdated(Host {
            hostname: Some("nas".to_owned()),
            ..Host::new(ip)
        }));

        assert_eq!(app.inventory.len(), 1);
        let host = app.inventory.get(ip).unwrap();
        assert_eq!(host.hostname.as_deref(), Some("nas"));
        assert!(host.mac.is_some(), "la MAC ne devait pas être perdue");
    }

    #[test]
    fn le_tri_par_defaut_suit_l_ordre_des_adresses() {
        assert_eq!(adresses(&app_avec_hotes()), vec![10, 20, 30]);
    }

    #[test]
    fn le_tri_par_constructeur_relegue_les_inconnus_en_fin() {
        let mut app = app_avec_hotes();
        app.sort = SortKey::Vendor;

        assert_eq!(adresses(&app), vec![10, 30, 20]);
    }

    #[test]
    fn le_tri_par_ports_place_les_hotes_les_plus_ouverts_en_tete() {
        let mut app = app_avec_hotes();
        app.sort = SortKey::Ports;

        assert_eq!(adresses(&app), vec![10, 30, 20]);
    }

    #[test]
    fn la_touche_s_fait_defiler_les_criteres_de_tri() {
        let mut app = app_avec_hotes();

        app.on_key(key(KeyCode::Char('s')));
        assert_eq!(app.sort, SortKey::Vendor);
        app.on_key(key(KeyCode::Char('s')));
        assert_eq!(app.sort, SortKey::Ports);
        app.on_key(key(KeyCode::Char('s')));
        assert_eq!(app.sort, SortKey::Address, "le cycle doit boucler");
    }

    #[test]
    fn le_filtre_porte_sur_toutes_les_colonnes() {
        let mut app = app_avec_hotes();
        app.apply(ScanEvent::HostUpdated(Host {
            hostname: Some("imprimante".to_owned()),
            ..Host::new(Ipv4Addr::new(192, 168, 1, 20))
        }));

        app.filter = "apple".to_owned();
        assert_eq!(adresses(&app), vec![10], "filtre par constructeur");

        app.filter = "1.30".to_owned();
        assert_eq!(adresses(&app), vec![30], "filtre par adresse");

        app.filter = "imprim".to_owned();
        assert_eq!(adresses(&app), vec![20], "filtre par nom");

        app.filter = "3c:22".to_owned();
        assert_eq!(
            adresses(&app).len(),
            3,
            "filtre par MAC, insensible à la casse"
        );
    }

    #[test]
    fn la_saisie_du_filtre_se_valide_ou_s_annule() {
        let mut app = app_avec_hotes();

        app.on_key(key(KeyCode::Char('/')));
        assert!(app.editing_filter);

        for c in "apple".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Backspace));
        assert_eq!(app.filter, "appl");

        app.on_key(key(KeyCode::Enter));
        assert!(!app.editing_filter, "Entrée quitte la saisie");
        assert_eq!(app.filter, "appl", "et conserve le filtre");

        app.on_key(key(KeyCode::Char('/')));
        app.on_key(key(KeyCode::Esc));
        assert!(app.filter.is_empty(), "Échap efface le filtre");
        assert!(!app.should_quit, "Échap en saisie ne doit pas quitter");
    }

    #[test]
    fn en_saisie_les_touches_de_commande_sont_du_texte() {
        let mut app = app_avec_hotes();
        app.on_key(key(KeyCode::Char('/')));

        app.on_key(key(KeyCode::Char('q')));
        app.on_key(key(KeyCode::Char('s')));

        assert_eq!(app.filter, "qs");
        assert!(!app.should_quit);
        assert_eq!(app.sort, SortKey::Address);
    }

    #[test]
    fn la_selection_reste_dans_les_bornes() {
        let mut app = app_avec_hotes();

        app.on_key(key(KeyCode::Up));
        assert_eq!(app.selected, 0, "pas de débordement vers le haut");

        for _ in 0..10 {
            app.on_key(key(KeyCode::Down));
        }
        assert_eq!(app.selected, 2, "pas de débordement vers le bas");

        app.on_key(key(KeyCode::Home));
        assert_eq!(app.selected, 0);
        app.on_key(key(KeyCode::End));
        assert_eq!(app.selected, 2);
    }

    #[test]
    fn un_filtre_qui_retrecit_la_liste_ramene_la_selection() {
        let mut app = app_avec_hotes();
        app.on_key(key(KeyCode::End));
        assert_eq!(app.selected, 2);

        app.on_key(key(KeyCode::Char('/')));
        for c in "apple".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }

        assert_eq!(app.visible_hosts().len(), 1);
        assert_eq!(app.selected, 0, "la sélection devait être ramenée");
        assert!(app.selected_host().is_some());
    }

    #[test]
    fn un_filtre_sans_correspondance_ne_selectionne_rien() {
        let mut app = app_avec_hotes();
        app.on_key(key(KeyCode::End));

        app.filter = "introuvable".to_owned();
        app.on_key(key(KeyCode::Char('/')));
        app.on_key(key(KeyCode::Backspace));

        assert!(app.visible_hosts().is_empty());
        assert_eq!(app.selected, 0);
        assert!(app.selected_host().is_none());
    }

    #[test]
    fn les_touches_de_sortie_sont_reconnues() {
        for code in [KeyCode::Char('q'), KeyCode::Esc] {
            let mut app = app_avec_hotes();
            app.on_key(key(code));
            assert!(app.should_quit, "{code:?} devait quitter");
        }

        let mut app = app_avec_hotes();
        app.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit, "Ctrl+C devait quitter");
    }

    #[test]
    fn les_relachements_de_touche_sont_ignores() {
        // Sans ce filtre, chaque appui compterait double sous Windows.
        let mut app = app_avec_hotes();
        let mut release = key(KeyCode::Char('s'));
        release.kind = KeyEventKind::Release;

        app.on_key(release);

        assert_eq!(app.sort, SortKey::Address);
    }
}
