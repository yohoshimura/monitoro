//! Transforme le registre IEEE (`assets/oui.csv`) en table statique triée.
//!
//! Le but est qu'aucune lecture de fichier ni accès réseau ne soit nécessaire à
//! l'exécution : la table est compilée dans le binaire et interrogée par
//! recherche binaire.

use std::{
    env,
    fs::File,
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

const REGISTRY: &str = "assets/oui.csv";

fn main() {
    println!("cargo:rerun-if-changed={REGISTRY}");
    println!("cargo:rerun-if-changed=build.rs");

    let mut entries = parse_registry(Path::new(REGISTRY));

    // La recherche binaire à l'exécution exige un tri par préfixe. Le registre
    // IEEE n'est pas trié, et contient occasionnellement des doublons.
    entries.sort_unstable_by_key(|(prefix, _)| *prefix);
    entries.dedup_by_key(|(prefix, _)| *prefix);

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("oui_table.rs");
    write_table(&out, &entries);
}

/// Extrait les couples (préfixe 24 bits, organisation) des assignations MA-L.
///
/// Un registre absent n'est pas une erreur fatale : le projet doit rester
/// compilable sans l'asset, la résolution de constructeur retombant alors sur
/// « inconnu ».
fn parse_registry(path: &Path) -> Vec<(u32, String)> {
    let Ok(file) = File::open(path) else {
        println!(
            "cargo:warning={} est absent : la table des constructeurs sera vide",
            path.display()
        );
        return Vec::new();
    };

    let mut reader = csv::Reader::from_reader(BufReader::new(file));
    let mut entries = Vec::with_capacity(40_000);

    for record in reader.records().flatten() {
        // Colonnes : Registry, Assignment, Organization Name, Organization Address.
        if record.get(0) != Some("MA-L") {
            continue;
        }

        let Some(assignment) = record.get(1).map(str::trim) else {
            continue;
        };
        if assignment.len() != 6 {
            continue;
        }
        let Ok(prefix) = u32::from_str_radix(assignment, 16) else {
            continue;
        };

        let organization = record.get(2).unwrap_or_default().trim();
        if organization.is_empty() {
            continue;
        }

        entries.push((prefix, organization.to_owned()));
    }

    entries
}

fn write_table(out: &Path, entries: &[(u32, String)]) {
    let file = File::create(out).expect("création de la table OUI");
    let mut writer = BufWriter::new(file);

    writeln!(
        writer,
        "/// Préfixes OUI triés, générés depuis {REGISTRY} par build.rs."
    )
    .unwrap();
    writeln!(
        writer,
        "pub(crate) static OUI_TABLE: [(u32, &str); {}] = [",
        entries.len()
    )
    .unwrap();

    for (prefix, organization) in entries {
        // `{:?}` produit un littéral Rust correctement échappé (guillemets,
        // antislashs) ; les noms d'organisation en contiennent régulièrement.
        writeln!(writer, "    ({prefix:#08X}, {organization:?}),").unwrap();
    }

    writeln!(writer, "];").unwrap();
    writer.flush().expect("écriture de la table OUI");
}
