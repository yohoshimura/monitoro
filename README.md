# monitoro

Découverte et inventaire du réseau local, en Rust — **sans droits administrateur
et sans rien installer**.

```
 monitoro  192.168.1.0/24  via Ethernet
ADRESSE          MAC                CONSTRUCTEUR             NOM        PORTS
192.168.1.1      00:00:5E:00:53:01  (constructeur)           routeur    22,443
192.168.1.12     00:00:5E:00:53:0C  (constructeur)           -          80
192.168.1.24     00:00:5E:00:53:18  (constructeur)           nas        80,443,445
192.168.1.37     00:00:5E:00:53:25  (constructeur)           -          9100
192.168.1.58     02:00:5E:00:53:3A  (MAC randomisée)         -          -
████████████████████████░░░░░░░░  254/254 · 20 hôte(s) · 8.9s · terminé
q quitter · s tri (adresse) · / filtrer · ↑↓ naviguer
```

## Ce que ça fait

Répond à la question « qui est sur mon réseau ? » : balaye le sous-réseau,
identifie chaque machine par son adresse matérielle, en déduit le constructeur,
et relève les ports ouverts. Les résultats s'affichent au fil du balayage.

## Installation

```sh
cargo build --release
```

Aucune dépendance externe : ni Npcap, ni WinPcap, ni privilèges élevés.

## Utilisation

```sh
monitoro                      # détecte le sous-réseau local et l'explore
monitoro 192.168.1.0/24       # une plage précise
monitoro 10.0.0.5             # une seule machine
monitoro --json > reseau.json # sortie exploitable par un autre outil
monitoro --plain              # tableau texte, sans interface
```

La sortie bascule automatiquement en mode texte lorsqu'elle est redirigée : pas
de séquences d'échappement dans vos fichiers.

| Option | Effet |
|---|---|
| `--json` / `--plain` | Sortie non interactive |
| `--concurrency <N>` | Adresses sondées simultanément (défaut : 64) |
| `--timeout <MS>` | Délai par tentative TCP (défaut : 600) |
| `--ports 22,80,443` | Ports à interroger |
| `--no-tcp` | ARP seul : plus rapide, mais aucun port relevé |
| `--no-resolve` | Ne cherche pas les noms de machines |
| `--yes` | Confirme une plage plus large qu'un /16 |

Dans l'interface : `q` quitte, `s` change le tri, `/` filtre (sur toutes les
colonnes), `↑` `↓` naviguent.

## Comment ça marche

Deux sondes complémentaires, appliquées à chaque adresse.

**ARP** (`SendARP`, API IP Helper de Windows) demande à la pile du système de
résoudre une adresse IPv4 en adresse matérielle. C'est la sonde décisive : un
appareil qui n'expose aucun service — téléphone, caméra, imprimante en veille —
reste invisible à un balayage de ports, mais **doit** répondre à ARP pour
communiquer sur le lien. C'est ce qui sépare un inventaire d'une simple liste de
services.

**TCP** tente une connexion sur quelques ports courants. Détail qui compte : un
refus de connexion (`RST`) prouve l'existence de l'hôte tout autant qu'une
connexion acceptée. Seul le silence est ambigu.

L'adresse matérielle est ensuite recherchée dans le registre IEEE, compilé dans
le binaire — aucune requête réseau à l'exécution.

## Limites connues

- **ARP est réservé à Windows et à IPv4.** Le reste du code est portable ; seul
  `src/probe/arp_win.rs` demanderait un équivalent pour Linux ou macOS. ARP ne
  franchit pas les routeurs : seul le sous-réseau local est explorable.
- **Les noms de machines remontent rarement.** La résolution inverse dépend
  d'une zone DNS inverse ou de LLMNR, souvent absentes ou désactivées sur un
  réseau domestique. La colonne reste alors vide.
- **Une MAC randomisée n'a pas de constructeur.** Les appareils mobiles
  changent d'adresse d'un réseau à l'autre ; monitoro l'indique explicitement
  plutôt que d'afficher « inconnu ».
- **Registre IEEE partiel.** Seules les assignations MA-L (préfixes /24) sont
  embarquées, soit la quasi-totalité des cas. Les plages MA-M et MA-S, publiées
  séparément par l'IEEE, retombent sur « inconnu ».
- **La sonde TCP peut être trompée hors du lien local.** Un intermédiaire qui
  accepte les connexions à la place de la destination — proxy transparent,
  portail captif — ferait passer une adresse *routée* pour vivante. Le
  sous-réseau local, joint directement sans passer par une passerelle, n'est
  pas concerné, et la sonde ARP ne l'est jamais.

## Mettre à jour le registre des constructeurs

```sh
curl -o assets/oui.csv https://standards-oui.ieee.org/oui/oui.csv
cargo build
```

`build.rs` reconstruit la table à chaque changement du fichier. Si le fichier
est absent, le projet compile quand même : la colonne constructeur reste vide.

## Développement

```sh
cargo test                    # 100 tests, sans réseau
cargo test -- --ignored       # tests dépendant d'un vrai réseau local
cargo clippy --all-targets
```

L'organisation suit le flux de données : `net` décide quoi scanner, `probe`
interroge, `scan` orchestre et **émet des événements**, `inventory` agrège,
`ui` présente. Le moteur n'imprime jamais — c'est ce qui permet à l'interface
de se remplir en direct et aux tests de le piloter sans terminal.

## Périmètre

Cette version couvre la découverte et l'inventaire. Le pilier *monitoring*
annoncé par le nom — surveillance continue, détection de nouvel appareil,
alertes — reste à construire, tout comme les sondes privilégiées (ICMP et ARP
bruts) et le support de Linux.

## Licence

MIT
