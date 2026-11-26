# omnitia

**Le gestionnaire de paquets modulaire de Velotia.**

> **Fork de [therealcoolnerd/omni](https://github.com/therealcoolnerd/omni)**, licence **AGPL-3.0-or-later conservée**. omnitia est le gestionnaire ; le reste du système (Velotia) vit dans d'autres composants séparés.

## Notice de fork

- **Base amont** : [therealcoolnerd/omni](https://github.com/therealcoolnerd/omni) — gestionnaire universel multi-PM (apt/dnf/pacman/snap/flatpak/nix/brew/winget…), Rust, rollback SQLite, résolution BFS, recherche cross-PM. Le code amont (boxes, brain, resolver, snapshot, database, CLI…) est conservé dans `src/`.
- **Licence conservée** : **AGPL-3.0-or-later**, identique à l'amont — texte complet dans [`LICENSE`](LICENSE), champ `license` de `Cargo.toml` inchangé. Les ajouts Velotia sont sous la même licence.
- **Fork** : [A2ER7Y/omnitia](https://github.com/A2ER7Y/omnitia). Le crate est renommé `omnitia` ; la bannière CLI affiche encore « omni » (héritage amont).

## Les ajouts Velotia

Trois modules ajoutés par-dessus omni (détails dans [`docs/velotia.md`](docs/velotia.md)) :

1. **Abstraction de dépendances par capacité** (`src/abstraction.rs`) — au lieu de `Depends: systemd`, un paquet dépend de capacités virtuelles (« un init », « un logind »…). Si dinit fournit la capacité, c'est satisfait. Map systemd → alternatives + niveaux de support (`native` / `modified` / `not-supported` / `not-tested`).
2. **Découverte des dépendances implicites** (`src/discovery.rs`) — les besoins réels ne sont pas toujours déclarés (ex. snapd). Scan **statique** implémenté (D-Bus, cgroups, `systemctl`/`loginctl`, hypothèse PID 1) ; le tracing **dynamique** (`strace`, `dbus-monitor`, `ltrace`) est prévu.
3. **Verre partagé Islansia** (`src/glass.rs`) — les paramètres de verre (blur, smoke, rim, milk, opacity, pv) sont lus depuis le **store JSON commun** `~/.config/velotia/glass.json`, partagé avec l'île Islansia/Vitreus via symlink. Changer le verre dans l'app Paramètres d'Islansia met à jour le store → omnitia recalcule son verre.

## Philosophie : modulaire, pas monolithique

On ne fait **pas comme systemd**, où tout (init, logind, journald, networkd, resolved, gestion cgroup…) est dans le même logiciel. Chaque capacité est un **composant séparé**, avec des **alternatives interchangeables**. omnitia orchestre ces composants sans les fusionner.

- Une capacité = un contrat (interface), pas une implémentation figée.
- Chaque capacité a une ou plusieurs implémentations (existantes, ou à faire si elles n'existent pas).
- Le gestionnaire abstrait les dépendances vers ces capacités, pas vers un logiciel précis.

## Map des capacités (écosystème systemd)

Catalogue implémenté dans `src/abstraction.rs` (noms de paquets **sensibles à la casse**) :

| Capacité | Identifiant virtuel | Alternatives (niveau de support) |
|---|---|---|
| logind (sessions/seats) | `logind` | elogind (`native`), LoginKit (`not-tested`) |
| service management (units) | `service-management` (alias `init`) | dinit, OpenRC, runit, s6 (`native`) |
| journald (logging) | `journald` | rsyslog, syslog-ng (`modified` — syslog ≠ API journal) |
| networkd | `networkd` | NetworkManager, connman (`native`) |
| resolved (DNS) | `resolved` | dnsmasq, unbound (`native`) |
| API D-Bus cgroup/scope/slice | `cgroup-scope-slice-api` | — aucune : **shim à faire** |

Une dépendance est satisfaite si **toutes** ses capacités le sont (conjonction). `not-supported` ne satisfait jamais ; `not-tested` fournit mais reste signalé comme non évalué. Une dep inconnue du catalogue reste concrète (paquet exact exigé).

## Le cas snapd (dépendance implicite)

snapd ne déclare pas proprement son besoin réel. `snap-confine` parle à systemd via D-Bus (`org.freedesktop.systemd1`, scope/slice) et écrit dans les cgroups : il exige l'**API cgroup de systemd**, pas juste « un init ». Abstraire le label ne suffit pas — il faut un **shim** qui implémente cette API par-dessus un autre init. C'est la pièce manquante à construire (`needs_shim`).

## Découverte des exceptions

- **Static** (implémenté) : scanner scripts/binaires pour appels D-Bus (`org.freedesktop.login1`, `org.freedesktop.systemd1`), écritures `/sys/fs/cgroup`, appels `systemctl`/`loginctl`, assumptions « systemd est PID 1 ». Analyse 100 % statique : le code analysé n'est **jamais exécuté**. Chaque finding porte la capacité, le numéro de ligne et la preuve.
- **Dynamic** (prévu) : tracer le runtime (`strace`, `dbus-monitor`, `ltrace`) pour voir à quoi le paquet parle vraiment.

## Usage CLI

Toolchain : Rust **stable** (`rust-toolchain.toml`). Le binaire produit par cargo s'appelle `omnitia`.

```sh
cargo build                          # ou : cargo build --release
cargo run -- search firefox          # recherche cross-PM
cargo run -- install firefox         # installation
cargo run -- install --from manifest.yaml
cargo run -- update --all --refresh
cargo run -- history undo            # rollback de la dernière installation
cargo run -- snapshot create avant-maj
cargo run -- resolve mon-paquet --detailed
./target/debug/omnitia list --detailed
```

Commandes héritées d'omni : `install`, `remove`, `search`, `info`, `update`, `list`, `history` (`show`/`undo`), `snapshot` (`create`/`list`/`revert`), `config` (`show`/`edit`/`reset`), `resolve`, `verify`, `hardware` (`detect`/`install`/`vendor`), `repository` (`add`/`remove`/`list`/`refresh`), `gui` (feature `gui`), `web` (interface web, `--port`). Flags globaux : `--verbose`, et `--mock` pour **simuler sans toucher au système réel**.

Sous-commandes Velotia **à venir** (stream 6, `src/velotia_cli.rs` encore au stade stub) : `abstract`, `discover`, `glass`, `capability`. En attendant, les modules s'utilisent comme bibliothèque :

```rust
use omnitia::abstraction::{abstract_dependency, is_satisfied};
use omnitia::discovery::scan_text;
use omnitia::glass::{parse_json_store, compute};

// « Depends: systemd » → 6 capacités virtuelles ; dinit seul ne suffit pas
let caps = abstract_dependency("systemd");
assert!(!is_satisfied("systemd", &["dinit"]));

// scan statique d'un script (jamais exécuté)
let findings = scan_text("systemctl start snapd");

// verre partagé : blur 0.1 → sigma 1.62 (scale 1.0)
let cfg = parse_json_store(r#"{"blur":0.1}"#);
let glass = compute(&cfg, 1.0);
```

## Statut

Le design doc initial est devenu du code :

- **Implémentés + testés** : `abstraction` (map + niveaux + satisfaction), `discovery` (scan statique), `glass` (formules Vitreus + store JSON).
- **Stubs en cours** (autres streams) : `capability_map`, `velotia_resolver`, `velotia_discovery` (dynamique), `velotia_glass`, `velotia_security`, `velotia_cli`.
- **Hérité d'omni** : le gestionnaire universel (boxes, brain, resolver, snapshot, database, CLI, GUI/web).

Prochaines étapes : la map complète des capacités au-delà de systemd, la découverte dynamique, le shim cgroup/scope/slice (cas snapd), puis le branchement des sous-commandes Velotia.

## Prior art / références

- [therealcoolnerd/omni](https://github.com/therealcoolnerd/omni) — l'amont dont ce fork est issu.
- [Bedrock Linux](https://bedrocklinux.org) — strata cross-distro sur un kernel (ne fait pas le cross-stratum init/service).
- Debian virtual packages / Provides ; elogind / LoginKit / systemd-shim (logind sans systemd PID 1).

## Licence

**AGPL-3.0-or-later** — voir [`LICENSE`](LICENSE). Fork de [therealcoolnerd/omni](https://github.com/therealcoolnerd/omni) sous la même licence ; copyright amont therealcoolnerd, ajouts Velotia sous AGPL-3.0-or-later.