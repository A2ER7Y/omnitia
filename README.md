# omnitia

**Le gestionnaire de paquets modulaire de Velotia.**

> Doc de design — pas de code pour l'instant. omnitia est le gestionnaire ; le reste du système (Velotia) vit dans d'autres composants séparés.

## Philosophie : modulaire, pas monolithique

On ne fait **pas comme systemd**, où tout (init, logind, journald, networkd, resolved, gestion cgroup…) est dans le même logiciel. Chaque capacité est un **composant séparé**, avec des **alternatives interchangeables**. omnitia orchestre ces composants sans les fusionner.

- Une capacité = un contrat (interface), pas une implémentation figée.
- Chaque capacité a une ou plusieurs implémentations (existantes, ou à faire si elles n'existent pas).
- Le gestionnaire abstrait les dépendances vers ces capacités, pas vers un logiciel précis.

## Ce que fait omnitia

1. **Abstraction de dépendances** (virtual packages / Provides) : au lieu de `Depends: systemd`, un paquet dépend d'une capacité (« un init », « un logind »). Si dinit fournit la capacité, c'est satisfait.
2. **Map des capacités → alternatives** : catalogue de chaque capacité et de ses implémentations.
3. **Découverte des dépendances implicites** : les besoins réels ne sont pas toujours déclarés (ex. snapd). Analyse static + dynamic pour les trouver et les noter.
4. **Niveaux de support** : `native` / `modified` / `not supported` / `not tested`.

## Map des capacités (exemple : l'écosystème systemd)

| Capacité | Alternatives | Statut |
|---|---|---|
| logind (sessions/seats) | elogind, LoginKit | existe |
| service management (units) | dinit, OpenRC, runit, s6 | existe (APIs différentes) |
| journald (logging) | rsyslog, syslog-ng | existe |
| networkd | NetworkManager, connman | existe |
| resolved (DNS) | dnsmasq, unbound | existe |
| cgroup/scope/slice D-Bus API | — | **à faire** (shim) |

## Le cas snapd (dépendance implicite)

snapd ne déclare pas proprement son besoin réel. `snap-confine` parle à systemd via D-Bus (scope/slice) et écrit dans les cgroups : il exige l'**API cgroup de systemd**, pas juste « un init ». Abstraire le label ne suffit pas — il faut un **shim** qui implémente cette API par-dessus un autre init. C'est la pièce manquante à construire.

## Découverte des exceptions

- **Static** : scanner scripts/binaires pour appels D-Bus (`org.freedesktop.login1`, `org.freedesktop.systemd1`), écritures `/sys/fs/cgroup`, appels `systemctl`/`loginctl`, assumptions « systemd est PID 1 ».
- **Dynamic** : tracer le runtime (`strace`, `dbus-monitor`, `ltrace`) pour voir à quoi le paquet parle vraiment.

## Prior art / références

- [therealcoolnerd/omni](https://github.com/therealcoolnerd/omni) — gestionnaire universel (apt/dnf/pacman/snap/flatpak/nix/brew/winget…), Rust, rollback SQLite, résolution BFS, recherche cross-PM.
- [Bedrock Linux](https://bedrocklinux.org) — strata cross-distro sur un kernel (ne fait pas le cross-stratum init/service).
- Debian virtual packages / Provides ; elogind / LoginKit / systemd-shim (logind sans systemd PID 1).

## Statut

Design doc. Prochaines étapes : la map complète des capacités + la méthode de découverte des dépendances implicites, puis le MVP du gestionnaire.