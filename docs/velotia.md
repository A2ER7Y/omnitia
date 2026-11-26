# Velotia — design d'omnitia

omnitia est le gestionnaire de paquets de Velotia : un **fork de [therealcoolnerd/omni](https://github.com/therealcoolnerd/omni)** (licence **AGPL-3.0-or-later conservée**, voir [`LICENSE`](../LICENSE) et le [README](../README.md)) augmenté d'une couche Velotia. Ce document décrit la philosophie, la map des capacités, les niveaux de support, la découverte des dépendances implicites et le store de verre partagé avec Islansia.

## 1. Philosophie : composants séparés, pas monolithique

Le contre-exemple est **systemd** : init, logind, journald, networkd, resolved, gestion cgroup… tout vit dans le même logiciel, et les paquets finissent par dépendre du monolithe entier alors qu'ils n'utilisent qu'une de ses facettes.

Velotia fait l'inverse :

- Chaque capacité est un **composant séparé**, avec des **alternatives interchangeables** (dinit ou OpenRC ou runit ou s6 pour « un init » ; elogind ou LoginKit pour « un logind »…).
- Une capacité = un **contrat** (interface), pas une implémentation figée. C'est l'esprit des *virtual packages* / `Provides` de Debian.
- Le gestionnaire **abstrait les dépendances vers ces capacités**, pas vers un logiciel précis : `Depends: systemd` est réécrit en capacités virtuelles, et n'importe quelle alternative qui fournit la capacité satisfait la dep.
- omnitia **orchestre** ces composants sans les fusionner. Le reste du système Velotia vit dans d'autres composants séparés ; omnitia n'est que le gestionnaire.

Prior art : [Bedrock Linux](https://bedrocklinux.org) fait des strata cross-distro sur un kernel, mais ne fait pas le cross-stratum init/service — c'est précisément le trou que Velotia adresse.

## 2. Map des capacités systemd → alternatives

Catalogue implémenté dans `src/abstraction.rs` (`Capability::alternatives()`). Les identifiants servent de **noms de paquets virtuels** (façon Debian Provides). Les noms de paquets sont **sensibles à la casse** (`OpenRC`, `NetworkManager`, `LoginKit`).

| Capacité systemd | Identifiant virtuel | Description | Alternatives | Niveau |
|---|---|---|---|---|
| logind | `logind` | un logind (sessions/seats) | elogind | `native` |
| | | | LoginKit | `not-tested` |
| service management | `service-management` (alias `init`) | un init (gestion de services) | dinit, OpenRC, runit, s6 | `native` |
| journald | `journald` | un journald (journalisation) | rsyslog, syslog-ng | `modified` |
| networkd | `networkd` | un networkd (gestion réseau) | NetworkManager, connman | `native` |
| resolved | `resolved` | un resolved (résolution DNS) | dnsmasq, unbound | `native` |
| API D-Bus cgroup/scope/slice | `cgroup-scope-slice-api` | API D-Bus cgroup/scope/slice | — aucune | **shim à faire** |

Notes :

- `rsyslog`/`syslog-ng` sont `modified` : syslog ≠ API journal, il faut une adaptation (traduction d'API).
- `LoginKit` est `not-tested` : il existe, fournit la capacité, mais reste signalé comme non évalué.
- L'API cgroup/scope/slice n'a **aucune alternative cataloguée** : `needs_shim(cap)` est vrai, c'est la pièce manquante à construire (cas snapd, § 4).
- `abstract_dependency` réécrit une dep :
  - `systemd` (le monolithe) → **toutes** les capacités qu'il incarne (les 6) ;
  - `systemd-logind`, `systemd-journald`, `systemd-networkd`, `systemd-resolved` → la capacité du composant ;
  - un identifiant de capacité (`logind`, `init`, …) → cette capacité (paquet virtuel) ;
  - une implémentation connue (`dinit`, `elogind`, …) → sa capacité : les alternatives sont interchangeables (`Depends: elogind` est satisfait par LoginKit) ;
  - un nom inconnu du catalogue → vecteur vide : la dep **reste concrète**, satisfaite seulement si le paquet exact est installé.

## 3. Niveaux de support

Quatre niveaux (`SupportLevel`, formes canoniques `native` / `modified` / `not-supported` / `not-tested` ; le parseur accepte aussi `not supported` / `not tested`) :

| Niveau | Signification | Satisfait une capacité ? |
|---|---|---|
| `native` | fonctionne tel quel, sans modification | oui |
| `modified` | fonctionne moyennant adaptation (patch, shim, traduction d'API) | oui |
| `not-supported` | incompatible connu | **jamais** |
| `not-tested` | existe, pas encore évalué | oui, mais reste signalé |

Sémantique de satisfaction (`is_satisfied`, `capability_satisfied`, `missing_capabilities`) :

- Une capacité est satisfaite si un paquet **installé** la fournit avec un niveau **utilisable** (tout sauf `not-supported`).
- Une dep abstraite est satisfaite si **toutes** ses capacités sont satisfaites (**conjonction**). C'est le cas snapd : « un init » ne suffit pas, il faut aussi l'API cgroup/scope/slice.
- `missing_capabilities(dep, installed)` liste ce qui manque — utile au resolver et pour signaler le shim manquant.
- Exemple : avec `dinit` seul, `systemd` n'est pas satisfait ; il manque 5 capacités (logind, journald, networkd, resolved, API cgroup). Même avec dinit + elogind + rsyslog + NetworkManager + dnsmasq, il manque encore l'API cgroup.

## 4. Découverte des dépendances implicites

Les dépendances déclarées ne révèlent pas les besoins réels : snapd ne déclare pas proprement son usage de l'API cgroup/scope/slice de systemd. Deux analyses complémentaires :

### 4.1 Statique — implémenté (`src/discovery.rs`)

**Invariant : analyse 100 % statique.** On ne fait que LIRE du texte (script, source, chaînes extraites d'un binaire) ; le code analysé n'est **jamais exécuté**. `scan_file` lit les octets en UTF-8 tolérant (les binaires contiennent des octets non UTF-8 ; on scanne quand même leurs chaînes).

Signaux détectés (`Capability` du module discovery) :

| Signal | Déclencheur | Capacité visée |
|---|---|---|
| `LogindDbus` | D-Bus `org.freedesktop.login1` | logind (sessions/seats) |
| `SystemdDbus` | D-Bus `org.freedesktop.systemd1` | service management **et** API cgroup/scope/slice |
| `CgroupFs` | écritures dans `/sys/fs/cgroup` | cgroupfs monté par l'init |
| `SystemctlCli` | appel CLI `systemctl` | service management via ligne de commande |
| `LoginctlCli` | appel CLI `loginctl` | logind via ligne de commande |
| `SystemdPid1` | `/run/systemd/system`, `/proc/1/*` + systemd, « systemd … pid 1 » | hypothèse « systemd est PID 1 » |

Chaque finding porte la **capacité**, le **numéro de ligne** (1-based) et la **preuve** (la ligne trimée, tronquée à 160 caractères). `unique_capabilities` donne la « liste de courses » triée/dédupliquée à abstraire (§ 2).

Heuristiques (ligne à ligne, assumées) :

- les lignes de commentaire pleine ligne (`#`, `//`) sont ignorées ;
- frontières de tokens : `systemctl` matche, `my_systemctl` et `systemctl2` non ; `/bin/systemctl` matche ;
- noms de bus : `org.freedesktop.systemd1.Manager` matche (bus + interface), `systemd10` et `xorg.freedesktop.login1` non ;
- cgroup : le chemin doit apparaître **avec intention d'écriture** (redirection `>`/`>>` vers le chemin, `tee`, `mkdir`, `rm`, `cp`, `mv`, `touch`, `dd`, flags `O_WRONLY`/`O_RDWR`/`O_CREAT`/`O_APPEND`, `fopen(..., "w"/"a")`, `write(`/`writev(`). Une simple lecture (`cat …`, même avec `2>/dev/null`) ne compte pas ;
- PID 1 : check `sd_booted()` (`/run/systemd/system`), inspection `/proc/1/*` avec mention de systemd, mention explicite « pid 1 » (insensible à la casse ; « pid 10 » ne matche pas).

Limites : une mention sur une ligne de code est un **signal, pas une preuve d'appel effectif** (pas d'analyse de flot de contrôle) ; les motifs étalés sur plusieurs lignes peuvent être manqués.

Exemple « snapd-like » (fixture des tests) :

```sh
#!/bin/sh
set -eu
SCOPE=snap.foo.scope
mkdir -p /sys/fs/cgroup/systemd/$SCOPE
echo $$ > /sys/fs/cgroup/systemd/$SCOPE/cgroup.procs
busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartTransientUnit
systemctl start snap.foo.service
```

→ findings : `CgroupFs` (lignes 4–5), `SystemdDbus` (ligne 6), `SystemctlCli` (ligne 7). Conclusion : `snap-confine` exige l'**API cgroup de systemd**, pas juste « un init ». Abstraire le label ne suffit pas — il faut un **shim** qui implémente cette API par-dessus un autre init.

### 4.2 Dynamique — prévu (design)

Tracer le runtime pour voir à quoi le paquet parle **vraiment**, là où le statique ne voit que des chaînes :

- `strace` : appels système (ouvertures/écritures `/sys/fs/cgroup`, sockets) ;
- `dbus-monitor` : trafic D-Bus réel (`org.freedesktop.login1`, `org.freedesktop.systemd1`, interfaces appelées) ;
- `ltrace` : appels de bibliothèque.

Le dynamique complète le statique (il lève les faux positifs « mention ≠ appel » et attrape les motifs multi-lignes/obfusqués). Module dédié `velotia_discovery` : stub en cours (autre stream).

## 5. Store de verre partagé (JSON)

omnitia et l'île **Islansia/Vitreus** partagent les mêmes paramètres de verre : un seul store, deux lecteurs/écrivains. Changer le verre dans l'app Paramètres d'Islansia met à jour le store → omnitia recalcule son verre (et inversement).

### 5.1 Le store commun

- **Fichier commun** : `~/.config/velotia/glass.json` — objet JSON **plat** de nombres.
- Contenu actuel (vérifié) :

```json
{"blur":0.5,"smoke":0.0,"rim":1.0,"milk":0.4,"opacity":1.0,"pv":0.0}
```

- **Partage via symlink** : le service files de pleamar est sandboxé au dossier de données de la scène (`$XDG_DATA_HOME/pleamar/<stem>/`, par défaut `~/.local/share/pleamar/<stem>/`) et `files.read(name)` n'accepte que des noms relatifs. Un symlink `state/glass.json` pointant vers le store commun **est suivi** par la lecture — c'est le seul contournement honnête. Câblage en place (vérifié) :

```text
~/.local/share/pleamar/vitreus-island/state/glass.json
    -> ~/.config/velotia/glass.json
```

- Côté scène : `files.read(name, "json")` → table parsée (JSON uniquement ; le service n'a **pas** de parseur key=value — d'où le choix du JSON pour le store partagé). Le watcher mtime (`sys.watch("files:" .. name, cb)`) suit la cible du symlink : il se déclenche à l'enregistrement puis à chaque changement (~4 polls/s). Fichier absent → les facts gardent leurs défauts.
- Côté omnitia : `glass::parse_json_store` lit le même fichier ; clés absentes → valeurs par défaut.

### 5.2 Paramètres (`GlassConfig`)

| Champ | Bornes | Défaut | Rôle |
|---|---|---|---|
| `blur` | 0..1 | 0.5 | force du blur (slider Glass) |
| `smoke` | 0..1 | 0.0 | fumée → teinte du verre |
| `rim` | multiplicateur | 1.0 | multiplicateur `glass_rim` |
| `milk` | 0..1 | 0.4 | lait du verre (consommé côté scène Vitreus, dérivé du curseur unique `glass_mix`) |
| `opacity` | 0..1 | 1.0 | opacité |
| `pv` | 0..1 | 0.0 | beat / pression |

`milk` est parsé et stocké par omnitia mais n'entre pas dans `compute()` : il est consommé côté scène. Les autres champs alimentent les formules ci-dessous.

### 5.3 Formules (source Vitreus, vérifiées)

- **Sigma du blur gaussien** — `islansia-vitreus/scenes/vitreus-blur.wgsl:4-6` :
  `sigma = mix(0.8, 9.0, clamp(force, 0, 1)) * scale`
- **Tint** — `bar_glass.plm` / INVENTAIRE-VITREUS :
  `tint = 22% + 45% * smoke`
- **Rim** :
  `rim = 10% * glass_rim + 14% * pv * glass_rim`
- **Opacity** : clamp 0..1.

`compute(cfg, scale)` retourne `Glass { sigma, tint, rim, opacity }` — ce que le renderer applique. Exemple : blur 0.1 → sigma 1.62 ; blur 0.5 → sigma 4.9 (scale 1.0). « Je passe à 10 %, ça change. »

### 5.4 API (`src/glass.rs`)

- `parse_json_store(s)` — parse le store JSON plat (format de l'île Vitreus) ; clés absentes → défauts ; parseur minimal std-only, sans dépendance.
- `parse_store(s)` — format texte `key=value` (une paire par ligne, `#` = commentaire), conservé pour compatibilité.
- `blur_sigma(force, scale)`, `tint(smoke)`, `rim(glass_rim, pv)`, `compute(cfg, scale)`.

## 6. Modules et statut

| Module | Rôle | État |
|---|---|---|
| `src/abstraction.rs` | capacités, alternatives, niveaux, satisfaction (stream B) | implémenté + tests |
| `src/discovery.rs` | scan statique des deps implicites (stream C) | implémenté + tests |
| `src/glass.rs` | formules Vitreus + store partagé | implémenté + tests |
| `src/capability_map.rs` | map de capacités étendue | stub (stream en cours) |
| `src/velotia_resolver.rs` | resolver par capacités | stub (stream en cours) |
| `src/velotia_discovery.rs` | découverte dynamique | stub (stream en cours) |
| `src/velotia_glass.rs` | intégration verre côté CLI/app | stub (stream en cours) |
| `src/velotia_security.rs` | sécurité couche Velotia | stub (stream en cours) |
| `src/velotia_cli.rs` | sous-commandes `abstract` / `discover` / `glass` / `capability` (stream 6) | stub (stream en cours) |
| modules amont omni | boxes, brain, resolver, snapshot, database, CLI… | hérités |

## Licence

**AGPL-3.0-or-later**, conservée de l'amont [therealcoolnerd/omni](https://github.com/therealcoolnerd/omni) — texte complet dans [`LICENSE`](../LICENSE). Les ajouts Velotia décrits ici sont sous la même licence.