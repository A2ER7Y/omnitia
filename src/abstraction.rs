//! Stream B — abstraction de dépendances (virtual packages / Provides) + map de capacités.
//!
//! Philosophie omnitia : une dépendance ne pointe pas vers un logiciel figé mais vers
//! une **capacité** (un contrat). `Depends: systemd` est réécrit en capacités virtuelles
//! (« un init », « un logind », …) ; si une alternative fournit la capacité, c'est satisfait.
//!
//! Sémantique :
//! - `abstract_dependency("systemd")` → toutes les capacités que le monolithe incarne
//!   (init, logind, journald, networkd, resolved, API cgroup). Une dep sur un composant
//!   (`systemd-logind`) ou sur une implémentation (`elogind`) → sa seule capacité.
//! - Une capacité est satisfaite si un paquet installé la fournit avec un niveau de
//!   support utilisable (`NotSupported` ne satisfait jamais ; `NotTested` fournit mais
//!   reste signalé comme non évalué).
//! - Une dep est satisfaite si **toutes** ses capacités sont satisfaites (conjonction).
//!   C'est le cas snapd : « un init » ne suffit pas, il faut l'API cgroup/scope/slice —
//!   la pièce manquante (shim), cf. `needs_shim`.
//! - Une dep inconnue du catalogue reste concrète : satisfaite seulement si le paquet
//!   exact est installé.
//!
//! Les noms de paquets sont sensibles à la casse (`OpenRC`, `NetworkManager`, `LoginKit`).

/// Une capacité = un contrat (interface), pas une implémentation figée.
/// L'ordre suit la map du README (écosystème systemd).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// logind — sessions/seats.
    Logind,
    /// service management — « un init » (units).
    ServiceManagement,
    /// journald — journalisation.
    Journald,
    /// networkd — gestion réseau.
    Networkd,
    /// resolved — résolution DNS.
    Resolved,
    /// API D-Bus cgroup/scope/slice de systemd — aucune alternative, shim à faire.
    CgroupScopeSliceApi,
}

impl Capability {
    /// Toutes les capacités du catalogue (ordre README).
    pub const ALL: [Capability; 6] = [
        Capability::Logind,
        Capability::ServiceManagement,
        Capability::Journald,
        Capability::Networkd,
        Capability::Resolved,
        Capability::CgroupScopeSliceApi,
    ];

    /// Identifiant canonique (sert aussi de nom de paquet virtuel, façon Debian Provides).
    pub fn id(self) -> &'static str {
        match self {
            Capability::Logind => "logind",
            Capability::ServiceManagement => "service-management",
            Capability::Journald => "journald",
            Capability::Networkd => "networkd",
            Capability::Resolved => "resolved",
            Capability::CgroupScopeSliceApi => "cgroup-scope-slice-api",
        }
    }

    /// Description humaine : la capacité virtuelle telle qu'écrite dans une dep.
    pub fn description(self) -> &'static str {
        match self {
            Capability::Logind => "un logind (sessions/seats)",
            Capability::ServiceManagement => "un init (gestion de services)",
            Capability::Journald => "un journald (journalisation)",
            Capability::Networkd => "un networkd (gestion réseau)",
            Capability::Resolved => "un resolved (résolution DNS)",
            Capability::CgroupScopeSliceApi => "API D-Bus cgroup/scope/slice",
        }
    }

    /// Retrouve une capacité depuis son identifiant (ou l'alias `init`).
    pub fn from_id(id: &str) -> Option<Capability> {
        match id.trim() {
            "logind" => Some(Capability::Logind),
            "service-management" | "init" => Some(Capability::ServiceManagement),
            "journald" => Some(Capability::Journald),
            "networkd" => Some(Capability::Networkd),
            "resolved" => Some(Capability::Resolved),
            "cgroup-scope-slice-api" => Some(Capability::CgroupScopeSliceApi),
            _ => None,
        }
    }

    /// Map capacités → alternatives (catalogue README).
    ///
    /// Niveaux initiaux du catalogue :
    /// - `Native` : fournit la capacité telle quelle (elogind ; les quatre inits ;
    ///   NetworkManager/connman ; dnsmasq/unbound).
    /// - `Modified` : fournit la capacité moyennant adaptation (rsyslog/syslog-ng :
    ///   syslog ≠ API journal).
    /// - `NotTested` : existe, pas encore évalué (LoginKit).
    /// - API cgroup : aucune alternative — shim à construire (cas snapd).
    pub fn alternatives(self) -> &'static [Alternative] {
        match self {
            Capability::Logind => &[
                Alternative {
                    name: "elogind",
                    level: SupportLevel::Native,
                },
                Alternative {
                    name: "LoginKit",
                    level: SupportLevel::NotTested,
                },
            ],
            Capability::ServiceManagement => &[
                Alternative {
                    name: "dinit",
                    level: SupportLevel::Native,
                },
                Alternative {
                    name: "OpenRC",
                    level: SupportLevel::Native,
                },
                Alternative {
                    name: "runit",
                    level: SupportLevel::Native,
                },
                Alternative {
                    name: "s6",
                    level: SupportLevel::Native,
                },
            ],
            Capability::Journald => &[
                Alternative {
                    name: "rsyslog",
                    level: SupportLevel::Modified,
                },
                Alternative {
                    name: "syslog-ng",
                    level: SupportLevel::Modified,
                },
            ],
            Capability::Networkd => &[
                Alternative {
                    name: "NetworkManager",
                    level: SupportLevel::Native,
                },
                Alternative {
                    name: "connman",
                    level: SupportLevel::Native,
                },
            ],
            Capability::Resolved => &[
                Alternative {
                    name: "dnsmasq",
                    level: SupportLevel::Native,
                },
                Alternative {
                    name: "unbound",
                    level: SupportLevel::Native,
                },
            ],
            Capability::CgroupScopeSliceApi => &[],
        }
    }
}

/// Niveau de support d'une implémentation (README : native / modified / not supported / not tested).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportLevel {
    /// Fonctionne tel quel, sans modification.
    Native,
    /// Fonctionne moyennant adaptation (patch, shim, traduction d'API).
    Modified,
    /// Incompatible connu : ne satisfait jamais la capacité.
    NotSupported,
    /// Existe mais pas encore évalué : fournit, reste signalé.
    NotTested,
}

impl SupportLevel {
    /// Nom canonique (forme du README, tirets).
    pub fn as_str(self) -> &'static str {
        match self {
            SupportLevel::Native => "native",
            SupportLevel::Modified => "modified",
            SupportLevel::NotSupported => "not-supported",
            SupportLevel::NotTested => "not-tested",
        }
    }

    /// Parse un niveau (`not-supported`/`not supported` acceptés, idem not-tested).
    pub fn parse(s: &str) -> Option<SupportLevel> {
        match s.trim() {
            "native" => Some(SupportLevel::Native),
            "modified" => Some(SupportLevel::Modified),
            "not-supported" | "not supported" => Some(SupportLevel::NotSupported),
            "not-tested" | "not tested" => Some(SupportLevel::NotTested),
            _ => None,
        }
    }

    /// Un niveau utilisable peut satisfaire une capacité.
    /// Seul `NotSupported` est exclu ; `NotTested` fournit mais reste à évaluer.
    pub fn is_usable(self) -> bool {
        !matches!(self, SupportLevel::NotSupported)
    }
}

/// Une implémentation concrète d'une capacité, avec son niveau de support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alternative {
    /// Nom exact du paquet (sensible à la casse).
    pub name: &'static str,
    /// Niveau de support catalogué.
    pub level: SupportLevel,
}

/// Vrai si `package` est une alternative cataloguée de `cap` (fait de catalogue,
/// indépendamment du niveau de support).
pub fn provides(package: &str, cap: Capability) -> bool {
    cap.alternatives().iter().any(|alt| alt.name == package)
}

/// Niveau de support catalogué de `package` pour `cap`, s'il est connu.
pub fn support_level(package: &str, cap: Capability) -> Option<SupportLevel> {
    cap.alternatives()
        .iter()
        .find(|alt| alt.name == package)
        .map(|alt| alt.level)
}

/// Abstrait une dépendance vers ses capacités virtuelles (virtual packages / Provides).
///
/// - `systemd` (le monolithe) → toutes les capacités qu'il incarne.
/// - `systemd-logind`, `systemd-journald`, … → la capacité du composant.
/// - Un nom de capacité (`logind`, `init`, …) → cette capacité (paquet virtuel).
/// - Une implémentation connue (`dinit`, `elogind`, …) → sa capacité : les
///   alternatives sont interchangeables.
/// - Inconnu → vecteur vide : la dep reste concrète (cf. `is_satisfied`).
pub fn abstract_dependency(dep: &str) -> Vec<Capability> {
    let dep = dep.trim();
    match dep {
        "systemd" => return Capability::ALL.to_vec(),
        "systemd-logind" => return vec![Capability::Logind],
        "systemd-journald" => return vec![Capability::Journald],
        "systemd-networkd" => return vec![Capability::Networkd],
        "systemd-resolved" => return vec![Capability::Resolved],
        _ => {}
    }
    if let Some(cap) = Capability::from_id(dep) {
        return vec![cap];
    }
    Capability::ALL
        .into_iter()
        .filter(|&cap| provides(dep, cap))
        .collect()
}

/// Vrai si un paquet installé fournit `cap` avec un niveau utilisable.
pub fn capability_satisfied(cap: Capability, installed: &[&str]) -> bool {
    cap.alternatives()
        .iter()
        .any(|alt| alt.level.is_usable() && installed.contains(&alt.name))
}

/// Vrai si la dep est satisfaite par les paquets installés.
///
/// Dep abstraite : toutes ses capacités doivent être satisfaites (conjonction).
/// Dep inconnue du catalogue : comparaison concrète exacte.
pub fn is_satisfied(dep: &str, installed: &[&str]) -> bool {
    let caps = abstract_dependency(dep);
    if caps.is_empty() {
        return installed.iter().any(|&p| p == dep.trim());
    }
    caps.into_iter()
        .all(|cap| capability_satisfied(cap, installed))
}

/// Capacités d'une dep qui ne sont pas satisfaites par les paquets installés.
/// Utile au resolver et pour signaler le shim manquant (cas snapd : API cgroup).
pub fn missing_capabilities(dep: &str, installed: &[&str]) -> Vec<Capability> {
    abstract_dependency(dep)
        .into_iter()
        .filter(|&cap| !capability_satisfied(cap, installed))
        .collect()
}

/// Vrai si la capacité n'a aucune alternative cataloguée : il faut construire un shim.
/// Actuellement seul `CgroupScopeSliceApi` est dans ce cas (cas snapd du README).
pub fn needs_shim(cap: Capability) -> bool {
    cap.alternatives().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_dep_rewritten_to_virtual_capabilities() {
        let caps = abstract_dependency("systemd");
        assert_eq!(caps, Capability::ALL.to_vec());
        assert!(caps.contains(&Capability::ServiceManagement)); // « un init »
        assert!(caps.contains(&Capability::Logind)); // « un logind »
        assert_eq!(caps.len(), 6);
        // tolérant aux espaces
        assert_eq!(abstract_dependency("  systemd  "), caps);
    }

    #[test]
    fn systemd_init_capability_satisfied_by_dinit() {
        // Le cas demandé : dep systemd → capacité « un init », satisfaite par dinit.
        let caps = abstract_dependency("systemd");
        assert!(caps.contains(&Capability::ServiceManagement));
        assert!(provides("dinit", Capability::ServiceManagement));
        assert!(capability_satisfied(
            Capability::ServiceManagement,
            &["dinit"]
        ));
        assert_eq!(
            support_level("dinit", Capability::ServiceManagement),
            Some(SupportLevel::Native)
        );
    }

    #[test]
    fn dinit_alone_does_not_satisfy_full_systemd() {
        // « un init » ne suffit pas : logind, journald, … et l'API cgroup manquent.
        assert!(!is_satisfied("systemd", &["dinit"]));
        let missing = missing_capabilities("systemd", &["dinit"]);
        assert!(!missing.contains(&Capability::ServiceManagement));
        assert!(missing.contains(&Capability::Logind));
        assert!(missing.contains(&Capability::CgroupScopeSliceApi));
        assert_eq!(missing.len(), 5);
    }

    #[test]
    fn map_matches_readme() {
        let names = |cap: Capability| -> Vec<&'static str> {
            cap.alternatives().iter().map(|alt| alt.name).collect()
        };
        assert_eq!(names(Capability::Logind), vec!["elogind", "LoginKit"]);
        assert_eq!(
            names(Capability::ServiceManagement),
            vec!["dinit", "OpenRC", "runit", "s6"]
        );
        assert_eq!(names(Capability::Journald), vec!["rsyslog", "syslog-ng"]);
        assert_eq!(
            names(Capability::Networkd),
            vec!["NetworkManager", "connman"]
        );
        assert_eq!(names(Capability::Resolved), vec!["dnsmasq", "unbound"]);
        assert!(names(Capability::CgroupScopeSliceApi).is_empty());
        // sensible à la casse
        assert!(!provides("openrc", Capability::ServiceManagement));
        assert!(provides("OpenRC", Capability::ServiceManagement));
    }

    #[test]
    fn cgroup_api_is_the_missing_shim() {
        // Cas snapd : même avec toutes les alternatives, l'API cgroup reste à faire.
        assert!(needs_shim(Capability::CgroupScopeSliceApi));
        assert!(!needs_shim(Capability::Logind));
        let installed = ["dinit", "elogind", "rsyslog", "NetworkManager", "dnsmasq"];
        assert!(!capability_satisfied(
            Capability::CgroupScopeSliceApi,
            &installed
        ));
        assert!(!is_satisfied("systemd", &installed));
        assert_eq!(
            missing_capabilities("systemd", &installed),
            vec![Capability::CgroupScopeSliceApi]
        );
        // une dep directe sur l'API cgroup n'est satisfaite par rien d'existant
        assert!(!is_satisfied("cgroup-scope-slice-api", &installed));
    }

    #[test]
    fn alternatives_are_interchangeable() {
        // Une dep sur une implémentation s'abstrait vers sa capacité.
        assert_eq!(abstract_dependency("elogind"), vec![Capability::Logind]);
        assert!(is_satisfied("elogind", &["LoginKit"]));
        assert!(is_satisfied("systemd-logind", &["elogind"]));
        assert!(is_satisfied("dinit", &["s6"]));
        // mais pas par un paquet d'une autre capacité
        assert!(!is_satisfied("elogind", &["dinit"]));
    }

    #[test]
    fn systemd_components_abstract_to_their_capability() {
        assert_eq!(
            abstract_dependency("systemd-logind"),
            vec![Capability::Logind]
        );
        assert_eq!(
            abstract_dependency("systemd-journald"),
            vec![Capability::Journald]
        );
        assert_eq!(
            abstract_dependency("systemd-networkd"),
            vec![Capability::Networkd]
        );
        assert_eq!(
            abstract_dependency("systemd-resolved"),
            vec![Capability::Resolved]
        );
    }

    #[test]
    fn capability_ids_work_as_virtual_deps() {
        // Roundtrip id → capacité, et alias « init ».
        for cap in Capability::ALL {
            assert_eq!(Capability::from_id(cap.id()), Some(cap));
        }
        assert_eq!(
            Capability::from_id("init"),
            Some(Capability::ServiceManagement)
        );
        assert_eq!(Capability::from_id("inexistant"), None);
        // Un nom de capacité est un paquet virtuel : Depends: logind → elogind satisfait.
        assert_eq!(abstract_dependency("logind"), vec![Capability::Logind]);
        assert!(is_satisfied("logind", &["elogind"]));
        assert!(is_satisfied("init", &["runit"]));
    }

    #[test]
    fn unknown_dep_stays_concrete() {
        assert!(abstract_dependency("firefox").is_empty());
        assert!(is_satisfied("firefox", &["firefox"]));
        assert!(!is_satisfied("firefox", &["dinit"]));
        assert!(missing_capabilities("firefox", &[]).is_empty());
    }

    #[test]
    fn support_levels_parse() {
        assert_eq!(SupportLevel::parse("native"), Some(SupportLevel::Native));
        assert_eq!(
            SupportLevel::parse("modified"),
            Some(SupportLevel::Modified)
        );
        assert_eq!(
            SupportLevel::parse("not-supported"),
            Some(SupportLevel::NotSupported)
        );
        assert_eq!(
            SupportLevel::parse("not supported"),
            Some(SupportLevel::NotSupported)
        );
        assert_eq!(
            SupportLevel::parse("not-tested"),
            Some(SupportLevel::NotTested)
        );
        assert_eq!(
            SupportLevel::parse("not tested"),
            Some(SupportLevel::NotTested)
        );
        assert_eq!(
            SupportLevel::parse("  native  "),
            Some(SupportLevel::Native)
        );
        assert_eq!(SupportLevel::parse("n'importe quoi"), None);
        // as_str est la forme canonique, roundtrip
        for level in [
            SupportLevel::Native,
            SupportLevel::Modified,
            SupportLevel::NotSupported,
            SupportLevel::NotTested,
        ] {
            assert_eq!(SupportLevel::parse(level.as_str()), Some(level));
        }
    }

    #[test]
    fn support_levels_usability() {
        // Native/Modified/NotTested fournissent ; NotSupported ne satisfait jamais.
        assert!(SupportLevel::Native.is_usable());
        assert!(SupportLevel::Modified.is_usable());
        assert!(SupportLevel::NotTested.is_usable());
        assert!(!SupportLevel::NotSupported.is_usable());
        // une alternative NotSupported ne satisferait pas, même installée
        let alt = Alternative {
            name: "fantome",
            level: SupportLevel::NotSupported,
        };
        assert!(!alt.level.is_usable());
        // NotTested fournit mais reste signalé (LoginKit)
        assert_eq!(
            support_level("LoginKit", Capability::Logind),
            Some(SupportLevel::NotTested)
        );
        assert!(capability_satisfied(Capability::Logind, &["LoginKit"]));
    }

    #[test]
    fn support_level_lookup() {
        assert_eq!(
            support_level("rsyslog", Capability::Journald),
            Some(SupportLevel::Modified)
        );
        assert_eq!(
            support_level("syslog-ng", Capability::Journald),
            Some(SupportLevel::Modified)
        );
        assert_eq!(
            support_level("dnsmasq", Capability::Resolved),
            Some(SupportLevel::Native)
        );
        // paquet inconnu, ou connu mais pour une autre capacité
        assert_eq!(support_level("firefox", Capability::Logind), None);
        assert_eq!(support_level("dinit", Capability::Logind), None);
    }

    #[test]
    fn descriptions_are_virtual_packages() {
        assert!(Capability::ServiceManagement
            .description()
            .contains("un init"));
        assert!(Capability::Logind.description().contains("un logind"));
        assert!(Capability::CgroupScopeSliceApi
            .description()
            .contains("cgroup"));
    }
}
