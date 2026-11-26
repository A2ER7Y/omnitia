//! Stream 1 — map des capacités systemd → alternatives (données + lookup + niveaux de support).
//!
//! Le catalogue (capacités, alternatives, niveau par implémentation) est défini dans
//! [`crate::abstraction`] (Stream B) ; ce module en expose la vue « capacité » :
//! lookup par identifiant, niveau de support global d'une capacité, liste des entrées.
//!
//! Données (map du README) :
//! - logind → elogind (`Native`), `LoginKit` (`NotTested`)
//! - service units (« un init ») → dinit / `OpenRC` / runit / s6 (`Native`)
//! - journald → rsyslog / syslog-ng (`Modified` : syslog ≠ API journal)
//! - networkd → `NetworkManager` / connman (`Native`)
//! - resolved → dnsmasq / unbound (`Native`)
//! - API `D-Bus` cgroup/scope/slice → aucune alternative : shim à écrire (cas snapd),
//!   niveau global `NotSupported`.

use crate::abstraction::{Alternative, Capability, SupportLevel};

/// Une entrée de la map : capacité, alternatives cataloguées, niveau de support global.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityEntry {
    /// La capacité (contrat virtuel, façon Debian Provides).
    pub capability: Capability,
    /// Alternatives cataloguées (vide = shim à construire).
    pub alternatives: &'static [Alternative],
    /// Niveau de support global de la capacité (cf. [`support_level`]).
    pub level: SupportLevel,
}

/// Lookup d'une capacité par identifiant → ses alternatives cataloguées.
///
/// Accepte les identifiants canoniques (`logind`, `service-management`, …) et
/// l'alias `init` ; tolérant aux espaces. Retourne `None` si l'identifiant est
/// inconnu du catalogue. Une capacité connue sans alternative (API cgroup)
/// retourne `Some(&[])`.
#[must_use]
pub fn lookup(id: &str) -> Option<&'static [Alternative]> {
    Capability::from_id(id).map(Capability::alternatives)
}

/// Niveau de support global d'une capacité : le meilleur niveau offert par une
/// de ses alternatives (`Native` > `Modified` > `NotTested` > `NotSupported`).
///
/// Aucune alternative cataloguée → `NotSupported` : il faut construire un shim
/// (cas de l'API `D-Bus` cgroup/scope/slice, exigée par snapd).
#[must_use]
pub fn support_level(cap: Capability) -> SupportLevel {
    cap.alternatives()
        .iter()
        .map(|alt| alt.level)
        .max_by_key(|&level| rank(level))
        .unwrap_or(SupportLevel::NotSupported)
}

/// Liste des capacités du catalogue, dans l'ordre du README.
#[must_use]
pub const fn capabilities() -> &'static [Capability] {
    &Capability::ALL
}

/// Toutes les entrées de la map (capacité + alternatives + niveau global),
/// dans l'ordre du README.
#[must_use]
pub fn entries() -> [CapabilityEntry; 6] {
    Capability::ALL.map(|cap| CapabilityEntry {
        capability: cap,
        alternatives: cap.alternatives(),
        level: support_level(cap),
    })
}

/// Rang d'un niveau pour comparer les alternatives (meilleur = plus haut).
const fn rank(level: SupportLevel) -> u8 {
    match level {
        SupportLevel::Native => 3,
        SupportLevel::Modified => 2,
        SupportLevel::NotTested => 1,
        SupportLevel::NotSupported => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Noms des alternatives, pour comparer facilement au catalogue README.
    fn names(alts: &[Alternative]) -> Vec<&'static str> {
        alts.iter().map(|alt| alt.name).collect()
    }

    #[test]
    fn lookup_known_capabilities() {
        let cases: [(&str, &[&str]); 6] = [
            ("logind", &["elogind", "LoginKit"]),
            ("service-management", &["dinit", "OpenRC", "runit", "s6"]),
            ("journald", &["rsyslog", "syslog-ng"]),
            ("networkd", &["NetworkManager", "connman"]),
            ("resolved", &["dnsmasq", "unbound"]),
            ("cgroup-scope-slice-api", &[]),
        ];
        for (id, expected) in cases {
            let alts = lookup(id).unwrap_or_else(|| panic!("capacité connue: {id}"));
            assert_eq!(names(alts), expected, "alternatives de {id}");
        }
        // alias « init » et tolérance aux espaces
        assert_eq!(
            names(lookup("init").unwrap()),
            vec!["dinit", "OpenRC", "runit", "s6"]
        );
        assert_eq!(
            names(lookup("  logind  ").unwrap()),
            vec!["elogind", "LoginKit"]
        );
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert_eq!(lookup("firefox"), None);
        assert_eq!(lookup(""), None);
        assert_eq!(lookup("inexistant"), None);
        // le monolithe n'est pas un identifiant de capacité
        assert_eq!(lookup("systemd"), None);
        // sensible à la casse
        assert_eq!(lookup("LOGIND"), None);
        assert_eq!(lookup("Cgroup-Scope-Slice-API"), None);
    }

    #[test]
    fn lookup_cgroup_is_known_but_empty() {
        // Capacité connue, aucune alternative : Some(&[]), pas None.
        let alts = lookup("cgroup-scope-slice-api").unwrap();
        assert_eq!(alts, []);
    }

    #[test]
    fn support_levels_per_capability() {
        // Meilleur niveau offert : elogind rend logind natif malgré LoginKit non testé.
        assert_eq!(support_level(Capability::Logind), SupportLevel::Native);
        assert_eq!(
            support_level(Capability::ServiceManagement),
            SupportLevel::Native
        );
        // syslog ≠ API journal : adaptation nécessaire.
        assert_eq!(support_level(Capability::Journald), SupportLevel::Modified);
        assert_eq!(support_level(Capability::Networkd), SupportLevel::Native);
        assert_eq!(support_level(Capability::Resolved), SupportLevel::Native);
    }

    #[test]
    fn cgroup_api_is_not_supported() {
        // Aucune alternative → NotSupported : shim à écrire (cas snapd).
        assert_eq!(
            support_level(Capability::CgroupScopeSliceApi),
            SupportLevel::NotSupported
        );
        assert!(!support_level(Capability::CgroupScopeSliceApi).is_usable());
        assert!(crate::abstraction::needs_shim(
            Capability::CgroupScopeSliceApi
        ));
    }

    #[test]
    fn capabilities_list_matches_readme_order() {
        let caps = capabilities();
        assert_eq!(caps.len(), 6);
        assert_eq!(caps, Capability::ALL.as_slice());
        let ids: Vec<&str> = caps.iter().map(|cap| cap.id()).collect();
        assert_eq!(
            ids,
            vec![
                "logind",
                "service-management",
                "journald",
                "networkd",
                "resolved",
                "cgroup-scope-slice-api",
            ]
        );
    }

    #[test]
    fn entries_are_consistent_with_lookup_and_levels() {
        let entries = entries();
        assert_eq!(entries.len(), 6);
        for (entry, &cap) in entries.iter().zip(Capability::ALL.iter()) {
            assert_eq!(entry.capability, cap);
            assert_eq!(lookup(cap.id()), Some(entry.alternatives));
            assert_eq!(entry.level, support_level(cap));
        }
        // l'entrée cgroup porte bien NotSupported
        let cgroup = entries
            .iter()
            .find(|e| e.capability == Capability::CgroupScopeSliceApi)
            .unwrap();
        assert_eq!(cgroup.alternatives, []);
        assert_eq!(cgroup.level, SupportLevel::NotSupported);
    }

    #[test]
    fn alternative_levels_match_catalog() {
        let level = |id: &str, package: &str| -> SupportLevel {
            lookup(id)
                .unwrap()
                .iter()
                .find(|alt| alt.name == package)
                .unwrap_or_else(|| panic!("{package} doit être catalogué pour {id}"))
                .level
        };
        assert_eq!(level("logind", "elogind"), SupportLevel::Native);
        assert_eq!(level("logind", "LoginKit"), SupportLevel::NotTested);
        for init in ["dinit", "OpenRC", "runit", "s6"] {
            assert_eq!(level("service-management", init), SupportLevel::Native);
        }
        assert_eq!(level("journald", "rsyslog"), SupportLevel::Modified);
        assert_eq!(level("journald", "syslog-ng"), SupportLevel::Modified);
        assert_eq!(level("networkd", "NetworkManager"), SupportLevel::Native);
        assert_eq!(level("networkd", "connman"), SupportLevel::Native);
        assert_eq!(level("resolved", "dnsmasq"), SupportLevel::Native);
        assert_eq!(level("resolved", "unbound"), SupportLevel::Native);
    }
}
