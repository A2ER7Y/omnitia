//! Stream 7 — tests d'intégration du module COMPLET `abstraction`.
//!
//! Vérifie l'API publique de `omnitia::abstraction` depuis l'extérieur du crate :
//! abstraction des dépendances par capacité, niveaux de support
//! (`Native` / `Modified` / `NotSupported` / `NotTested`), map systemd → alternatives,
//! et cas limites (capacité ou dep inconnue, conflits, casse, espaces).
//!
//! Aucune dépendance sur les stubs WIP `velotia_*` : uniquement `abstraction`.

use omnitia::abstraction::{
    abstract_dependency, capability_satisfied, is_satisfied, missing_capabilities, needs_shim,
    provides, support_level, Alternative, Capability, SupportLevel,
};

/// Catalogue d'une capacité sous forme (nom, niveau), pour comparaisons exactes.
fn catalog(cap: Capability) -> Vec<(&'static str, SupportLevel)> {
    cap.alternatives()
        .iter()
        .map(|alt| (alt.name, alt.level))
        .collect()
}

// ---------------------------------------------------------------------------
// 1. Catalogue de capacités : identifiants, alias, descriptions
// ---------------------------------------------------------------------------

#[test]
fn capability_all_matches_readme_order() {
    assert_eq!(
        Capability::ALL,
        [
            Capability::Logind,
            Capability::ServiceManagement,
            Capability::Journald,
            Capability::Networkd,
            Capability::Resolved,
            Capability::CgroupScopeSliceApi,
        ]
    );
    assert_eq!(Capability::ALL.len(), 6);
    // pas de doublon dans le catalogue
    for (i, a) in Capability::ALL.iter().enumerate() {
        for b in &Capability::ALL[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn capability_ids_are_canonical_virtual_names() {
    assert_eq!(Capability::Logind.id(), "logind");
    assert_eq!(Capability::ServiceManagement.id(), "service-management");
    assert_eq!(Capability::Journald.id(), "journald");
    assert_eq!(Capability::Networkd.id(), "networkd");
    assert_eq!(Capability::Resolved.id(), "resolved");
    assert_eq!(
        Capability::CgroupScopeSliceApi.id(),
        "cgroup-scope-slice-api"
    );
}

#[test]
fn capability_from_id_roundtrip_and_init_alias() {
    for cap in Capability::ALL {
        assert_eq!(Capability::from_id(cap.id()), Some(cap));
    }
    // alias « init » → service management, tolérant aux espaces
    assert_eq!(
        Capability::from_id("init"),
        Some(Capability::ServiceManagement)
    );
    assert_eq!(
        Capability::from_id("  init  "),
        Some(Capability::ServiceManagement)
    );
    assert_eq!(Capability::from_id(" logind "), Some(Capability::Logind));
}

#[test]
fn capability_from_id_rejects_unknown_and_wrong_case() {
    // capacité inconnue
    assert_eq!(Capability::from_id("inexistant"), None);
    assert_eq!(Capability::from_id(""), None);
    assert_eq!(Capability::from_id("   "), None);
    // le monolithe n'est pas une capacité
    assert_eq!(Capability::from_id("systemd"), None);
    // sensible à la casse
    assert_eq!(Capability::from_id("Logind"), None);
    assert_eq!(Capability::from_id("INIT"), None);
    assert_eq!(Capability::from_id("Service-Management"), None);
}

#[test]
fn capability_descriptions_are_human_readable() {
    for cap in Capability::ALL {
        assert_ne!(cap.description(), "");
    }
    assert!(Capability::ServiceManagement
        .description()
        .contains("un init"));
    assert!(Capability::Logind.description().contains("un logind"));
    assert!(Capability::Journald.description().contains("un journald"));
    assert!(Capability::Networkd.description().contains("un networkd"));
    assert!(Capability::Resolved.description().contains("un resolved"));
    assert!(Capability::CgroupScopeSliceApi
        .description()
        .contains("cgroup"));
}

// ---------------------------------------------------------------------------
// 2. Niveaux de support : Native / Modified / NotSupported / NotTested
// ---------------------------------------------------------------------------

#[test]
fn support_level_as_str_is_canonical() {
    assert_eq!(SupportLevel::Native.as_str(), "native");
    assert_eq!(SupportLevel::Modified.as_str(), "modified");
    assert_eq!(SupportLevel::NotSupported.as_str(), "not-supported");
    assert_eq!(SupportLevel::NotTested.as_str(), "not-tested");
}

#[test]
fn support_level_parse_roundtrip_all_variants() {
    for level in [
        SupportLevel::Native,
        SupportLevel::Modified,
        SupportLevel::NotSupported,
        SupportLevel::NotTested,
    ] {
        assert_eq!(SupportLevel::parse(level.as_str()), Some(level));
    }
    // formes avec espace acceptées
    assert_eq!(
        SupportLevel::parse("not supported"),
        Some(SupportLevel::NotSupported)
    );
    assert_eq!(
        SupportLevel::parse("not tested"),
        Some(SupportLevel::NotTested)
    );
    // tolérant aux espaces
    assert_eq!(
        SupportLevel::parse("  native  "),
        Some(SupportLevel::Native)
    );
    assert_eq!(
        SupportLevel::parse(" modified "),
        Some(SupportLevel::Modified)
    );
}

#[test]
fn support_level_parse_rejects_garbage_and_wrong_case() {
    assert_eq!(SupportLevel::parse(""), None);
    assert_eq!(SupportLevel::parse("n'importe quoi"), None);
    assert_eq!(SupportLevel::parse("unsupported"), None);
    // sensible à la casse
    assert_eq!(SupportLevel::parse("Native"), None);
    assert_eq!(SupportLevel::parse("NOT-TESTED"), None);
}

#[test]
fn support_level_usability_contract() {
    // Native / Modified / NotTested fournissent ; NotSupported ne satisfait jamais.
    assert!(SupportLevel::Native.is_usable());
    assert!(SupportLevel::Modified.is_usable());
    assert!(SupportLevel::NotTested.is_usable());
    assert!(!SupportLevel::NotSupported.is_usable());

    // une alternative construite avec NotSupported est inutilisable,
    // même si son nom était installé
    let fantome = Alternative {
        name: "fantome",
        level: SupportLevel::NotSupported,
    };
    assert!(!fantome.level.is_usable());
    assert_eq!(fantome.name, "fantome");

    // contrat vérifié à travers l'API publique : si le catalogue contenait
    // une alternative NotSupported, elle ne satisferait jamais sa capacité
    for cap in Capability::ALL {
        for alt in cap.alternatives() {
            if alt.level == SupportLevel::NotSupported {
                assert!(!capability_satisfied(cap, &[alt.name]));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Map systemd → alternatives (catalogue README)
// ---------------------------------------------------------------------------

#[test]
fn map_logind_elogind_native_loginkit_not_tested() {
    assert_eq!(
        catalog(Capability::Logind),
        vec![
            ("elogind", SupportLevel::Native),
            ("LoginKit", SupportLevel::NotTested),
        ]
    );
}

#[test]
fn map_service_management_four_native_inits() {
    assert_eq!(
        catalog(Capability::ServiceManagement),
        vec![
            ("dinit", SupportLevel::Native),
            ("OpenRC", SupportLevel::Native),
            ("runit", SupportLevel::Native),
            ("s6", SupportLevel::Native),
        ]
    );
}

#[test]
fn map_journald_syslog_alternatives_are_modified() {
    // syslog ≠ API journal : adaptation nécessaire
    assert_eq!(
        catalog(Capability::Journald),
        vec![
            ("rsyslog", SupportLevel::Modified),
            ("syslog-ng", SupportLevel::Modified),
        ]
    );
}

#[test]
fn map_networkd_and_resolved_native_alternatives() {
    assert_eq!(
        catalog(Capability::Networkd),
        vec![
            ("NetworkManager", SupportLevel::Native),
            ("connman", SupportLevel::Native),
        ]
    );
    assert_eq!(
        catalog(Capability::Resolved),
        vec![
            ("dnsmasq", SupportLevel::Native),
            ("unbound", SupportLevel::Native),
        ]
    );
}

#[test]
fn map_cgroup_api_has_no_alternative_and_needs_shim() {
    assert_eq!(
        catalog(Capability::CgroupScopeSliceApi),
        Vec::<(&str, SupportLevel)>::new()
    );
    assert!(needs_shim(Capability::CgroupScopeSliceApi));
    // toutes les autres capacités ont des alternatives : pas de shim
    for cap in Capability::ALL {
        if cap != Capability::CgroupScopeSliceApi {
            assert!(!needs_shim(cap));
            assert_ne!(cap.alternatives(), [] as [Alternative; 0]);
        }
    }
}

#[test]
fn map_package_names_are_case_sensitive() {
    assert!(provides("OpenRC", Capability::ServiceManagement));
    assert!(!provides("openrc", Capability::ServiceManagement));
    assert!(!provides("OPENRC", Capability::ServiceManagement));
    assert!(provides("NetworkManager", Capability::Networkd));
    assert!(!provides("networkmanager", Capability::Networkd));
    assert!(provides("LoginKit", Capability::Logind));
    assert!(!provides("loginkit", Capability::Logind));
    assert!(!provides("Elogind", Capability::Logind));
    // le lookup de niveau suit la même casse
    assert_eq!(
        support_level("OpenRC", Capability::ServiceManagement),
        Some(SupportLevel::Native)
    );
    assert_eq!(support_level("openrc", Capability::ServiceManagement), None);
}

#[test]
fn provides_and_support_level_are_catalog_facts() {
    // `provides` est un fait de catalogue, indépendamment du niveau :
    // `LoginKit` (NotTested) fournit bien logind
    assert!(provides("LoginKit", Capability::Logind));
    assert_eq!(
        support_level("LoginKit", Capability::Logind),
        Some(SupportLevel::NotTested)
    );
    // paquet inconnu, ou connu mais pour une autre capacité
    assert_eq!(support_level("firefox", Capability::Logind), None);
    assert!(!provides("firefox", Capability::Logind));
    assert_eq!(support_level("dinit", Capability::Logind), None);
    assert!(!provides("dinit", Capability::Journald));
    // le monolithe n'est pas catalogué comme sa propre alternative
    for cap in Capability::ALL {
        assert!(!provides("systemd", cap));
        assert_eq!(support_level("systemd", cap), None);
    }
}

// ---------------------------------------------------------------------------
// 4. Abstraction de dépendances par capacité
// ---------------------------------------------------------------------------

#[test]
fn systemd_monolith_abstracts_to_all_capabilities() {
    let caps = abstract_dependency("systemd");
    assert_eq!(caps, Capability::ALL.to_vec());
    assert_eq!(caps.len(), 6);
    assert!(caps.contains(&Capability::ServiceManagement)); // « un init »
    assert!(caps.contains(&Capability::Logind)); // « un logind »
    assert!(caps.contains(&Capability::CgroupScopeSliceApi));
    // tolérant aux espaces
    assert_eq!(abstract_dependency("  systemd  "), caps);
}

#[test]
fn systemd_components_abstract_to_their_single_capability() {
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
    assert_eq!(
        abstract_dependency(" systemd-logind "),
        vec![Capability::Logind]
    );
    // composant sans capacité cataloguée → dep concrète
    assert_eq!(
        abstract_dependency("systemd-unknown"),
        Vec::<Capability>::new()
    );
}

#[test]
fn capability_names_work_as_virtual_deps() {
    assert_eq!(abstract_dependency("logind"), vec![Capability::Logind]);
    assert_eq!(
        abstract_dependency("service-management"),
        vec![Capability::ServiceManagement]
    );
    assert_eq!(
        abstract_dependency("init"),
        vec![Capability::ServiceManagement]
    );
    assert_eq!(abstract_dependency("journald"), vec![Capability::Journald]);
    assert_eq!(abstract_dependency("networkd"), vec![Capability::Networkd]);
    assert_eq!(abstract_dependency("resolved"), vec![Capability::Resolved]);
    assert_eq!(
        abstract_dependency("cgroup-scope-slice-api"),
        vec![Capability::CgroupScopeSliceApi]
    );
}

#[test]
fn implementations_abstract_to_their_capability() {
    // les alternatives sont interchangeables : une dep sur une implémentation
    // s'abstrait vers sa capacité
    assert_eq!(abstract_dependency("elogind"), vec![Capability::Logind]);
    assert_eq!(abstract_dependency("LoginKit"), vec![Capability::Logind]);
    for init in ["dinit", "OpenRC", "runit", "s6"] {
        assert_eq!(
            abstract_dependency(init),
            vec![Capability::ServiceManagement]
        );
    }
    for syslog in ["rsyslog", "syslog-ng"] {
        assert_eq!(abstract_dependency(syslog), vec![Capability::Journald]);
    }
    for net in ["NetworkManager", "connman"] {
        assert_eq!(abstract_dependency(net), vec![Capability::Networkd]);
    }
    for dns in ["dnsmasq", "unbound"] {
        assert_eq!(abstract_dependency(dns), vec![Capability::Resolved]);
    }
}

#[test]
fn unknown_dep_abstracts_to_empty_vector() {
    assert_eq!(abstract_dependency("firefox"), Vec::<Capability>::new());
    assert_eq!(abstract_dependency(""), Vec::<Capability>::new());
    assert_eq!(abstract_dependency("   "), Vec::<Capability>::new());
    assert_eq!(abstract_dependency("libsystemd"), Vec::<Capability>::new());
    // sensible à la casse : « SYSTEMD » n'est pas le monolithe
    assert_eq!(abstract_dependency("SYSTEMD"), Vec::<Capability>::new());
    assert_eq!(abstract_dependency("Logind"), Vec::<Capability>::new());
}

// ---------------------------------------------------------------------------
// 5. Satisfaction, conjonction et conflits
// ---------------------------------------------------------------------------

#[test]
fn init_capability_satisfied_by_any_catalogued_init() {
    for init in ["dinit", "OpenRC", "runit", "s6"] {
        assert!(provides(init, Capability::ServiceManagement));
        assert!(capability_satisfied(Capability::ServiceManagement, &[init]));
        assert!(is_satisfied("init", &[init]));
        assert!(!is_satisfied("systemd", &[init]));
        // « un init » ne suffit pas pour le monolithe, mais la capacité init
        // est bien couverte
        assert!(!missing_capabilities("systemd", &[init]).contains(&Capability::ServiceManagement));
    }
}

#[test]
fn empty_installed_set_satisfies_no_abstract_dep() {
    assert!(!is_satisfied("systemd", &[]));
    assert!(!is_satisfied("logind", &[]));
    assert!(!is_satisfied("init", &[]));
    assert!(!is_satisfied("cgroup-scope-slice-api", &[]));
    assert_eq!(
        missing_capabilities("systemd", &[]),
        Capability::ALL.to_vec()
    );
    // dep inconnue : rien d'installé → non satisfaite
    assert!(!is_satisfied("firefox", &[]));
}

#[test]
fn conjunction_conflict_full_alternative_stack_still_needs_cgroup_shim() {
    // cas snapd : toutes les alternatives installées, mais l'API cgroup
    // n'a aucune alternative → la dep systemd reste insatisfaite
    let installed = ["dinit", "elogind", "rsyslog", "NetworkManager", "dnsmasq"];
    assert!(!is_satisfied("systemd", &installed));
    assert_eq!(
        missing_capabilities("systemd", &installed),
        vec![Capability::CgroupScopeSliceApi]
    );
    assert!(!capability_satisfied(
        Capability::CgroupScopeSliceApi,
        &installed
    ));
    // même avec TOUTES les alternatives du catalogue installées
    let everything: Vec<&str> = Capability::ALL
        .iter()
        .flat_map(|cap| cap.alternatives().iter().map(|alt| alt.name))
        .collect();
    assert!(!capability_satisfied(
        Capability::CgroupScopeSliceApi,
        &everything
    ));
    assert!(!is_satisfied("systemd", &everything));
    assert!(!is_satisfied("cgroup-scope-slice-api", &everything));
    assert_eq!(
        missing_capabilities("systemd", &everything),
        vec![Capability::CgroupScopeSliceApi]
    );
}

#[test]
fn missing_capabilities_reports_exact_gaps_in_order() {
    // dinit seul : il manque les 5 autres capacités, dans l'ordre du catalogue
    assert_eq!(
        missing_capabilities("systemd", &["dinit"]),
        vec![
            Capability::Logind,
            Capability::Journald,
            Capability::Networkd,
            Capability::Resolved,
            Capability::CgroupScopeSliceApi,
        ]
    );
    // dinit + elogind : il en manque 4
    assert_eq!(
        missing_capabilities("systemd", &["dinit", "elogind"]),
        vec![
            Capability::Journald,
            Capability::Networkd,
            Capability::Resolved,
            Capability::CgroupScopeSliceApi,
        ]
    );
    // dep entièrement satisfaite → aucun manque
    assert_eq!(
        missing_capabilities("logind", &["elogind"]),
        Vec::<Capability>::new()
    );
    assert_eq!(
        missing_capabilities("init", &["s6"]),
        Vec::<Capability>::new()
    );
    // dep inconnue : pas de capacités, donc pas de manque signalé
    assert_eq!(
        missing_capabilities("firefox", &[]),
        Vec::<Capability>::new()
    );
}

#[test]
fn not_tested_provides_but_stays_flagged() {
    // `LoginKit` fournit logind mais reste signalé comme non évalué
    assert_eq!(
        support_level("LoginKit", Capability::Logind),
        Some(SupportLevel::NotTested)
    );
    assert!(SupportLevel::NotTested.is_usable());
    assert!(capability_satisfied(Capability::Logind, &["LoginKit"]));
    assert!(is_satisfied("systemd-logind", &["LoginKit"]));
    assert!(is_satisfied("logind", &["LoginKit"]));
    assert!(is_satisfied("elogind", &["LoginKit"]));
}

#[test]
fn modified_level_satisfies_journald() {
    assert!(capability_satisfied(Capability::Journald, &["rsyslog"]));
    assert!(capability_satisfied(Capability::Journald, &["syslog-ng"]));
    assert!(is_satisfied("systemd-journald", &["rsyslog"]));
    assert!(is_satisfied("journald", &["syslog-ng"]));
    assert!(is_satisfied("rsyslog", &["syslog-ng"]));
}

#[test]
fn cross_capability_conflict_does_not_satisfy() {
    // un paquet d'une autre capacité ne satisfait pas la dep
    assert!(!is_satisfied("elogind", &["dinit"]));
    assert!(!is_satisfied("logind", &["rsyslog"]));
    assert!(!is_satisfied("init", &["elogind"]));
    assert!(!is_satisfied("systemd-logind", &["NetworkManager"]));
    assert!(!is_satisfied("networkd", &["dnsmasq"]));
    assert!(!capability_satisfied(Capability::Logind, &["dinit"]));
}

#[test]
fn alternatives_are_interchangeable_within_a_capability() {
    // propriété sur toute la map : une dep sur une alternative est satisfaite
    // par n'importe quelle alternative utilisable de la même capacité
    for cap in Capability::ALL {
        for provider in cap.alternatives() {
            for installed in cap.alternatives() {
                if installed.level.is_usable() {
                    assert!(
                        is_satisfied(provider.name, &[installed.name]),
                        "{provider} devrait être satisfait par {installed} ({cap})",
                        provider = provider.name,
                        installed = installed.name,
                        cap = cap.id()
                    );
                }
            }
        }
    }
}

#[test]
fn multiple_providers_of_same_capability_are_a_disjunction() {
    // plusieurs inits installés : la capacité est satisfaite (disjonction),
    // pas de conflit bloquant
    assert!(is_satisfied("init", &["dinit", "OpenRC", "runit", "s6"]));
    assert!(is_satisfied("logind", &["elogind", "LoginKit"]));
    assert!(is_satisfied("journald", &["rsyslog", "syslog-ng"]));
    assert!(capability_satisfied(
        Capability::ServiceManagement,
        &["OpenRC", "s6"]
    ));
}

#[test]
fn unknown_dep_stays_concrete_and_exact() {
    // dep inconnue du catalogue : satisfaite seulement si le paquet exact
    // est installé
    assert!(is_satisfied("firefox", &["firefox"]));
    assert!(!is_satisfied("firefox", &["dinit"]));
    assert!(!is_satisfied("firefox", &["firefox-esr"]));
    // tolérant aux espaces côté dep
    assert!(is_satisfied("  firefox  ", &["firefox"]));
    // mais les noms installés sont comparés exactement (pas de trim)
    assert!(!is_satisfied("firefox", &["  firefox  "]));
    // une dep inconnue qui ressemble à une capacité mais avec la mauvaise
    // casse reste concrète : « Logind » n'est pas le paquet virtuel logind
    assert!(!is_satisfied("Logind", &["elogind"]));
    assert!(is_satisfied("Logind", &["Logind"]));
}

#[test]
fn scenario_snapd_style_dep_requires_shim_report() {
    // scénario resolver : une dep « systemd » sur un système à alternatives
    // complètes doit signaler exactement le shim manquant (API cgroup),
    // et une dep directe sur l'API cgroup ne peut être satisfaite par rien
    let stack = ["s6", "elogind", "syslog-ng", "connman", "unbound"];
    assert!(!is_satisfied("systemd", &stack));
    let missing = missing_capabilities("systemd", &stack);
    assert_eq!(missing, vec![Capability::CgroupScopeSliceApi]);
    assert!(missing.iter().all(|&cap| needs_shim(cap)));
    // le shim est la seule pièce manquante : toutes les autres capacités
    // sont couvertes par cette pile
    for cap in Capability::ALL {
        if cap != Capability::CgroupScopeSliceApi {
            assert!(capability_satisfied(cap, &stack));
        }
    }
}
