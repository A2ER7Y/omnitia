//! Stream 2 — résolution de dépendances PAR CAPACITÉ (pas logiciel figé).
//!
//! Ce module adapte le catalogue d'[`abstraction`] au resolver d'omni : une
//! dépendance abstraite (ex. `init`, `logind`, `systemd-logind`, `elogind`) est
//! résolue vers un **paquet concret disponible** choisi parmi les alternatives
//! de chaque capacité, en respectant les niveaux de support.
//!
//! Philosophie (héritée d'`abstraction`) :
//! - `Depends: systemd` n'exige pas le monolithe mais un ensemble de capacités
//!   (« un init », « un logind », …). Toute alternative utilisable satisfait.
//! - Une dépendance est résolue si **toutes** ses capacités le sont (conjonction).
//! - `NotSupported` ne satisfait jamais ; `NotTested` fournit mais reste signalé
//!   (warning) ; `Modified` fournit moyennant adaptation (warning).
//! - Une dépendance inconnue du catalogue reste **concrète** : elle n'est résolue
//!   que si le paquet exact est installé ou disponible.
//!
//! Pont avec les types omni :
//! - entrée : [`Dependency`] (`crate::resolver`), dont `name` et `conflicts` ;
//! - état : [`InstalledPackage`] (`crate::types`) pour les paquets installés et
//!   le catalogue des paquets disponibles (fixtures, aucun accès système réel).
//!
//! Politique de choix d'une alternative (déterministe) :
//! 1. niveau de support utilisable (`Native` > `Modified` > `NotTested`) ;
//! 2. à niveau égal, préférer un paquet **déjà installé** (éviter une installation) ;
//! 3. à égalité, ordre du catalogue (stable).
//!
//! Les noms de paquets sont sensibles à la casse (`OpenRC`, `NetworkManager`,
//! `LoginKit`), comme dans `abstraction`.

use crate::abstraction::{self, Alternative, Capability, SupportLevel};
use crate::resolver::Dependency;
use crate::types::InstalledPackage;
use std::collections::HashMap;
use std::fmt;

/// Erreur typée de résolution par capacité.
///
/// Chaque variante identifie précisément pourquoi une dépendance n'a pas pu être
/// résolue vers un paquet concret, afin que l'appelant (CLI, resolver omni)
/// puisse réagir de façon ciblée (construire un shim, proposer une alternative,
/// signaler un conflit, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionError {
    /// Le nom demandé n'est pas une capacité du catalogue (ni un identifiant,
    /// ni l'alias `init`). Levée par [`CapabilityResolver::resolve_capability`].
    UnknownCapability {
        /// Identifiant de capacité inconnu.
        name: String,
    },
    /// La capacité existe mais n'a **aucune** alternative cataloguée : il faut
    /// construire un shim (cas snapd : API D-Bus cgroup/scope/slice).
    NeedsShim {
        /// Capacité sans alternative.
        capability: Capability,
    },
    /// La capacité a des alternatives utilisables mais **aucune** n'est installée
    /// ni disponible dans le catalogue fourni.
    NoAlternativeAvailable {
        /// Capacité non satisfaite faute de paquet disponible.
        capability: Capability,
    },
    /// Conflit déclaré via `Dependency.conflicts` : soit un paquet installé est
    /// en conflit, soit tous les candidats utilisables sont exclus par conflit.
    Conflict {
        /// Nom de la dépendance en conflit.
        dependency: String,
        /// Paquets installés en conflit, ou candidats exclus par le conflit.
        packages: Vec<String>,
    },
    /// Dépendance concrète (inconnue du catalogue de capacités) dont le paquet
    /// exact n'est ni installé ni disponible.
    ConcreteNotAvailable {
        /// Nom du paquet concret introuvable.
        name: String,
    },
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCapability { name } => {
                write!(f, "capacité inconnue du catalogue : '{name}'")
            }
            Self::NeedsShim { capability } => write!(
                f,
                "capacité '{}' sans alternative : un shim est à construire ({})",
                capability.id(),
                capability.description()
            ),
            Self::NoAlternativeAvailable { capability } => write!(
                f,
                "aucune alternative disponible pour la capacité '{}'",
                capability.id()
            ),
            Self::Conflict {
                dependency,
                packages,
            } => write!(
                f,
                "conflit pour la dépendance '{dependency}' avec : {}",
                packages.join(", ")
            ),
            Self::ConcreteNotAvailable { name } => {
                write!(f, "paquet concret '{name}' non installé et non disponible")
            }
        }
    }
}

impl std::error::Error for ResolutionError {}

/// Une capacité résolue vers un paquet concret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCapability {
    /// Capacité virtuelle satisfaite.
    pub capability: Capability,
    /// Nom exact du paquet concret choisi (sensible à la casse).
    pub package: String,
    /// Version du paquet (issue des paquets installés ou disponibles).
    pub version: String,
    /// Niveau de support catalogué de l'alternative choisie.
    pub level: SupportLevel,
    /// Vrai si le paquet choisi est déjà installé (aucune installation requise).
    pub already_installed: bool,
}

/// Issue concrète d'une résolution : soit un ensemble de capacités (dep
/// abstraite), soit un paquet exact (dep concrète inconnue du catalogue).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// Dépendance abstraite : une entrée par capacité, toutes satisfaites
    /// (conjonction). L'ordre suit celui d'`abstraction::abstract_dependency`.
    Capabilities(Vec<ResolvedCapability>),
    /// Dépendance concrète : le paquet exact, installé ou disponible.
    Concrete {
        /// Nom exact du paquet concret.
        package: String,
        /// Version du paquet concret.
        version: String,
        /// Vrai si le paquet concret est déjà installé.
        already_installed: bool,
    },
}

/// Résolution complète d'une dépendance, avec les signalements de support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// Nom de la dépendance d'origine (tel que fourni).
    pub dependency: String,
    /// Issue concrète (capacités ou paquet exact).
    pub resolved: Resolved,
    /// Avertissements de support : `NotTested` (non évalué) et `Modified`
    /// (adaptation requise). Vide si tout est `Native` ou concret.
    pub warnings: Vec<String>,
}

/// Résout des dépendances par capacité vers des paquets concrets disponibles.
///
/// L'état est fourni explicitement (fixtures) : `installed` (paquets présents)
/// et `available` (catalogue installable). Aucune commande système n'est
/// exécutée ; le module est pur et déterministe, testable sur fixtures.
pub struct CapabilityResolver {
    installed: Vec<InstalledPackage>,
    available: Vec<InstalledPackage>,
    installed_index: HashMap<String, String>,
    available_index: HashMap<String, String>,
}

impl CapabilityResolver {
    /// Construit un resolver à partir des paquets installés et disponibles.
    ///
    /// Les index nom → version sont construits une fois ; en cas de doublon,
    /// la première occurrence gagne. Un nom présent dans `installed` est
    /// considéré déjà installé même s'il figure aussi dans `available`.
    #[must_use]
    pub fn new(installed: Vec<InstalledPackage>, available: Vec<InstalledPackage>) -> Self {
        let installed_index = index_by_name(&installed);
        let available_index = index_by_name(&available);
        Self {
            installed,
            available,
            installed_index,
            available_index,
        }
    }

    /// Paquets installés fournis au resolver.
    #[must_use]
    pub fn installed(&self) -> &[InstalledPackage] {
        &self.installed
    }

    /// Catalogue des paquets disponibles fourni au resolver.
    #[must_use]
    pub fn available(&self) -> &[InstalledPackage] {
        &self.available
    }

    /// Résout une dépendance omni [`Dependency`] par capacité.
    ///
    /// - Dep abstraite (`systemd`, `init`, `logind`, `elogind`, …) : chaque
    ///   capacité est résolue vers une alternative disponible (conjonction).
    /// - Dep inconnue du catalogue : résolution concrète du paquet exact.
    /// - `dep.conflicts` est vérifié contre les paquets installés (sémantique
    ///   omni) et exclut les candidats en conflit.
    ///
    /// # Errors
    ///
    /// [`ResolutionError::Conflict`] si un paquet installé est en conflit ou si
    /// tous les candidats sont exclus ; [`ResolutionError::NeedsShim`] si une
    /// capacité n'a aucune alternative ; [`ResolutionError::NoAlternativeAvailable`]
    /// si aucune alternative utilisable n'est disponible ;
    /// [`ResolutionError::ConcreteNotAvailable`] si une dep concrète est introuvable.
    pub fn resolve_dependency(&self, dep: &Dependency) -> Result<Resolution, ResolutionError> {
        // Conflit avec un paquet installé : même sémantique que le resolver omni
        // (check_conflicts), vérifié avant toute résolution.
        let installed_conflicts: Vec<String> = dep
            .conflicts
            .iter()
            .filter(|c| self.installed_index.contains_key(c.as_str()))
            .cloned()
            .collect();
        if !installed_conflicts.is_empty() {
            return Err(ResolutionError::Conflict {
                dependency: dep.name.clone(),
                packages: installed_conflicts,
            });
        }

        let caps = abstraction::abstract_dependency(&dep.name);
        if caps.is_empty() {
            return self.resolve_concrete(dep);
        }

        let mut resolved = Vec::with_capacity(caps.len());
        let mut warnings = Vec::new();
        for cap in caps {
            let rc = self.resolve_capability_inner(cap, &dep.name, &dep.conflicts)?;
            if let Some(w) = support_warning(&rc) {
                warnings.push(w);
            }
            resolved.push(rc);
        }
        Ok(Resolution {
            dependency: dep.name.clone(),
            resolved: Resolved::Capabilities(resolved),
            warnings,
        })
    }

    /// Résout un identifiant de capacité (`logind`, `init`, `service-management`, …)
    /// vers un paquet concret disponible.
    ///
    /// Contrairement à [`Self::resolve_dependency`], cette entrée est **stricte** :
    /// seul un identifiant de capacité (ou l'alias `init`) est accepté. Un nom
    /// d'implémentation (`elogind`) ou un paquet inconnu doit passer par
    /// `resolve_dependency`.
    ///
    /// # Errors
    ///
    /// [`ResolutionError::UnknownCapability`] si l'identifiant n'est pas une
    /// capacité du catalogue ; [`ResolutionError::NeedsShim`] /
    /// [`ResolutionError::NoAlternativeAvailable`] si la capacité ne peut être
    /// satisfaite par un paquet disponible.
    pub fn resolve_capability(&self, id: &str) -> Result<Resolution, ResolutionError> {
        let cap = Capability::from_id(id).ok_or_else(|| ResolutionError::UnknownCapability {
            name: id.trim().to_string(),
        })?;
        let rc = self.resolve_capability_inner(cap, id, &[])?;
        let warnings = support_warning(&rc).into_iter().collect();
        Ok(Resolution {
            dependency: id.to_string(),
            resolved: Resolved::Capabilities(vec![rc]),
            warnings,
        })
    }

    /// Résout une liste de dépendances ; s'arrête à la première erreur typée.
    ///
    /// # Errors
    ///
    /// La première [`ResolutionError`] rencontrée (voir [`Self::resolve_dependency`]).
    pub fn resolve_all(&self, deps: &[Dependency]) -> Result<Vec<Resolution>, ResolutionError> {
        deps.iter()
            .map(|dep| self.resolve_dependency(dep))
            .collect()
    }

    /// Résolution concrète d'une dépendance inconnue du catalogue de capacités.
    fn resolve_concrete(&self, dep: &Dependency) -> Result<Resolution, ResolutionError> {
        let name = dep.name.trim();
        if dep.conflicts.iter().any(|c| c.as_str() == name) {
            return Err(ResolutionError::Conflict {
                dependency: dep.name.clone(),
                packages: vec![name.to_string()],
            });
        }
        match self.lookup(name) {
            Some((version, already_installed)) => Ok(Resolution {
                dependency: dep.name.clone(),
                resolved: Resolved::Concrete {
                    package: name.to_string(),
                    version,
                    already_installed,
                },
                warnings: Vec::new(),
            }),
            None => Err(ResolutionError::ConcreteNotAvailable {
                name: name.to_string(),
            }),
        }
    }

    /// Choisit une alternative disponible pour `cap`, en respectant le support
    /// et les conflits. Cœur de la résolution par capacité.
    fn resolve_capability_inner(
        &self,
        cap: Capability,
        dep_name: &str,
        conflicts: &[String],
    ) -> Result<ResolvedCapability, ResolutionError> {
        let alternatives = cap.alternatives();
        if alternatives.is_empty() {
            return Err(ResolutionError::NeedsShim { capability: cap });
        }

        // Alternatives utilisables (niveau de support), avant exclusion par conflit.
        let usable_level: Vec<&Alternative> = alternatives
            .iter()
            .filter(|alt| alt.level.is_usable())
            .collect();
        if usable_level.is_empty() {
            return Err(ResolutionError::NoAlternativeAvailable { capability: cap });
        }

        // Candidats utilisables ET non conflictuels, avec leur index catalogue.
        let candidates: Vec<(usize, &Alternative)> = alternatives
            .iter()
            .enumerate()
            .filter(|(_, alt)| {
                alt.level.is_usable() && !conflicts.iter().any(|c| c.as_str() == alt.name)
            })
            .collect();
        if candidates.is_empty() {
            // Tous les candidats utilisables sont exclus par un conflit déclaré.
            return Err(ResolutionError::Conflict {
                dependency: dep_name.to_string(),
                packages: usable_level
                    .iter()
                    .map(|alt| alt.name.to_string())
                    .collect(),
            });
        }

        // Parmi les candidats, ne garder que ceux installés ou disponibles.
        let mut available: Vec<Candidate<'_>> = Vec::new();
        for (index, alt) in candidates {
            if let Some((version, installed)) = self.lookup(alt.name) {
                available.push(Candidate {
                    alt,
                    version,
                    installed,
                    index,
                });
            }
        }

        // Choix déterministe : support d'abord, puis déjà installé, puis catalogue.
        let chosen = available
            .into_iter()
            .min_by_key(|c| (support_rank(c.alt.level), u8::from(!c.installed), c.index));
        match chosen {
            Some(c) => Ok(ResolvedCapability {
                capability: cap,
                package: c.alt.name.to_string(),
                version: c.version,
                level: c.alt.level,
                already_installed: c.installed,
            }),
            None => Err(ResolutionError::NoAlternativeAvailable { capability: cap }),
        }
    }

    /// Version et statut d'installation d'un paquet : installé en priorité,
    /// sinon disponible au catalogue. `None` si le paquet est inconnu des deux.
    fn lookup(&self, name: &str) -> Option<(String, bool)> {
        self.installed_index
            .get(name)
            .map(|version| (version.clone(), true))
            .or_else(|| {
                self.available_index
                    .get(name)
                    .map(|version| (version.clone(), false))
            })
    }
}

/// Candidat disponible interne (alternative + version + statut + index catalogue).
struct Candidate<'a> {
    alt: &'a Alternative,
    version: String,
    installed: bool,
    index: usize,
}

/// Construit un index nom → version (première occurrence gagne).
fn index_by_name(packages: &[InstalledPackage]) -> HashMap<String, String> {
    let mut index = HashMap::new();
    for pkg in packages {
        index
            .entry(pkg.name.clone())
            .or_insert_with(|| pkg.version.clone());
    }
    index
}

/// Rang d'un niveau de support pour le choix (plus petit = préféré).
/// `NotSupported` est exclu en amont ; son rang est le plus défavorable.
const fn support_rank(level: SupportLevel) -> u8 {
    match level {
        SupportLevel::Native => 0,
        SupportLevel::Modified => 1,
        SupportLevel::NotTested => 2,
        SupportLevel::NotSupported => 3,
    }
}

/// Avertissement de support pour une capacité résolue, le cas échéant.
/// `NotTested` → non évalué ; `Modified` → adaptation requise ; sinon `None`.
fn support_warning(rc: &ResolvedCapability) -> Option<String> {
    match rc.level {
        SupportLevel::NotTested => Some(format!(
            "capacité '{}' fournie par '{}' (not-tested) : support non évalué",
            rc.capability.id(),
            rc.package
        )),
        SupportLevel::Modified => Some(format!(
            "capacité '{}' fournie par '{}' (modified) : adaptation requise",
            rc.capability.id(),
            rc.package
        )),
        SupportLevel::Native | SupportLevel::NotSupported => None,
    }
}

/// Filtre les alternatives **utilisables** (niveau de support) et **non
/// conflictuelles**. Expose la règle de support pour tests sur fixtures :
/// `NotSupported` est toujours exclu, même si le paquet est installé.
///
/// `conflicts` contient des noms de paquets exclus (sémantique `Dependency.conflicts`).
#[must_use]
pub fn usable_alternatives<'a>(
    alternatives: &'a [Alternative],
    conflicts: &[String],
) -> Vec<&'a Alternative> {
    alternatives
        .iter()
        .filter(|alt| alt.level.is_usable())
        .filter(|alt| !conflicts.iter().any(|c| c.as_str() == alt.name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture : paquet installé/d disponible avec nom + version.
    fn pkg(name: &str, version: &str) -> InstalledPackage {
        InstalledPackage::new(name.to_string(), version.to_string())
    }

    /// Fixture : dépendance omni minimale (non optionnelle, sans conflit).
    fn dep(name: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version_req: None,
            box_type: "apt".to_string(),
            optional: false,
            conflicts: vec![],
            provides: vec![],
        }
    }

    /// Fixture : dépendance avec conflits déclarés.
    fn dep_with_conflicts(name: &str, conflicts: &[&str]) -> Dependency {
        Dependency {
            conflicts: conflicts.iter().map(|c| (*c).to_string()).collect(),
            ..dep(name)
        }
    }

    /// Extrait l'unique capacité résolue (panique si concrete/multiple).
    fn single(res: &Resolution) -> &ResolvedCapability {
        match &res.resolved {
            Resolved::Capabilities(caps) => {
                assert_eq!(caps.len(), 1, "attendu une seule capacité");
                &caps[0]
            }
            Resolved::Concrete { .. } => panic!("attendu une résolution par capacité"),
        }
    }

    // --- Résolution capacité → paquet concret -------------------------------

    #[test]
    fn init_resolves_to_available_dinit() {
        let resolver = CapabilityResolver::new(vec![], vec![pkg("dinit", "0.18")]);
        let res = resolver.resolve_dependency(&dep("init")).unwrap();
        let rc = single(&res);
        assert_eq!(rc.capability, Capability::ServiceManagement);
        assert_eq!(rc.package, "dinit");
        assert_eq!(rc.version, "0.18");
        assert_eq!(rc.level, SupportLevel::Native);
        assert!(!rc.already_installed);
        assert_eq!(res.warnings, Vec::<String>::new());
    }

    #[test]
    fn logind_resolves_to_installed_elogind() {
        let resolver = CapabilityResolver::new(vec![pkg("elogind", "243.7")], vec![]);
        let res = resolver.resolve_dependency(&dep("logind")).unwrap();
        let rc = single(&res);
        assert_eq!(rc.capability, Capability::Logind);
        assert_eq!(rc.package, "elogind");
        assert_eq!(rc.version, "243.7");
        assert!(rc.already_installed);
    }

    #[test]
    fn capability_id_entry_point_resolves() {
        let resolver = CapabilityResolver::new(vec![], vec![pkg("runit", "2.1")]);
        let res = resolver.resolve_capability("init").unwrap();
        assert_eq!(single(&res).package, "runit");
        let res = resolver.resolve_capability("service-management").unwrap();
        assert_eq!(single(&res).package, "runit");
    }

    #[test]
    fn implementation_dep_is_interchangeable() {
        // Une dep sur elogind s'abstrait vers logind : LoginKit (installé) satisfait.
        let resolver = CapabilityResolver::new(vec![pkg("LoginKit", "0.1")], vec![]);
        let res = resolver.resolve_dependency(&dep("elogind")).unwrap();
        let rc = single(&res);
        assert_eq!(rc.capability, Capability::Logind);
        assert_eq!(rc.package, "LoginKit");
        assert_eq!(rc.level, SupportLevel::NotTested);
        // NotTested fournit mais reste signalé.
        assert_eq!(res.warnings.len(), 1);
        assert!(res.warnings[0].contains("not-tested"));
    }

    #[test]
    fn systemd_component_resolves_to_its_capability() {
        let resolver = CapabilityResolver::new(vec![], vec![pkg("NetworkManager", "1.4")]);
        let res = resolver
            .resolve_dependency(&dep("systemd-networkd"))
            .unwrap();
        let rc = single(&res);
        assert_eq!(rc.capability, Capability::Networkd);
        assert_eq!(rc.package, "NetworkManager");
    }

    #[test]
    fn modified_support_resolves_with_warning() {
        let resolver = CapabilityResolver::new(vec![], vec![pkg("rsyslog", "8.0")]);
        let res = resolver.resolve_dependency(&dep("journald")).unwrap();
        let rc = single(&res);
        assert_eq!(rc.package, "rsyslog");
        assert_eq!(rc.level, SupportLevel::Modified);
        assert_eq!(res.warnings.len(), 1);
        assert!(res.warnings[0].contains("modified"));
    }

    // --- Politique de choix : support, puis installé, puis catalogue --------

    #[test]
    fn native_preferred_over_not_tested() {
        // elogind (Native) et LoginKit (NotTested) disponibles → elogind gagne.
        let resolver = CapabilityResolver::new(
            vec![],
            vec![pkg("LoginKit", "0.1"), pkg("elogind", "243.7")],
        );
        let res = resolver.resolve_dependency(&dep("logind")).unwrap();
        assert_eq!(single(&res).package, "elogind");
        assert_eq!(res.warnings, Vec::<String>::new());
    }

    #[test]
    fn support_level_beats_already_installed() {
        // LoginKit installé (NotTested) mais elogind disponible (Native) → elogind.
        let resolver =
            CapabilityResolver::new(vec![pkg("LoginKit", "0.1")], vec![pkg("elogind", "243.7")]);
        let res = resolver.resolve_dependency(&dep("logind")).unwrap();
        let rc = single(&res);
        assert_eq!(rc.package, "elogind");
        assert!(!rc.already_installed);
    }

    #[test]
    fn installed_preferred_at_equal_support() {
        // Tous les inits sont Native ; OpenRC installé → préféré à dinit disponible.
        let resolver = CapabilityResolver::new(
            vec![pkg("OpenRC", "0.5")],
            vec![pkg("dinit", "0.18"), pkg("OpenRC", "0.5")],
        );
        let res = resolver.resolve_dependency(&dep("init")).unwrap();
        let rc = single(&res);
        assert_eq!(rc.package, "OpenRC");
        assert!(rc.already_installed);
    }

    #[test]
    fn catalog_order_breaks_ties() {
        // dinit et OpenRC disponibles, aucun installé → ordre catalogue (dinit).
        let resolver =
            CapabilityResolver::new(vec![], vec![pkg("dinit", "0.18"), pkg("OpenRC", "0.5")]);
        let res = resolver.resolve_dependency(&dep("init")).unwrap();
        assert_eq!(single(&res).package, "dinit");
    }

    #[test]
    fn case_sensitive_package_names() {
        // "openrc" (minuscule) n'est pas l'alternative cataloguée "OpenRC".
        let resolver = CapabilityResolver::new(vec![], vec![pkg("openrc", "0.5")]);
        let err = resolver.resolve_dependency(&dep("init")).unwrap_err();
        assert_eq!(
            err,
            ResolutionError::NoAlternativeAvailable {
                capability: Capability::ServiceManagement
            }
        );
    }

    // --- Capacité inconnue → erreur typée -----------------------------------

    #[test]
    fn unknown_capability_id_is_typed_error() {
        let resolver = CapabilityResolver::new(vec![], vec![pkg("dinit", "0.18")]);
        let err = resolver.resolve_capability("inexistant").unwrap_err();
        assert_eq!(
            err,
            ResolutionError::UnknownCapability {
                name: "inexistant".to_string()
            }
        );
        // L'alias vide / inconnu est aussi rejeté.
        assert!(matches!(
            resolver.resolve_capability("").unwrap_err(),
            ResolutionError::UnknownCapability { .. }
        ));
        // Un nom d'implémentation n'est pas un identifiant de capacité.
        assert!(matches!(
            resolver.resolve_capability("elogind").unwrap_err(),
            ResolutionError::UnknownCapability { .. }
        ));
    }

    #[test]
    fn unknown_dep_stays_concrete_then_typed_error_if_absent() {
        let resolver = CapabilityResolver::new(vec![], vec![]);
        // Inconnu du catalogue → concret ; absent → erreur typée dédiée.
        let err = resolver.resolve_dependency(&dep("firefox")).unwrap_err();
        assert_eq!(
            err,
            ResolutionError::ConcreteNotAvailable {
                name: "firefox".to_string()
            }
        );
    }

    #[test]
    fn unknown_dep_concrete_resolves_when_present() {
        let resolver = CapabilityResolver::new(vec![pkg("firefox", "120")], vec![]);
        let res = resolver.resolve_dependency(&dep("firefox")).unwrap();
        match res.resolved {
            Resolved::Concrete {
                package,
                version,
                already_installed,
            } => {
                assert_eq!(package, "firefox");
                assert_eq!(version, "120");
                assert!(already_installed);
            }
            Resolved::Capabilities(_) => panic!("attendu une résolution concrète"),
        }
        assert_eq!(res.warnings, Vec::<String>::new());
    }

    // --- Conflits -----------------------------------------------------------

    #[test]
    fn conflict_with_installed_package_is_typed_error() {
        // Sémantique omni : dep.conflicts contre un paquet installé → conflit.
        let resolver = CapabilityResolver::new(vec![pkg("elogind", "243.7")], vec![]);
        let err = resolver
            .resolve_dependency(&dep_with_conflicts("logind", &["elogind"]))
            .unwrap_err();
        assert_eq!(
            err,
            ResolutionError::Conflict {
                dependency: "logind".to_string(),
                packages: vec!["elogind".to_string()],
            }
        );
    }

    #[test]
    fn conflict_excludes_candidate_and_picks_another() {
        // dinit exclu par conflit → OpenRC (même capacité, Native) est choisi.
        let resolver =
            CapabilityResolver::new(vec![], vec![pkg("dinit", "0.18"), pkg("OpenRC", "0.5")]);
        let res = resolver
            .resolve_dependency(&dep_with_conflicts("init", &["dinit"]))
            .unwrap();
        assert_eq!(single(&res).package, "OpenRC");
    }

    #[test]
    fn conflict_excluding_all_candidates_is_typed_error() {
        let resolver = CapabilityResolver::new(
            vec![],
            vec![pkg("elogind", "243.7"), pkg("LoginKit", "0.1")],
        );
        let err = resolver
            .resolve_dependency(&dep_with_conflicts("logind", &["elogind", "LoginKit"]))
            .unwrap_err();
        assert_eq!(
            err,
            ResolutionError::Conflict {
                dependency: "logind".to_string(),
                packages: vec!["elogind".to_string(), "LoginKit".to_string()],
            }
        );
    }

    #[test]
    fn concrete_dep_conflict_is_typed_error() {
        let resolver = CapabilityResolver::new(vec![], vec![pkg("firefox", "120")]);
        let err = resolver
            .resolve_dependency(&dep_with_conflicts("firefox", &["firefox"]))
            .unwrap_err();
        assert_eq!(
            err,
            ResolutionError::Conflict {
                dependency: "firefox".to_string(),
                packages: vec!["firefox".to_string()],
            }
        );
    }

    // --- Shim / absence d'alternative ---------------------------------------

    #[test]
    fn cgroup_api_needs_shim() {
        let resolver = CapabilityResolver::new(vec![], vec![pkg("dinit", "0.18")]);
        let err = resolver
            .resolve_capability("cgroup-scope-slice-api")
            .unwrap_err();
        assert_eq!(
            err,
            ResolutionError::NeedsShim {
                capability: Capability::CgroupScopeSliceApi
            }
        );
    }

    #[test]
    fn full_systemd_dep_needs_shim_for_cgroup() {
        // Toutes les alternatives disponibles, mais l'API cgroup reste à faire.
        let resolver = CapabilityResolver::new(
            vec![],
            vec![
                pkg("dinit", "0.18"),
                pkg("elogind", "243.7"),
                pkg("rsyslog", "8.0"),
                pkg("NetworkManager", "1.4"),
                pkg("dnsmasq", "2.9"),
            ],
        );
        let err = resolver.resolve_dependency(&dep("systemd")).unwrap_err();
        assert_eq!(
            err,
            ResolutionError::NeedsShim {
                capability: Capability::CgroupScopeSliceApi
            }
        );
    }

    #[test]
    fn no_available_alternative_is_typed_error() {
        let resolver = CapabilityResolver::new(vec![], vec![pkg("firefox", "120")]);
        let err = resolver.resolve_dependency(&dep("logind")).unwrap_err();
        assert_eq!(
            err,
            ResolutionError::NoAlternativeAvailable {
                capability: Capability::Logind
            }
        );
    }

    // --- Règle de support sur fixtures synthétiques -------------------------

    #[test]
    fn not_supported_alternative_never_usable() {
        // Fixture synthétique incluant un niveau NotSupported (absent du catalogue
        // réel) : il doit être exclu même s'il est le seul « fourni ».
        let alts = [
            Alternative {
                name: "fantome",
                level: SupportLevel::NotSupported,
            },
            Alternative {
                name: "elogind",
                level: SupportLevel::Native,
            },
        ];
        let usable = usable_alternatives(&alts, &[]);
        assert_eq!(usable.len(), 1);
        assert_eq!(usable[0].name, "elogind");

        // Tous NotSupported → aucun candidat utilisable.
        let only_bad = [Alternative {
            name: "fantome",
            level: SupportLevel::NotSupported,
        }];
        assert_eq!(
            usable_alternatives(&only_bad, &[]),
            Vec::<&Alternative>::new()
        );
    }

    #[test]
    fn usable_alternatives_respects_conflicts() {
        let alts = Capability::ServiceManagement.alternatives();
        let conflicts = vec!["dinit".to_string(), "s6".to_string()];
        let usable = usable_alternatives(alts, &conflicts);
        let names: Vec<&str> = usable.iter().map(|alt| alt.name).collect();
        assert_eq!(names, vec!["OpenRC", "runit"]);
    }

    // --- resolve_all / Display / Error --------------------------------------

    #[test]
    fn resolve_all_collects_resolutions() {
        let resolver =
            CapabilityResolver::new(vec![], vec![pkg("dinit", "0.18"), pkg("elogind", "243.7")]);
        let deps = vec![dep("init"), dep("logind")];
        let all = resolver.resolve_all(&deps).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(single(&all[0]).package, "dinit");
        assert_eq!(single(&all[1]).package, "elogind");
    }

    #[test]
    fn resolve_all_stops_at_first_error() {
        let resolver = CapabilityResolver::new(vec![], vec![pkg("dinit", "0.18")]);
        let deps = vec![dep("init"), dep("logind")];
        let err = resolver.resolve_all(&deps).unwrap_err();
        assert_eq!(
            err,
            ResolutionError::NoAlternativeAvailable {
                capability: Capability::Logind
            }
        );
    }

    #[test]
    fn error_display_and_trait() {
        let err = ResolutionError::UnknownCapability {
            name: "foo".to_string(),
        };
        assert!(err.to_string().contains("foo"));
        // Implémente std::error::Error (utilisable avec anyhow/Box<dyn Error>).
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert!(boxed.to_string().contains("capacité inconnue"));

        let shim = ResolutionError::NeedsShim {
            capability: Capability::CgroupScopeSliceApi,
        };
        assert!(shim.to_string().contains("shim"));
    }

    #[test]
    fn accessors_expose_fixtures() {
        let installed = vec![pkg("elogind", "243.7")];
        let available = vec![pkg("dinit", "0.18")];
        let resolver = CapabilityResolver::new(installed.clone(), available.clone());
        assert_eq!(resolver.installed(), installed.as_slice());
        assert_eq!(resolver.available(), available.as_slice());
    }
}
