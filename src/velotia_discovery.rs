//! Stream 3 — intégration découverte : deps implicites d'un paquet → capacités + support.
//!
//! Scan statique des scripts/fichiers d'un paquet (texte fourni en fixture) via
//! [`crate::discovery`], puis mapping de chaque finding vers un contrat de
//! capacité ([`crate::abstraction`]) et son niveau de support.
//!
//! INVARIANT : analyse 100 % statique et lecture seule — le texte analysé
//! n'est JAMAIS exécuté (mêmes garanties que [`crate::discovery::scan_text`]).
//!
//! # Mapping signal → capacité(s)
//!
//! | Signal ([`crate::discovery::Capability`]) | Capacité(s) ([`crate::abstraction::Capability`]) |
//! |---|---|
//! | `LogindDbus` (`org.freedesktop.login1`) | `Logind` |
//! | `SystemdDbus` (`org.freedesktop.systemd1`) | `ServiceManagement` + `CgroupScopeSliceApi` |
//! | `CgroupFs` (écritures `/sys/fs/cgroup`) | `CgroupScopeSliceApi` |
//! | `SystemctlCli` | `ServiceManagement` |
//! | `LoginctlCli` | `Logind` |
//! | `SystemdPid1` | `ServiceManagement` (support `not-supported`, cf. ci-dessous) |
//!
//! Choix assumés (heuristiques, comme la découverte elle-même) :
//! - `SystemdDbus` couvre À LA FOIS les units et l'API cgroup/scope/slice :
//!   la ligne ne permet pas de distinguer `StartUnit` de `StartTransientUnit`,
//!   on sur-approxime (cas snapd : un shim est nécessaire).
//! - `CgroupFs` mappe vers `CgroupScopeSliceApi` : le README traite les écritures
//!   cgroup de snap-confine comme l'exigence de l'API cgroup de systemd, pas
//!   juste « un init ». Aucune alternative cataloguée → shim à construire.
//! - `SystemdPid1` mappe vers `ServiceManagement` mais avec un support
//!   `NotSupported` : un check « systemd est PID 1 » n'est satisfait par AUCUNE
//!   alternative d'init (dinit/OpenRC/… ne sont pas systemd). C'est le signal
//!   le plus difficile à satisfaire avec un autre init.
//!
//! # Niveaux de support
//!
//! Le support d'un finding est le MEILLEUR niveau catalogué parmi les
//! alternatives de la capacité (`native` > `modified` > `not-tested` >
//! `not-supported`) ; `None` = aucune alternative cataloguée → shim requis
//! ([`crate::abstraction::needs_shim`]). Le résumé par capacité retient le
//! niveau le PLUS CONTRAIGNANT de ses findings (l'usage le plus dur gagne).

use std::fmt;
use std::path::Path;

use crate::abstraction::{self, Capability, SupportLevel};
use crate::discovery::{self, Finding};

/// Mappe un signal détecté vers le(s) contrat(s) de capacité qu'il exige.
/// Voir la table de mapping en tête de module pour les choix assumés.
#[must_use]
pub const fn capabilities_for(signal: discovery::Capability) -> &'static [Capability] {
    match signal {
        discovery::Capability::SystemdDbus => &[
            Capability::ServiceManagement,
            Capability::CgroupScopeSliceApi,
        ],
        discovery::Capability::CgroupFs => &[Capability::CgroupScopeSliceApi],
        discovery::Capability::LogindDbus | discovery::Capability::LoginctlCli => {
            &[Capability::Logind]
        }
        // Même contrat ; le support diffère (PID 1 → not-supported), cf. support_for.
        discovery::Capability::SystemctlCli | discovery::Capability::SystemdPid1 => {
            &[Capability::ServiceManagement]
        }
    }
}

/// Classement des niveaux de support (du meilleur au pire).
const fn rank(level: SupportLevel) -> u8 {
    match level {
        SupportLevel::Native => 3,
        SupportLevel::Modified => 2,
        SupportLevel::NotTested => 1,
        SupportLevel::NotSupported => 0,
    }
}

/// Meilleur niveau de support catalogué parmi les alternatives de `cap`.
/// `None` si aucune alternative n'est cataloguée (shim à construire).
#[must_use]
pub fn best_support(cap: Capability) -> Option<SupportLevel> {
    cap.alternatives()
        .iter()
        .map(|alt| alt.level)
        .max_by_key(|&level| rank(level))
}

/// Support effectif d'un finding : meilleur niveau catalogué de la capacité.
///
/// Exception : `SystemdPid1` → `NotSupported` (aucune alternative d'init ne
/// peut passer un check « systemd est PID 1 »). `None` = aucune alternative
/// cataloguée → shim requis.
#[must_use]
pub fn support_for(signal: discovery::Capability, cap: Capability) -> Option<SupportLevel> {
    if signal == discovery::Capability::SystemdPid1 {
        Some(SupportLevel::NotSupported)
    } else {
        best_support(cap)
    }
}

/// Un finding de découverte mappé vers un contrat de capacité, avec sa preuve
/// (ligne + texte) et son niveau de support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedFinding {
    /// Signal détecté par [`crate::discovery::scan_text`].
    pub signal: discovery::Capability,
    /// Contrat de capacité exigé par ce signal.
    pub capability: Capability,
    /// Numéro de ligne dans le texte analysé (commence à 1).
    pub line: usize,
    /// Preuve : la ligne (trimée, tronquée par la découverte).
    pub evidence: String,
    /// Meilleur support catalogué pour cette capacité ; `None` = aucune
    /// alternative → shim à construire (cf. [`Self::needs_shim`]).
    pub support: Option<SupportLevel>,
}

impl MappedFinding {
    /// Vrai si la capacité n'a aucune alternative cataloguée : shim à construire.
    #[must_use]
    pub fn needs_shim(&self) -> bool {
        abstraction::needs_shim(self.capability)
    }
}

/// Résumé par capacité : support le plus contraignant observé, lignes de preuve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    /// Contrat de capacité exigé par le paquet.
    pub capability: Capability,
    /// Niveau le plus contraignant parmi les findings de cette capacité
    /// (`None` = aucune alternative cataloguée → shim requis).
    pub support: Option<SupportLevel>,
    /// Vrai si aucune alternative n'existe : shim à construire (cas snapd).
    pub needs_shim: bool,
    /// Lignes de preuve (triées, dédupliquées).
    pub lines: Vec<usize>,
}

/// Rapport structuré de découverte : findings mappés (capacité, preuve, support)
/// + résumés par capacité, dans l'ordre du catalogue ([`Capability::ALL`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryReport {
    /// Findings mappés, dans l'ordre du scan (ligne, puis ordre des signaux).
    pub findings: Vec<MappedFinding>,
    /// Résumés par capacité exigée (ordre du catalogue).
    pub capabilities: Vec<CapabilityReport>,
}

impl DiscoveryReport {
    /// Vrai si aucune dépendance implicite n'a été détectée.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Vrai si au moins une capacité exigée n'a aucune alternative (shim requis).
    #[must_use]
    pub fn needs_shim(&self) -> bool {
        self.capabilities.iter().any(|c| c.needs_shim)
    }

    /// Capacités exigées par le paquet (ordre du catalogue, dédupliquées).
    #[must_use]
    pub fn required_capabilities(&self) -> Vec<Capability> {
        self.capabilities.iter().map(|c| c.capability).collect()
    }

    /// Signaux détectés, uniques et triés (ordre de l'enum de la découverte).
    #[must_use]
    pub fn signals(&self) -> Vec<discovery::Capability> {
        let mut signals: Vec<discovery::Capability> =
            self.findings.iter().map(|m| m.signal).collect();
        signals.sort();
        signals.dedup();
        signals
    }
}

/// Libellé du support pour les rapports (`None` = shim requis).
fn support_label(support: Option<SupportLevel>) -> &'static str {
    support.map_or("shim requis (aucune alternative)", SupportLevel::as_str)
}

impl fmt::Display for CapabilityReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines: Vec<String> = self.lines.iter().map(ToString::to_string).collect();
        write!(
            f,
            "{} : {} (lignes {})",
            self.capability.id(),
            support_label(self.support),
            lines.join(", ")
        )
    }
}

impl fmt::Display for DiscoveryReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return writeln!(f, "Aucune dépendance implicite détectée.");
        }
        writeln!(
            f,
            "Dépendances implicites (analyse statique, {} preuve(s)) :",
            self.findings.len()
        )?;
        for cap in &self.capabilities {
            writeln!(f, "- {cap}")?;
            for m in self
                .findings
                .iter()
                .filter(|m| m.capability == cap.capability)
            {
                writeln!(f, "  L{} : {}", m.line, m.evidence)?;
            }
        }
        Ok(())
    }
}

/// Analyse un texte (script shell, source C, chaînes d'un binaire…) : scan
/// statique via [`crate::discovery::scan_text`] puis mapping vers les capacités.
/// Le texte n'est jamais interprété ni exécuté.
///
/// ```
/// use omnitia::velotia_discovery::analyze_text;
/// use omnitia::abstraction::Capability;
/// let report = analyze_text("systemctl start snapd");
/// assert_eq!(report.required_capabilities(), vec![Capability::ServiceManagement]);
/// assert!(!report.needs_shim());
/// ```
#[must_use]
pub fn analyze_text(text: &str) -> DiscoveryReport {
    build_report(&discovery::scan_text(text))
}

/// Analyse un fichier SANS l'exécuter (lecture seule, décodage UTF-8 tolérant,
/// cf. [`crate::discovery::scan_file`]) puis mapping vers les capacités.
///
/// # Errors
///
/// Erreur I/O si le fichier est illisible (absent, permissions…).
pub fn analyze_file(path: &Path) -> std::io::Result<DiscoveryReport> {
    let findings = discovery::scan_file(path)?;
    Ok(build_report(&findings))
}

/// Construit le rapport structuré à partir des findings bruts de la découverte.
fn build_report(findings: &[Finding]) -> DiscoveryReport {
    // Chaque finding est expandé vers ses capacités (un signal peut en exiger
    // plusieurs, ex. systemd1 → units + API cgroup).
    let mut mapped: Vec<MappedFinding> = Vec::new();
    for f in findings {
        for &cap in capabilities_for(f.capability) {
            mapped.push(MappedFinding {
                signal: f.capability,
                capability: cap,
                line: f.line,
                evidence: f.evidence.clone(),
                support: support_for(f.capability, cap),
            });
        }
    }
    // Résumés par capacité, dans l'ordre du catalogue ; le support retenu est
    // le plus contraignant (l'usage le plus dur gagne, ex. PID 1).
    let mut capabilities = Vec::new();
    for cap in Capability::ALL {
        let related: Vec<&MappedFinding> = mapped.iter().filter(|m| m.capability == cap).collect();
        if related.is_empty() {
            continue;
        }
        let support = related
            .iter()
            .map(|m| m.support)
            .min_by_key(|s| s.map_or(0, |level| rank(level) + 1))
            .flatten();
        let mut lines: Vec<usize> = related.iter().map(|m| m.line).collect();
        lines.sort_unstable();
        lines.dedup();
        capabilities.push(CapabilityReport {
            capability: cap,
            support,
            needs_shim: abstraction::needs_shim(cap),
            lines,
        });
    }
    DiscoveryReport {
        findings: mapped,
        capabilities,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture « snapd-like » (même script que la découverte) : snap-confine
    /// parle à systemd1 (D-Bus), écrit dans les cgroups et appelle systemctl.
    /// Lignes : 1 shebang, 2 commentaire, 3 set, 4 variable, 5 mkdir cgroup,
    /// 6 echo > cgroup.procs, 7 busctl systemd1, 8 systemctl.
    const SNAPD_LIKE: &str = "\
#!/bin/sh
# snap-confine-like : org.freedesktop.systemd1 (commentaire ignoré)
set -eu
SCOPE=snap.foo.scope
mkdir -p /sys/fs/cgroup/systemd/$SCOPE
echo $$ > /sys/fs/cgroup/systemd/$SCOPE/cgroup.procs
busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartTransientUnit
systemctl start snap.foo.service
";

    /// Retrouve un finding mappé par (capacité, ligne).
    fn find(report: &DiscoveryReport, cap: Capability, line: usize) -> Option<&MappedFinding> {
        report
            .findings
            .iter()
            .find(|m| m.capability == cap && m.line == line)
    }

    /// Retrouve un résumé de capacité.
    fn summary(report: &DiscoveryReport, cap: Capability) -> Option<&CapabilityReport> {
        report.capabilities.iter().find(|c| c.capability == cap)
    }

    #[test]
    fn snapd_like_signals_and_capabilities() {
        let report = analyze_text(SNAPD_LIKE);
        // Signaux détectés : systemd1 + cgroupfs + systemctl (pas logind, pas PID 1).
        assert_eq!(
            report.signals(),
            vec![
                discovery::Capability::SystemdDbus,
                discovery::Capability::CgroupFs,
                discovery::Capability::SystemctlCli,
            ]
        );
        // Contrats exigés : « un init » ne suffit pas, il faut l'API cgroup (shim).
        assert_eq!(
            report.required_capabilities(),
            vec![
                Capability::ServiceManagement,
                Capability::CgroupScopeSliceApi
            ]
        );
        assert!(report.needs_shim());
        // 5 findings mappés : L5 et L6 (cgroup), L7 (systemd1 → 2 capacités), L8.
        assert_eq!(report.findings.len(), 5);
        assert!(find(&report, Capability::CgroupScopeSliceApi, 5).is_some());
        assert!(find(&report, Capability::CgroupScopeSliceApi, 6).is_some());
        assert!(find(&report, Capability::CgroupScopeSliceApi, 7).is_some());
        assert!(find(&report, Capability::ServiceManagement, 7).is_some());
        assert!(find(&report, Capability::ServiceManagement, 8).is_some());
        // La preuve est la ligne elle-même.
        let ev = &find(&report, Capability::CgroupScopeSliceApi, 6)
            .unwrap()
            .evidence;
        assert!(ev.contains("cgroup.procs"));
    }

    #[test]
    fn snapd_like_support_levels() {
        let report = analyze_text(SNAPD_LIKE);
        // API cgroup : aucune alternative → shim, sur toutes ses preuves.
        for line in [5, 6, 7] {
            let m = find(&report, Capability::CgroupScopeSliceApi, line).unwrap();
            assert_eq!(m.support, None);
            assert!(m.needs_shim());
        }
        // Units (systemd1 + systemctl) : alternatives natives (dinit, OpenRC…).
        for line in [7, 8] {
            let m = find(&report, Capability::ServiceManagement, line).unwrap();
            assert_eq!(m.support, Some(SupportLevel::Native));
            assert!(!m.needs_shim());
        }
        // Résumés : support + lignes de preuve agrégées.
        let sm = summary(&report, Capability::ServiceManagement).unwrap();
        assert_eq!(sm.support, Some(SupportLevel::Native));
        assert!(!sm.needs_shim);
        assert_eq!(sm.lines, vec![7, 8]);
        let cg = summary(&report, Capability::CgroupScopeSliceApi).unwrap();
        assert_eq!(cg.support, None);
        assert!(cg.needs_shim);
        assert_eq!(cg.lines, vec![5, 6, 7]);
    }

    #[test]
    fn false_positives_excluded() {
        // Commentaires, tokens collés, lectures cgroup, bus trafiqués, « pid 10 » :
        // rien ne doit remonter dans le rapport.
        let text = "\
# org.freedesktop.systemd1 systemctl loginctl /sys/fs/cgroup
// org.freedesktop.login1 mkdir /sys/fs/cgroup
my_systemctl start x
systemctl2 start y
cat /sys/fs/cgroup/foo/cgroup.procs
cat /sys/fs/cgroup/foo/cgroup.procs 2>/dev/null
xorg.freedesktop.login1
org.freedesktop.systemd10
echo \"systemd pid 10\"
";
        let report = analyze_text(text);
        assert!(report.is_empty());
        assert_eq!(report.findings, []);
        assert_eq!(report.capabilities, []);
        assert_eq!(report.signals(), []);
        assert!(!report.needs_shim());
        assert_eq!(
            report.to_string(),
            "Aucune dépendance implicite détectée.\n"
        );
    }

    #[test]
    fn login1_and_loginctl_map_to_logind() {
        let text = "\
dbus-send --system --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.ListSessions
/usr/bin/loginctl list-sessions
";
        let report = analyze_text(text);
        assert_eq!(
            report.signals(),
            vec![
                discovery::Capability::LogindDbus,
                discovery::Capability::LoginctlCli,
            ]
        );
        assert_eq!(report.required_capabilities(), vec![Capability::Logind]);
        // elogind est natif (LoginKit n'est que not-tested) → meilleur = native.
        let logind = summary(&report, Capability::Logind).unwrap();
        assert_eq!(logind.support, Some(SupportLevel::Native));
        assert!(!logind.needs_shim);
        assert_eq!(logind.lines, vec![1, 2]);
        assert!(!report.needs_shim());
    }

    #[test]
    fn pid1_assumption_is_not_supported_by_alternatives() {
        let text = "\
[ \"$(cat /proc/1/comm)\" = \"systemd\" ] || exit 1
test -d /run/systemd/system && echo booted
";
        let report = analyze_text(text);
        assert_eq!(report.signals(), vec![discovery::Capability::SystemdPid1]);
        assert_eq!(
            report.required_capabilities(),
            vec![Capability::ServiceManagement]
        );
        // Aucune alternative d'init ne passe un check « systemd est PID 1 ».
        let sm = summary(&report, Capability::ServiceManagement).unwrap();
        assert_eq!(sm.support, Some(SupportLevel::NotSupported));
        assert!(!sm.needs_shim);
        assert_eq!(sm.lines, vec![1, 2]);
        for m in &report.findings {
            assert_eq!(m.support, Some(SupportLevel::NotSupported));
        }
    }

    #[test]
    fn hardest_usage_wins_in_summary() {
        // systemctl (native) + hypothèse PID 1 (not-supported) sur la même ligne :
        // le résumé de ServiceManagement retient le plus contraignant.
        let report = analyze_text("systemctl start x && test -d /run/systemd/system");
        assert_eq!(report.findings.len(), 2);
        let sm = summary(&report, Capability::ServiceManagement).unwrap();
        assert_eq!(sm.support, Some(SupportLevel::NotSupported));
        assert_eq!(sm.lines, vec![1]);
        assert!(find(&report, Capability::ServiceManagement, 1).is_some());
    }

    #[test]
    fn mapping_covers_every_signal() {
        for signal in [
            discovery::Capability::LogindDbus,
            discovery::Capability::SystemdDbus,
            discovery::Capability::CgroupFs,
            discovery::Capability::SystemctlCli,
            discovery::Capability::LoginctlCli,
            discovery::Capability::SystemdPid1,
        ] {
            let caps = capabilities_for(signal);
            assert!(!caps.is_empty(), "{signal:?}");
            for &cap in caps {
                assert!(Capability::ALL.contains(&cap));
                // Support cohérent avec le catalogue (sauf override PID 1).
                let expected = if signal == discovery::Capability::SystemdPid1 {
                    Some(SupportLevel::NotSupported)
                } else {
                    best_support(cap)
                };
                assert_eq!(support_for(signal, cap), expected);
            }
        }
        // systemd1 exige bien les DEUX contrats (units + API cgroup).
        assert_eq!(
            capabilities_for(discovery::Capability::SystemdDbus),
            &[
                Capability::ServiceManagement,
                Capability::CgroupScopeSliceApi
            ]
        );
    }

    #[test]
    fn best_support_ranking() {
        // Native l'emporte sur NotTested (elogind > LoginKit).
        assert_eq!(best_support(Capability::Logind), Some(SupportLevel::Native));
        assert_eq!(
            best_support(Capability::ServiceManagement),
            Some(SupportLevel::Native)
        );
        // Journald : uniquement des alternatives « modified ».
        assert_eq!(
            best_support(Capability::Journald),
            Some(SupportLevel::Modified)
        );
        // API cgroup : aucune alternative → None (shim).
        assert_eq!(best_support(Capability::CgroupScopeSliceApi), None);
    }

    #[test]
    fn same_line_dedup_preserved() {
        // Deux systemctl sur la même ligne → un seul finding (dédup découverte).
        let report = analyze_text("systemctl start a; systemctl start b");
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].line, 1);
        assert_eq!(
            report.findings[0].signal,
            discovery::Capability::SystemctlCli
        );
    }

    #[test]
    fn evidence_truncation_preserved() {
        let long = format!("{} systemctl start x", "a".repeat(300));
        let report = analyze_text(&long);
        assert_eq!(report.findings.len(), 1);
        let ev = &report.findings[0].evidence;
        assert!(ev.chars().count() <= 163);
        assert!(ev.ends_with("..."));
    }

    #[test]
    fn empty_text_no_findings() {
        assert!(analyze_text("").is_empty());
        assert!(analyze_text("\n\n  \n").is_empty());
    }

    #[test]
    fn analyze_file_matches_text_without_executing() {
        let path = std::env::temp_dir().join(format!(
            "omnitia_velotia_discovery_test_{}.sh",
            std::process::id()
        ));
        std::fs::write(&path, SNAPD_LIKE).unwrap();
        let from_file = analyze_file(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(from_file, analyze_text(SNAPD_LIKE));
        // Fichier absent → erreur I/O (pas de panique).
        assert!(analyze_file(Path::new("/nonexistent/omnitia-velotia-discovery")).is_err());
    }

    #[test]
    fn display_report_is_structured() {
        let report = analyze_text(SNAPD_LIKE);
        let text = report.to_string();
        // Résumés : capacité + support + lignes.
        assert!(text.contains("service-management : native (lignes 7, 8)"));
        assert!(text.contains(
            "cgroup-scope-slice-api : shim requis (aucune alternative) (lignes 5, 6, 7)"
        ));
        // Preuves ligne par ligne.
        assert!(text.contains("L6 : echo $$ > /sys/fs/cgroup/systemd/$SCOPE/cgroup.procs"));
        assert!(text.contains("L8 : systemctl start snap.foo.service"));
        assert!(text.contains("5 preuve(s)"));
    }
}
