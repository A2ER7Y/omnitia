//! Stream 8 — tests d'intégration du module `discovery` COMPLET (`omnitia::discovery`).
//!
//! Analyse 100 % statique : les fixtures ne sont JAMAIS exécutées, seulement
//! lues par `scan_text` / `scan_file`. On teste l'API publique :
//! `scan_text`, `scan_file`, `unique_capabilities`, `Capability` (+ `label`), `Finding`.
//!
//! Couverture : fixture snapd-like (D-Bus `systemd1` + cgroup), elogind,
//! faux positifs (lectures cgroup, `my_systemctl`, pid 10, commentaires),
//! dédup, troncature de preuve, scan multi-lignes.

use omnitia::discovery::{scan_file, scan_text, unique_capabilities, Capability, Finding};
use std::path::{Path, PathBuf};

// Mirroir de la constante privée MAX_EVIDENCE du module (160 caractères).
// La preuve tronquée = 160 premiers caractères + "..." = 163 caractères.
const MAX_EVIDENCE: usize = 160;

// Retrouve un finding par (capacité, ligne). Renvoie Option pour permettre
// assert!(...is_some()) / assert!(...is_none()) sans déclencher search_is_some.
fn find(findings: &[Finding], capability: Capability, line: usize) -> Option<&Finding> {
    findings
        .iter()
        .find(|f| f.capability == capability && f.line == line)
}

// Chemin de fichier temporaire unique (pid + suffixe propre au test).
fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "omnitia_discovery_it_{}_{name}.tmp",
        std::process::id()
    ))
}

// ---------------------------------------------------------------------------
// Fixture snapd-like : D-Bus org.freedesktop.systemd1 + écritures cgroup.
// ---------------------------------------------------------------------------

// Lignes : 1 shebang, 2 commentaire (mention systemd1 ignorée), 3 set,
// 4 variable, 5 mkdir cgroup, 6 echo > cgroup.procs, 7 busctl systemd1,
// 8 systemctl.
const SNAPD_LIKE: &str = "\
#!/bin/sh
# snap-confine-like : org.freedesktop.systemd1 (commentaire ignoré)
set -eu
SCOPE=snap.foo.scope
mkdir -p /sys/fs/cgroup/systemd/snap.foo.scope
echo $$ > /sys/fs/cgroup/systemd/snap.foo.scope/cgroup.procs
busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartTransientUnit
systemctl start snap.foo.service
";

#[test]
fn snapd_like_detects_systemd1_dbus_and_cgroup_writes() {
    let findings = scan_text(SNAPD_LIKE);
    assert!(find(&findings, Capability::CgroupFs, 5).is_some());
    assert!(find(&findings, Capability::CgroupFs, 6).is_some());
    assert!(find(&findings, Capability::SystemdDbus, 7).is_some());
    assert!(find(&findings, Capability::SystemctlCli, 8).is_some());
    assert_eq!(findings.len(), 4);

    // La preuve est la ligne trimée ; le commentaire (ligne 2) n'est pas un signal.
    let evidence = &find(&findings, Capability::CgroupFs, 6).unwrap().evidence;
    assert!(evidence.contains("cgroup.procs"));
    assert!(find(&findings, Capability::SystemdDbus, 2).is_none());
    assert!(find(&findings, Capability::LogindDbus, 7).is_none());
    assert!(find(&findings, Capability::SystemdPid1, 7).is_none());
}

#[test]
fn snapd_like_unique_capabilities_implies_shim() {
    let findings = scan_text(SNAPD_LIKE);
    // Conclusion « cas snapd » : systemd1 (D-Bus) + cgroupfs → un shim est
    // nécessaire, pas seulement « un init ». Liste triée (ordre de l'enum).
    assert_eq!(
        unique_capabilities(&findings),
        vec![
            Capability::SystemdDbus,
            Capability::CgroupFs,
            Capability::SystemctlCli,
        ]
    );
}

// ---------------------------------------------------------------------------
// elogind : fournit la même API org.freedesktop.login1 / loginctl que logind.
// La capacité détectée est « logind », indépendamment de l'implémentation.
// ---------------------------------------------------------------------------

#[test]
fn elogind_script_detected_as_logind_capability() {
    let text = "\
#!/bin/sh
# Session setup pour elogind (logind autonome, sans systemd)
loginctl enable-linger \"$USER\"
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager ListSessions
";
    let findings = scan_text(text);
    assert!(find(&findings, Capability::LoginctlCli, 3).is_some());
    assert!(find(&findings, Capability::LogindDbus, 4).is_some());
    assert_eq!(findings.len(), 2);
    // elogind satisfait la capacité logind, pas systemd.
    assert_eq!(
        unique_capabilities(&findings),
        vec![Capability::LogindDbus, Capability::LoginctlCli]
    );
    assert!(find(&findings, Capability::SystemdDbus, 4).is_none());
    assert!(find(&findings, Capability::SystemdPid1, 4).is_none());
}

#[test]
fn elogind_name_alone_is_not_a_signal() {
    // Le nom de l'implémentation « elogind » n'est pas un motif : seul l'usage
    // de l'API login1 / loginctl compte.
    assert_eq!(scan_text("elogind --version"), Vec::new());
    assert_eq!(scan_text("command -v elogind"), Vec::new());
}

// ---------------------------------------------------------------------------
// Faux positifs : lectures cgroup, lookalikes CLI, pid 10, commentaires.
// ---------------------------------------------------------------------------

#[test]
fn cgroup_reads_are_not_writes() {
    let text = "\
cat /sys/fs/cgroup/cpu.stat
cat /sys/fs/cgroup/foo/cgroup.procs 2>/dev/null
grep -r . /sys/fs/cgroup/foo/
";
    // Une simple lecture (même avec 2>/dev/null) n'est pas une écriture.
    assert_eq!(scan_text(text), Vec::new());
}

#[test]
fn cgroup_read_with_redirect_elsewhere_ignored() {
    // Le '>' cible /tmp, pas le cgroup : lecture cgroup + écriture ailleurs.
    let text = "cat /sys/fs/cgroup/foo/cgroup.procs > /tmp/snapshot.txt";
    assert_eq!(scan_text(text), Vec::new());
}

#[test]
fn cli_lookalikes_not_detected() {
    let text = "\
my_systemctl start foo
systemctl2 start foo
systemctl_wrapper start foo
my_loginctl list-sessions
loginctl2 list-sessions
notsystemctl start foo
";
    // Frontières de token : ni préfixe/suffixe collé ne compte comme appel.
    assert_eq!(scan_text(text), Vec::new());
}

#[test]
fn pid10_and_pid_lookalikes_not_detected() {
    let text = "\
echo \"systemd pid 10\"
echo \"systemd pid=10\"
echo \"systemd pid 123\"
echo \"pid 1\"
";
    // « pid 10 » / « pid=10 » ≠ « pid 1 » ; « pid 1 » sans systemd ≠ hypothèse.
    assert_eq!(scan_text(text), Vec::new());
}

#[test]
fn proc1_comm_without_systemd_not_detected() {
    // Lire /proc/1/comm sans mention de systemd n'est pas une hypothèse PID 1.
    assert_eq!(scan_text("cat /proc/1/comm"), Vec::new());
}

#[test]
fn full_line_comments_ignored() {
    let text = "\
# systemctl start snapd
# busctl call org.freedesktop.systemd1 org.freedesktop.login1
// loginctl list-sessions /sys/fs/cgroup
   # org.freedesktop.login1 (commentaire indenté)
\t// commentaire indenté par tab
";
    assert_eq!(scan_text(text), Vec::new());
}

#[test]
fn inline_mention_on_code_line_is_signal_documented_limitation() {
    // Limite assumée (cf. doc du module) : une mention sur une ligne de CODE
    // est un signal, même dans un commentaire de fin de ligne. Seules les
    // lignes de commentaire pleine ligne sont ignorées.
    let findings = scan_text("echo hello # systemctl mention");
    assert!(find(&findings, Capability::SystemctlCli, 1).is_some());
    assert_eq!(findings.len(), 1);
}

#[test]
fn bus_name_boundaries_reject_lookalikes() {
    let text = "\
org.freedesktop.systemd10
xorg.freedesktop.login1
foo.org.freedesktop.systemd1
org.freedesktop.login10
";
    // Suffixe collé (10), préfixe collé (x), ou '.' précédent → pas de match.
    assert_eq!(scan_text(text), Vec::new());
}

#[test]
fn bus_name_with_interface_and_delimiters_matches() {
    let text = "\
org.freedesktop.systemd1.Manager
--dest=org.freedesktop.login1
\"org.freedesktop.systemd1\"
";
    let findings = scan_text(text);
    // '.' suivant autorisé (bus + interface) ; '=' et '"' sont des frontières.
    assert!(find(&findings, Capability::SystemdDbus, 1).is_some());
    assert!(find(&findings, Capability::LogindDbus, 2).is_some());
    assert!(find(&findings, Capability::SystemdDbus, 3).is_some());
    assert_eq!(findings.len(), 3);
}

// ---------------------------------------------------------------------------
// Dédup : une capacité testée une seule fois par ligne.
// ---------------------------------------------------------------------------

#[test]
fn same_line_same_capability_dedup() {
    // Deux systemctl sur la même ligne → un seul finding.
    let findings = scan_text("systemctl start a; systemctl stop b");
    assert_eq!(findings.len(), 1);
    assert!(find(&findings, Capability::SystemctlCli, 1).is_some());

    // Plusieurs mentions du même bus sur une ligne → un seul finding.
    let findings = scan_text(
        "busctl call org.freedesktop.systemd1 org.freedesktop.systemd1.Manager org.freedesktop.systemd1",
    );
    assert_eq!(findings.len(), 1);
    assert!(find(&findings, Capability::SystemdDbus, 1).is_some());

    // Deux écritures cgroup sur une ligne → un seul finding.
    let findings = scan_text("echo 1 > /sys/fs/cgroup/a; echo 2 > /sys/fs/cgroup/b");
    assert_eq!(findings.len(), 1);
    assert!(find(&findings, Capability::CgroupFs, 1).is_some());
}

#[test]
fn same_capability_different_lines_not_deduped() {
    let text = "systemctl start a\nsystemctl start b\n";
    let findings = scan_text(text);
    // La dédup est par (capacité, ligne) : deux lignes distinctes → deux findings.
    assert_eq!(findings.len(), 2);
    assert!(find(&findings, Capability::SystemctlCli, 1).is_some());
    assert!(find(&findings, Capability::SystemctlCli, 2).is_some());
}

#[test]
fn multiple_capabilities_one_line() {
    let findings = scan_text("systemctl start x && test -d /run/systemd/system");
    assert!(find(&findings, Capability::SystemctlCli, 1).is_some());
    assert!(find(&findings, Capability::SystemdPid1, 1).is_some());
    assert_eq!(findings.len(), 2);
}

#[test]
fn all_six_capabilities_one_line_in_enum_order() {
    let text = "busctl call org.freedesktop.login1 org.freedesktop.systemd1; \
echo 1 > /sys/fs/cgroup/x; systemctl start a; loginctl list-sessions; \
test -d /run/systemd/system";
    let findings = scan_text(text);
    assert_eq!(findings.len(), 6);
    // Ordre des tests dans scan_text = ordre de l'enum, tous ligne 1.
    let order: Vec<Capability> = findings.iter().map(|f| f.capability).collect();
    assert_eq!(
        order,
        vec![
            Capability::LogindDbus,
            Capability::SystemdDbus,
            Capability::CgroupFs,
            Capability::SystemctlCli,
            Capability::LoginctlCli,
            Capability::SystemdPid1,
        ]
    );
    assert!(findings.iter().all(|f| f.line == 1));
}

#[test]
fn unique_capabilities_sorted_enum_order_and_deduped() {
    // Construit directement des Finding (champs publics) dans le désordre avec
    // un doublon : unique_capabilities doit trier (ordre enum) et dédupliquer.
    let findings = vec![
        Finding {
            capability: Capability::SystemdPid1,
            line: 1,
            evidence: String::new(),
        },
        Finding {
            capability: Capability::LoginctlCli,
            line: 2,
            evidence: String::new(),
        },
        Finding {
            capability: Capability::SystemctlCli,
            line: 3,
            evidence: String::new(),
        },
        Finding {
            capability: Capability::CgroupFs,
            line: 4,
            evidence: String::new(),
        },
        Finding {
            capability: Capability::SystemdDbus,
            line: 5,
            evidence: String::new(),
        },
        Finding {
            capability: Capability::LogindDbus,
            line: 6,
            evidence: String::new(),
        },
        Finding {
            capability: Capability::SystemctlCli,
            line: 7,
            evidence: String::new(),
        },
    ];
    assert_eq!(
        unique_capabilities(&findings),
        vec![
            Capability::LogindDbus,
            Capability::SystemdDbus,
            Capability::CgroupFs,
            Capability::SystemctlCli,
            Capability::LoginctlCli,
            Capability::SystemdPid1,
        ]
    );
}

#[test]
fn unique_capabilities_empty() {
    assert_eq!(unique_capabilities(&[]), Vec::new());
    assert_eq!(scan_text(""), Vec::new());
    assert_eq!(scan_text("\n\n  \n"), Vec::new());
}

// ---------------------------------------------------------------------------
// Troncature de preuve (MAX_EVIDENCE = 160 caractères, puis "...").
// ---------------------------------------------------------------------------

#[test]
fn evidence_truncated_on_long_line() {
    let long = format!("{} systemctl start x", "a".repeat(300));
    let findings = scan_text(&long);
    assert_eq!(findings.len(), 1);
    let evidence = &findings[0].evidence;
    assert_eq!(evidence.chars().count(), MAX_EVIDENCE + 3);
    assert!(evidence.ends_with("..."));
    assert_eq!(evidence, &format!("{}...", "a".repeat(MAX_EVIDENCE)));
}

#[test]
fn evidence_exactly_max_not_truncated() {
    // "systemctl start " = 16 caractères ; + 144 'x' = 160 pile.
    let line = format!("systemctl start {}", "x".repeat(MAX_EVIDENCE - 16));
    assert_eq!(line.chars().count(), MAX_EVIDENCE);
    let findings = scan_text(&line);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].evidence, line);
    assert!(!findings[0].evidence.ends_with("..."));
}

#[test]
fn evidence_one_over_max_truncated() {
    let line = format!("systemctl start {}", "x".repeat(MAX_EVIDENCE - 16 + 1));
    assert_eq!(line.chars().count(), MAX_EVIDENCE + 1);
    let findings = scan_text(&line);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].evidence.chars().count(), MAX_EVIDENCE + 3);
    assert!(findings[0].evidence.ends_with("..."));
}

#[test]
fn evidence_multibyte_truncation_is_char_based() {
    // 200 'é' (2 octets chacun) + systemctl : la troncature compte des
    // caractères, pas des octets → pas de coupure en milieu de codepoint.
    let line = format!("{} systemctl start x", "é".repeat(200));
    let findings = scan_text(&line);
    assert_eq!(findings.len(), 1);
    let evidence = &findings[0].evidence;
    assert_eq!(evidence.chars().count(), MAX_EVIDENCE + 3);
    assert_eq!(evidence, &format!("{}...", "é".repeat(MAX_EVIDENCE)));
}

#[test]
fn evidence_is_trimmed_line() {
    let findings = scan_text("   systemctl start x   ");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].evidence, "systemctl start x");
}

// ---------------------------------------------------------------------------
// Scan multi-lignes : numéros 1-based, lignes vides/commentaires comptées,
// CRLF, motifs étalés sur plusieurs lignes manqués (limite documentée).
// ---------------------------------------------------------------------------

#[test]
fn multiline_line_numbers_count_blanks_and_comments() {
    let text = "\
#!/bin/sh

# commentaire mentionnant systemctl
systemctl start foo

busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager ListSessions
echo 1 > /sys/fs/cgroup/foo/cgroup.procs
// commentaire C loginctl
test -d /run/systemd/system
";
    let findings = scan_text(text);
    // Les lignes vides et commentaires comptent dans la numérotation.
    assert!(find(&findings, Capability::SystemctlCli, 4).is_some());
    assert!(find(&findings, Capability::LogindDbus, 6).is_some());
    assert!(find(&findings, Capability::CgroupFs, 7).is_some());
    assert!(find(&findings, Capability::SystemdPid1, 9).is_some());
    assert_eq!(findings.len(), 4);
}

#[test]
fn multiline_crlf_line_endings() {
    let text = "systemctl start a\r\nloginctl list-sessions\r\n";
    let findings = scan_text(text);
    assert!(find(&findings, Capability::SystemctlCli, 1).is_some());
    assert!(find(&findings, Capability::LoginctlCli, 2).is_some());
    assert_eq!(findings.len(), 2);
    // La preuve est trimée : pas de '\r' résiduel.
    assert_eq!(findings[0].evidence, "systemctl start a");
}

#[test]
fn split_pattern_across_lines_missed_documented_limitation() {
    // Limite assumée : un motif coupé sur plusieurs lignes n'est pas détecté.
    assert_eq!(scan_text("org.freedesktop.\nsystemd1"), Vec::new());
    assert_eq!(scan_text("system\nctl start x"), Vec::new());
}

#[test]
fn positive_pid1_controls() {
    let text = "\
[ \"$(cat /proc/1/comm)\" = \"systemd\" ] || exit 1
test -d /run/systemd/system && echo booted
echo \"requires systemd as PID 1\" >&2
";
    let findings = scan_text(text);
    assert!(find(&findings, Capability::SystemdPid1, 1).is_some());
    assert!(find(&findings, Capability::SystemdPid1, 2).is_some());
    assert!(find(&findings, Capability::SystemdPid1, 3).is_some());
    assert_eq!(findings.len(), 3);
}

// ---------------------------------------------------------------------------
// scan_file : lecture seule (jamais d'exécution), UTF-8 tolérant, erreur I/O.
// ---------------------------------------------------------------------------

#[test]
fn scan_file_reads_script_without_executing() {
    let path = temp_path("script");
    std::fs::write(&path, SNAPD_LIKE).unwrap();
    let findings = scan_file(&path).unwrap();
    std::fs::remove_file(&path).ok();
    // Mêmes résultats que scan_text sur le même contenu.
    assert_eq!(findings, scan_text(SNAPD_LIKE));
    assert!(find(&findings, Capability::SystemdDbus, 7).is_some());
    assert!(find(&findings, Capability::CgroupFs, 6).is_some());
}

#[test]
fn scan_file_binary_strings_lossy() {
    // Octets non UTF-8 autour d'une chaîne D-Bus (cas binaire stripé) :
    // décodage tolérant, la chaîne est quand même scannée.
    let mut bytes = vec![0xFF, 0xFE, 0x00];
    bytes.extend_from_slice(b"org.freedesktop.systemd1");
    bytes.push(0x00);
    let path = temp_path("binary");
    std::fs::write(&path, bytes).unwrap();
    let findings = scan_file(&path).unwrap();
    std::fs::remove_file(&path).ok();
    assert!(find(&findings, Capability::SystemdDbus, 1).is_some());
}

#[test]
fn scan_file_missing_returns_io_error() {
    // Fichier absent → erreur I/O, pas de panique.
    assert!(scan_file(Path::new("/nonexistent/omnitia-discovery-it")).is_err());
}

#[test]
fn scan_file_empty_ok() {
    let path = temp_path("empty");
    std::fs::write(&path, b"").unwrap();
    let findings = scan_file(&path).unwrap();
    std::fs::remove_file(&path).ok();
    assert_eq!(findings, Vec::new());
}

// ---------------------------------------------------------------------------
// API publique : Finding (forme publique) et Capability::label.
// ---------------------------------------------------------------------------

#[test]
fn finding_struct_matches_public_shape() {
    let findings = scan_text("systemctl start x");
    assert_eq!(
        findings,
        vec![Finding {
            capability: Capability::SystemctlCli,
            line: 1,
            evidence: "systemctl start x".to_string(),
        }]
    );
}

#[test]
fn labels_nonempty_and_distinct() {
    let caps = [
        Capability::LogindDbus,
        Capability::SystemdDbus,
        Capability::CgroupFs,
        Capability::SystemctlCli,
        Capability::LoginctlCli,
        Capability::SystemdPid1,
    ];
    let mut unique_labels = std::collections::HashSet::new();
    for capability in caps {
        let label = capability.label();
        assert_ne!(label, "");
        unique_labels.insert(label);
    }
    assert_eq!(unique_labels.len(), caps.len());
}
