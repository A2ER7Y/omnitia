//! Stream C — découverte des dépendances IMPLICITES (analyse statique).
//!
//! Les dépendances déclarées ne révèlent pas les besoins réels : `snapd` ne
//! déclare pas proprement son usage de l'API cgroup/scope/slice de systemd
//! (D-Bus `org.freedesktop.systemd1` + écritures `/sys/fs/cgroup`). Ce module
//! scanne un texte (script, ou chaînes extraites d'un binaire) et retourne
//! les capacités implicites détectées, avec le numéro de ligne et la preuve.
//!
//! INVARIANT : analyse 100 % statique — on ne fait que LIRE du texte ;
//! le code analysé n'est JAMAIS exécuté.
//!
//! Signaux détectés (cf. README, « Découverte des exceptions ») :
//! - appels D-Bus `org.freedesktop.login1` / `org.freedesktop.systemd1` ;
//! - écritures dans `/sys/fs/cgroup` (redirections, `tee`, `mkdir`, `open`…) ;
//! - appels CLI `systemctl` / `loginctl` ;
//! - hypothèses « systemd est PID 1 » (`/proc/1/comm`, `/run/systemd/system`…).
//!
//! Limites (heuristiques ligne à ligne, assumées) :
//! - les lignes de commentaire (`#`, `//`) sont ignorées ;
//! - une mention sur une ligne de code est un signal, pas une preuve d'appel
//!   effectif (pas d'analyse de flot de contrôle) ;
//! - les motifs étalés sur plusieurs lignes peuvent être manqués.

use std::path::Path;

/// Longueur max de la preuve stockée (les lignes de binaires peuvent être énormes).
const MAX_EVIDENCE: usize = 160;

/// Chemin du filesystem cgroup (v1/v2) monté par l'init.
const CGROUP_PATH: &str = "/sys/fs/cgroup";

/// Capacité implicite détectée — à rapprocher de la map du README.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    /// D-Bus `org.freedesktop.login1` → capacité « logind (sessions/seats) »
    /// (alternatives : elogind, LoginKit).
    LogindDbus,
    /// D-Bus `org.freedesktop.systemd1` → « service management (units) » ET
    /// l'API cgroup/scope/slice (le cas snapd : un shim est nécessaire).
    SystemdDbus,
    /// Écritures dans `/sys/fs/cgroup` → dépend du cgroupfs monté par l'init.
    CgroupFs,
    /// CLI `systemctl` → « service management (units) » via ligne de commande.
    SystemctlCli,
    /// CLI `loginctl` → « logind » via ligne de commande.
    LoginctlCli,
    /// Hypothèse « systemd est PID 1 » (checks `/proc/1/*`, `/run/systemd/system`,
    /// « pid 1 ») — la plus difficile à satisfaire avec un autre init.
    SystemdPid1,
}

impl Capability {
    /// Libellé lisible pour les rapports.
    pub fn label(self) -> &'static str {
        match self {
            Self::LogindDbus => "logind (D-Bus org.freedesktop.login1)",
            Self::SystemdDbus => {
                "systemd (D-Bus org.freedesktop.systemd1 : units + cgroup/scope/slice)"
            }
            Self::CgroupFs => "cgroupfs (écritures /sys/fs/cgroup)",
            Self::SystemctlCli => "service management (CLI systemctl)",
            Self::LoginctlCli => "logind (CLI loginctl)",
            Self::SystemdPid1 => "hypothèse systemd = PID 1",
        }
    }
}

/// Une dépendance implicite trouvée : capacité + ligne (1-based) + preuve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Capacité implicite détectée.
    pub capability: Capability,
    /// Numéro de ligne dans le texte analysé (commence à 1).
    pub line: usize,
    /// Preuve : la ligne (trimée), tronquée à [`MAX_EVIDENCE`] caractères.
    pub evidence: String,
}

/// Scanne un texte (script shell, source C, chaînes d'un binaire…) et retourne
/// les capacités implicites détectées, ligne par ligne. Purement statique :
/// le texte n'est jamais interprété ni exécuté.
///
/// ```
/// use omnitia::discovery::{scan_text, Capability};
/// let findings = scan_text("systemctl start snapd");
/// assert_eq!(findings[0].capability, Capability::SystemctlCli);
/// assert_eq!(findings[0].line, 1);
/// ```
pub fn scan_text(text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        // Commentaires pleine ligne : une mention n'est pas un appel.
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let lineno = i + 1;
        // Chaque capacité est testée une seule fois par ligne → pas de doublon
        // (capacité, ligne) même si le motif apparaît plusieurs fois.
        if contains_bus_name(line, "org.freedesktop.login1") {
            out.push(finding(Capability::LogindDbus, lineno, line));
        }
        if contains_bus_name(line, "org.freedesktop.systemd1") {
            out.push(finding(Capability::SystemdDbus, lineno, line));
        }
        if cgroup_write(line) {
            out.push(finding(Capability::CgroupFs, lineno, line));
        }
        if contains_word(line, "systemctl") {
            out.push(finding(Capability::SystemctlCli, lineno, line));
        }
        if contains_word(line, "loginctl") {
            out.push(finding(Capability::LoginctlCli, lineno, line));
        }
        if systemd_pid1(line) {
            out.push(finding(Capability::SystemdPid1, lineno, line));
        }
    }
    out
}

/// Scanne un fichier SANS l'exécuter : lecture seule des octets, décodage
/// UTF-8 tolérant (les binaires contiennent des octets non UTF-8 ; on scanne
/// quand même leurs chaînes). Erreur I/O si le fichier est illisible.
pub fn scan_file(path: &Path) -> std::io::Result<Vec<Finding>> {
    let bytes = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    Ok(scan_text(&text))
}

/// Capacités uniques présentes dans les findings, triées (ordre de l'enum).
/// C'est la « liste de courses » à abstraire (stream B) pour le paquet analysé.
pub fn unique_capabilities(findings: &[Finding]) -> Vec<Capability> {
    let mut caps: Vec<Capability> = findings.iter().map(|f| f.capability).collect();
    caps.sort();
    caps.dedup();
    caps
}

/// Construit un finding avec la preuve tronquée.
fn finding(capability: Capability, line: usize, evidence: &str) -> Finding {
    let evidence = if evidence.chars().count() > MAX_EVIDENCE {
        let cut: String = evidence.chars().take(MAX_EVIDENCE).collect();
        format!("{cut}...")
    } else {
        evidence.to_string()
    };
    Finding {
        capability,
        line,
        evidence,
    }
}

/// Vrai si `c` est un caractère de « mot » (frontière de token).
fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `word` présent comme token entier : ni précédé ni suivi d'un caractère de
/// mot (`systemctl` matche, `my_systemctl` et `systemctl2` non ; `/bin/systemctl`
/// matche car `/` n'est pas un caractère de mot).
fn contains_word(line: &str, word: &str) -> bool {
    for (idx, _) in line.match_indices(word) {
        let before_ok = idx == 0 || !line[..idx].chars().next_back().is_some_and(is_word_char);
        let after = idx + word.len();
        let after_ok =
            after >= line.len() || !line[after..].chars().next().is_some_and(is_word_char);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Nom de bus D-Bus présent avec des frontières correctes :
/// - précédé d'autre chose qu'un caractère de mot ou `.` (pas `xorg.freedesktop…`) ;
/// - suivi d'autre chose qu'un caractère de mot, MAIS `.` est autorisé car
///   `org.freedesktop.systemd1.Manager` est le bus + l'interface (`systemd10` non).
fn contains_bus_name(line: &str, name: &str) -> bool {
    for (idx, _) in line.match_indices(name) {
        let before_ok = idx == 0
            || !line[..idx]
                .chars()
                .next_back()
                .is_some_and(|c| is_word_char(c) || c == '.');
        let after = idx + name.len();
        let after_ok =
            after >= line.len() || !line[after..].chars().next().is_some_and(is_word_char);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Écriture dans `/sys/fs/cgroup` : le chemin doit apparaître ET la ligne
/// doit montrer une intention d'écriture. Une simple lecture (`cat …`) ne
/// compte pas.
fn cgroup_write(line: &str) -> bool {
    if !line.contains(CGROUP_PATH) {
        return false;
    }
    // Redirection `>` / `>>` dont la cible est le chemin cgroup : le `>` doit
    // précéder le chemin (évite le faux positif `cat /sys/fs/cgroup/x 2>/dev/null`).
    for (idx, _) in line.match_indices(CGROUP_PATH) {
        let prefix =
            line[..idx].trim_end_matches(|c: char| c.is_whitespace() || c == '"' || c == '\'');
        if prefix.ends_with('>') {
            return true;
        }
    }
    has_write_intent(line)
}

/// Indices d'écriture sur la ligne (commandes shell, flags C, modes stdio).
fn has_write_intent(line: &str) -> bool {
    for w in [
        "tee", "mkdir", "rmdir", "rm", "cp", "mv", "touch", "install", "dd",
    ] {
        if contains_word(line, w) {
            return true;
        }
    }
    for flag in ["O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND"] {
        if line.contains(flag) {
            return true;
        }
    }
    if line.contains("fopen") && (line.contains("\"w\"") || line.contains("\"a\"")) {
        return true;
    }
    line.contains("write(") || line.contains("writev(")
}

/// Hypothèse « systemd est PID 1 » :
/// - check `sd_booted()` : présence de `/run/systemd/system` ;
/// - inspection de `/proc/1/*` avec mention de systemd ;
/// - mention explicite « systemd … pid 1 » (insensible à la casse).
fn systemd_pid1(line: &str) -> bool {
    if line.contains("/run/systemd/system") {
        return true;
    }
    let lower = line.to_lowercase();
    if line.contains("/proc/1/") && lower.contains("systemd") {
        return true;
    }
    lower.contains("systemd")
        && ["pid 1", "pid1", "pid=1", "pid = 1"]
            .iter()
            .any(|p| contains_word(&lower, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture « snapd-like » : snap-confine parle à systemd1 (D-Bus) ET écrit
    /// dans les cgroups → il exige l'API cgroup de systemd, pas juste « un init ».
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

    /// Retrouve un finding par (capacité, ligne).
    fn find(fs: &[Finding], cap: Capability, line: usize) -> Option<&Finding> {
        fs.iter().find(|f| f.capability == cap && f.line == line)
    }

    #[test]
    fn snapd_like_detects_systemd1_and_cgroup() {
        let f = scan_text(SNAPD_LIKE);
        assert!(find(&f, Capability::CgroupFs, 5).is_some());
        assert!(find(&f, Capability::CgroupFs, 6).is_some());
        assert!(find(&f, Capability::SystemdDbus, 7).is_some());
        assert!(find(&f, Capability::SystemctlCli, 8).is_some());
        assert_eq!(f.len(), 4);
        // La preuve est la ligne elle-même.
        let ev = &find(&f, Capability::CgroupFs, 6).unwrap().evidence;
        assert!(ev.contains("cgroup.procs"));
        // Conclusion « cas snapd » : systemd1 + cgroupfs → shim nécessaire.
        assert_eq!(
            unique_capabilities(&f),
            vec![
                Capability::SystemdDbus,
                Capability::CgroupFs,
                Capability::SystemctlCli
            ]
        );
        // Pas de logind ni d'hypothèse PID 1 dans cette fixture.
        assert!(find(&f, Capability::LogindDbus, 7).is_none());
        assert!(find(&f, Capability::SystemdPid1, 7).is_none());
    }

    #[test]
    fn login1_dbus_detected() {
        let text = "dbus-send --system --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.ListSessions\n\
                    gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1\n";
        let f = scan_text(text);
        assert!(find(&f, Capability::LogindDbus, 1).is_some());
        assert!(find(&f, Capability::LogindDbus, 2).is_some());
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn cli_calls_word_boundary() {
        let text = "systemctl --user restart foo\n\
                    /usr/bin/loginctl list-sessions\n\
                    my_systemctl start x\n\
                    systemctl2 start y\n";
        let f = scan_text(text);
        assert!(find(&f, Capability::SystemctlCli, 1).is_some());
        assert!(find(&f, Capability::LoginctlCli, 2).is_some());
        // `my_systemctl` / `systemctl2` ne sont pas des appels systemctl.
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn cgroup_writes_detected_reads_ignored() {
        let text = "\
echo 1 > /sys/fs/cgroup/foo/cgroup.procs
echo 1 >> /sys/fs/cgroup/foo/cgroup.procs
echo 1 | tee -a /sys/fs/cgroup/foo/cgroup.procs
mkdir /sys/fs/cgroup/foo
open(\"/sys/fs/cgroup/foo/cgroup.procs\", O_WRONLY|O_CREAT, 0644);
fopen(\"/sys/fs/cgroup/foo/cgroup.procs\", \"w\");
cat /sys/fs/cgroup/foo/cgroup.procs
cat /sys/fs/cgroup/foo/cgroup.procs 2>/dev/null
echo 1 > \"/sys/fs/cgroup/foo/cgroup.procs\"
";
        let f = scan_text(text);
        // Lignes 1-6 et 9 : écritures. Lignes 7-8 : lectures (même avec 2>/dev/null).
        for line in [1, 2, 3, 4, 5, 6, 9] {
            assert!(
                find(&f, Capability::CgroupFs, line).is_some(),
                "ligne {line}"
            );
        }
        assert!(find(&f, Capability::CgroupFs, 7).is_none());
        assert!(find(&f, Capability::CgroupFs, 8).is_none());
        assert_eq!(f.len(), 7);
    }

    #[test]
    fn pid1_assumptions_detected() {
        let text = "\
[ \"$(cat /proc/1/comm)\" = \"systemd\" ] || exit 1
test -d /run/systemd/system && echo booted
echo \"requires systemd as PID 1\" >&2
systemctl is-system-running
echo \"systemd pid 10\"
";
        let f = scan_text(text);
        assert!(find(&f, Capability::SystemdPid1, 1).is_some());
        assert!(find(&f, Capability::SystemdPid1, 2).is_some());
        assert!(find(&f, Capability::SystemdPid1, 3).is_some());
        // systemctl seul ≠ hypothèse PID 1 ; « pid 10 » ≠ « pid 1 ».
        assert!(find(&f, Capability::SystemctlCli, 4).is_some());
        assert!(find(&f, Capability::SystemdPid1, 4).is_none());
        assert!(find(&f, Capability::SystemdPid1, 5).is_none());
    }

    #[test]
    fn comment_lines_ignored() {
        let text = "# org.freedesktop.systemd1 et org.freedesktop.login1\n\
                    // systemctl loginctl /sys/fs/cgroup\n";
        assert!(scan_text(text).is_empty());
    }

    #[test]
    fn empty_text_no_findings() {
        assert!(scan_text("").is_empty());
        assert!(scan_text("\n\n  \n").is_empty());
        assert!(unique_capabilities(&[]).is_empty());
    }

    #[test]
    fn bus_name_boundaries() {
        let text = "org.freedesktop.systemd1.Manager\n\
                    org.freedesktop.systemd10\n\
                    xorg.freedesktop.login1\n";
        let f = scan_text(text);
        // Bus + interface (.Manager) = match ; suffixes collés = non.
        assert!(find(&f, Capability::SystemdDbus, 1).is_some());
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn same_line_dedup_and_multiple_signals() {
        // Deux systemctl sur la même ligne → un seul finding.
        let f = scan_text("systemctl start a; systemctl start b");
        assert_eq!(f.len(), 1);
        // Une ligne peut porter plusieurs capacités distinctes.
        let f = scan_text("systemctl start x && test -d /run/systemd/system");
        assert!(find(&f, Capability::SystemctlCli, 1).is_some());
        assert!(find(&f, Capability::SystemdPid1, 1).is_some());
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn evidence_truncated_on_long_lines() {
        let long = format!("{} systemctl start x", "a".repeat(300));
        let f = scan_text(&long);
        assert_eq!(f.len(), 1);
        assert!(f[0].evidence.chars().count() <= MAX_EVIDENCE + 3);
        assert!(f[0].evidence.ends_with("..."));
    }

    #[test]
    fn scan_file_reads_script_without_executing() {
        let path =
            std::env::temp_dir().join(format!("omnitia_discovery_test_{}.sh", std::process::id()));
        std::fs::write(&path, SNAPD_LIKE).unwrap();
        let f = scan_file(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(find(&f, Capability::SystemdDbus, 7).is_some());
        assert!(find(&f, Capability::CgroupFs, 6).is_some());
        // Fichier absent → erreur I/O (pas de panique).
        assert!(scan_file(Path::new("/nonexistent/omnitia-discovery")).is_err());
    }

    #[test]
    fn scan_file_binary_strings_lossy() {
        // Octets non UTF-8 autour d'une chaîne D-Bus (cas binaire stripé).
        let mut bytes = vec![0xFF, 0xFE, 0x00];
        bytes.extend_from_slice(b"org.freedesktop.systemd1");
        bytes.push(0x00);
        let path =
            std::env::temp_dir().join(format!("omnitia_discovery_test_bin_{}", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let f = scan_file(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(find(&f, Capability::SystemdDbus, 1).is_some());
    }

    #[test]
    fn labels_are_nonempty() {
        for cap in [
            Capability::LogindDbus,
            Capability::SystemdDbus,
            Capability::CgroupFs,
            Capability::SystemctlCli,
            Capability::LoginctlCli,
            Capability::SystemdPid1,
        ] {
            assert!(!cap.label().is_empty());
        }
    }
}
