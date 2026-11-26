//! Stream 6 — sous-commandes CLI Velotia : `abstract` / `discover` / `glass` / `capability`.
//!
//! Câblage des trois modules Velotia COMPLETS dans le CLI `omni` :
//! - [`crate::abstraction`] : dépendance → capacités virtuelles + catalogue d'alternatives ;
//! - [`crate::discovery`] : scan statique des dépendances implicites (lecture seule,
//!   le fichier analysé n'est JAMAIS exécuté) ;
//! - [`crate::glass`] : verre calculé depuis le store partagé Islansia/Vitreus.
//!
//! Commandes d'affichage uniquement : aucune installation, aucune modification
//! du système réel. Les fonctions `render_*` sont pures (texte → texte) pour
//! être testables sur fixtures ; les fonctions `cmd_*` font l'affichage et les
//! seules lectures fichier.

use crate::{abstraction, discovery, glass};
use anyhow::{Context, Result};
use clap::Args;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Candidats de store par défaut (convention Vitreus : `state/glass.json`),
/// relatifs au répertoire courant.
const DEFAULT_STORES: [&str; 2] = ["glass.json", "state/glass.json"];

/// Arguments de `omni abstract <dep>`.
#[derive(Args, Debug)]
pub struct AbstractArgs {
    /// Dépendance à abstraire (ex. systemd, systemd-logind, elogind, logind)
    #[arg(value_name = "DEP")]
    pub dep: String,
}

/// Arguments de `omni discover <fichier>`.
#[derive(Args, Debug)]
pub struct DiscoverArgs {
    /// Fichier à scanner (script ou binaire ; lecture seule, jamais exécuté)
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// Arguments de `omni glass [store]`.
#[derive(Args, Debug)]
pub struct GlassArgs {
    /// Store partagé (JSON ou `key=value`) ; sans argument : `glass.json` puis
    /// `state/glass.json` dans le répertoire courant, sinon valeurs par défaut
    #[arg(value_name = "STORE")]
    pub store: Option<PathBuf>,

    /// Facteur d'échelle appliqué au sigma du blur
    #[arg(long, default_value = "1.0")]
    pub scale: f32,
}

/// Arguments de `omni capability <nom>`.
#[derive(Args, Debug)]
pub struct CapabilityArgs {
    /// Identifiant de capacité (logind, init, journald…) ou nom d'implémentation
    /// (elogind, dinit, rsyslog…)
    #[arg(value_name = "NAME")]
    pub name: String,
}

/// `omni abstract <dep>` : affiche les capacités virtuelles d'une dépendance.
/// Commande infaillible : l'abstraction est une fonction pure du catalogue.
pub fn cmd_abstract(args: &AbstractArgs) {
    print!("{}", render_abstract(&args.dep));
}

/// `omni discover <fichier>` : scan statique des dépendances implicites.
///
/// # Errors
/// Erreur si le fichier est illisible (absent, permissions…). Le fichier n'est
/// jamais exécuté : seuls ses octets sont lus.
pub fn cmd_discover(args: &DiscoverArgs) -> Result<()> {
    println!(
        "🔎 Scan statique de « {} » (lecture seule, jamais exécuté)",
        args.file.display()
    );
    let findings = discovery::scan_file(&args.file)
        .with_context(|| format!("fichier illisible : {}", args.file.display()))?;
    print!("{}", render_findings(&findings));
    Ok(())
}

/// `omni glass [store]` : affiche le verre calculé depuis le store partagé.
///
/// # Errors
/// Erreur si un store explicite est illisible. Sans store, retombe sur les
/// candidats par défaut puis sur les valeurs par défaut (jamais d'erreur).
pub fn cmd_glass(args: &GlassArgs) -> Result<()> {
    let (cfg, source) = load_glass_config(args.store.as_deref())?;
    print!("{}", render_glass(&cfg, args.scale, &source));
    Ok(())
}

/// `omni capability <nom>` : lookup d'une capacité ou d'une implémentation.
/// Commande infaillible : un nom inconnu produit un message d'aide, pas une
/// erreur (convention des commandes de lookup du CLI).
pub fn cmd_capability(args: &CapabilityArgs) {
    print!("{}", render_capability(&args.name));
}

/// Rend l'abstraction d'une dépendance : capacités virtuelles + alternatives.
/// Une dep inconnue du catalogue reste concrète (paquet exact).
#[must_use]
pub fn render_abstract(dep: &str) -> String {
    let dep = dep.trim();
    let caps = abstraction::abstract_dependency(dep);
    let mut out = String::new();
    if caps.is_empty() {
        let _ = writeln!(
            out,
            "📦 « {dep} » est inconnu du catalogue : la dépendance reste concrète."
        );
        let _ = writeln!(
            out,
            "   Elle n'est satisfaite que si le paquet exact « {dep} » est installé."
        );
        return out;
    }
    let _ = writeln!(
        out,
        "🧩 « {dep} » → {} capacité(s) virtuelle(s) :",
        caps.len()
    );
    for cap in caps {
        let _ = writeln!(out, "\n  • {} — {}", cap.id(), cap.description());
        let _ = writeln!(out, "      {}", render_alternatives(cap));
    }
    let _ = writeln!(
        out,
        "\nℹ️  La dep est satisfaite si TOUTES ses capacités le sont (conjonction)."
    );
    out
}

/// Rend le lookup d'un nom : capacité (id ou alias) → catalogue ;
/// implémentation connue → capacités fournies ; sinon message d'aide.
#[must_use]
pub fn render_capability(name: &str) -> String {
    let name = name.trim();
    let mut out = String::new();
    if let Some(cap) = abstraction::Capability::from_id(name) {
        let _ = writeln!(out, "🗺️  Capacité « {} » — {}", cap.id(), cap.description());
        let _ = writeln!(out, "  {}", render_alternatives(cap));
        return out;
    }
    // Pas un id de capacité : peut-être une implémentation cataloguée.
    let provided: Vec<(abstraction::Capability, abstraction::SupportLevel)> =
        abstraction::Capability::ALL
            .into_iter()
            .filter_map(|cap| abstraction::support_level(name, cap).map(|level| (cap, level)))
            .collect();
    if !provided.is_empty() {
        let _ = writeln!(out, "📦 « {name} » — implémentation connue :");
        for (cap, level) in provided {
            let _ = writeln!(
                out,
                "  • fournit {} — {} ({})",
                cap.id(),
                cap.description(),
                level.as_str()
            );
        }
        return out;
    }
    let ids: Vec<&str> = abstraction::Capability::ALL
        .iter()
        .map(|cap| cap.id())
        .collect();
    let _ = writeln!(
        out,
        "❌ « {name} » : ni capacité ni implémentation connue du catalogue."
    );
    let _ = writeln!(
        out,
        "   Capacités connues : {} (alias « init » → service-management)",
        ids.join(", ")
    );
    out
}

/// Rend les alternatives d'une capacité, avec niveaux de support ;
/// signale le shim à construire quand aucune alternative n'existe.
fn render_alternatives(cap: abstraction::Capability) -> String {
    let alts = cap.alternatives();
    if alts.is_empty() {
        return "⚠️  aucune alternative cataloguée : shim à construire (cas snapd)".to_string();
    }
    let list: Vec<String> = alts
        .iter()
        .map(|alt| format!("{} ({})", alt.name, alt.level.as_str()))
        .collect();
    format!("alternatives : {}", list.join(", "))
}

/// Rend les findings d'un scan statique : preuve ligne par ligne, puis la
/// « liste de courses » des capacités uniques à abstraire.
#[must_use]
pub fn render_findings(findings: &[discovery::Finding]) -> String {
    let mut out = String::new();
    if findings.is_empty() {
        let _ = writeln!(out, "✅ Aucune dépendance implicite détectée.");
        return out;
    }
    let _ = writeln!(
        out,
        "🔎 {} dépendance(s) implicite(s) détectée(s) :",
        findings.len()
    );
    for f in findings {
        let _ = writeln!(out, "\n  ligne {} : {}", f.line, f.capability.label());
        let _ = writeln!(out, "      {}", f.evidence);
    }
    let unique = discovery::unique_capabilities(findings);
    let _ = writeln!(
        out,
        "\n📋 Capacités uniques ({}) — « liste de courses » à abstraire :",
        unique.len()
    );
    for cap in unique {
        let _ = writeln!(out, "  • {}", cap.label());
    }
    out
}

/// Parse un texte de store : objet JSON plat (format Vitreus) si le texte
/// commence par `{`, sinon format `key=value` (une paire par ligne).
#[must_use]
pub fn parse_glass_text(text: &str) -> glass::GlassConfig {
    if text.trim_start().starts_with('{') {
        glass::parse_json_store(text)
    } else {
        glass::parse_store(text)
    }
}

/// Lit un store explicite et retourne (config, source lisible).
///
/// # Errors
/// Erreur I/O contextuelle si le fichier est illisible.
fn read_store(path: &Path) -> Result<(glass::GlassConfig, String)> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("store de verre illisible : {}", path.display()))?;
    Ok((parse_glass_text(&text), path.display().to_string()))
}

/// Charge la config de verre : store explicite, sinon candidats par défaut
/// ([`DEFAULT_STORES`]), sinon valeurs par défaut. Retourne (config, source).
///
/// # Errors
/// Erreur uniquement si un store explicite est illisible ; l'absence de store
/// par défaut retombe silencieusement sur les valeurs par défaut.
pub fn load_glass_config(store: Option<&Path>) -> Result<(glass::GlassConfig, String)> {
    if let Some(path) = store {
        return read_store(path);
    }
    for candidate in DEFAULT_STORES {
        let path = Path::new(candidate);
        if path.is_file() {
            return read_store(path);
        }
    }
    Ok((
        glass::GlassConfig::default(),
        "défauts (aucun store trouvé)".to_string(),
    ))
}

/// Rend le verre calculé (formule Vitreus) depuis la config partagée.
#[must_use]
pub fn render_glass(cfg: &glass::GlassConfig, scale: f32, source: &str) -> String {
    let computed = glass::compute(cfg, scale);
    format!(
        "🪟 Verre calculé — store : {source}\n  \
         config  : blur={} smoke={} rim={} milk={} opacity={} pv={}\n  \
         sigma   = {:.2}\n  \
         tint    = {:.2}\n  \
         rim     = {:.2}\n  \
         opacity = {:.2}\n",
        cfg.blur,
        cfg.smoke,
        cfg.rim,
        cfg.milk,
        cfg.opacity,
        cfg.pv,
        computed.sigma,
        computed.tint,
        computed.rim,
        computed.opacity
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture « snapd-like » (même esprit que la fixture de discovery) :
    /// écritures cgroup + D-Bus `systemd1` + `systemctl`. Lignes : 1 shebang,
    /// 2 commentaire (ignoré), 3 set, 4 variable, 5 mkdir cgroup,
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

    /// Fixture de store JSON (format île Vitreus).
    const JSON_STORE: &str =
        r#"{"blur":0.5,"smoke":0.0,"rim":1.0,"milk":0.4,"opacity":1.0,"pv":0.0}"#;

    /// Fixture de store `key=value`.
    const KV_STORE: &str = "blur=0.1\nsmoke=0.0\n# commentaire\nrim=2.0\n";

    #[test]
    fn abstract_systemd_lists_all_capabilities_and_shim() {
        let out = render_abstract("systemd");
        assert!(out.contains("6 capacité(s)"));
        for cap in abstraction::Capability::ALL {
            assert!(out.contains(cap.id()), "capacité {} absente", cap.id());
        }
        assert!(out.contains("dinit (native)"));
        assert!(out.contains("LoginKit (not-tested)"));
        assert!(out.contains("rsyslog (modified)"));
        assert!(out.contains("shim à construire"));
        assert!(out.contains("conjonction"));
    }

    #[test]
    fn abstract_component_maps_to_single_capability() {
        let out = render_abstract("systemd-logind");
        assert!(out.contains("1 capacité(s)"));
        assert!(out.contains("logind"));
        assert!(!out.contains("journald"));
        // Une implémentation s'abstrait vers sa capacité.
        let out = render_abstract("elogind");
        assert!(out.contains("logind"));
        assert!(!out.contains("service-management"));
    }

    #[test]
    fn abstract_unknown_dep_stays_concrete() {
        let out = render_abstract("firefox");
        assert!(out.contains("reste concrète"));
        assert!(out.contains("firefox"));
        assert!(!out.contains("capacité(s) virtuelle(s)"));
    }

    #[test]
    fn capability_lookup_by_id_and_alias() {
        let out = render_capability("logind");
        assert!(out.contains("Capacité « logind »"));
        assert!(out.contains("elogind (native)"));
        let alias = render_capability("init");
        assert!(alias.contains("service-management"));
        assert!(alias.contains("OpenRC (native)"));
        let shim = render_capability("cgroup-scope-slice-api");
        assert!(shim.contains("shim à construire"));
    }

    #[test]
    fn capability_lookup_by_implementation() {
        let out = render_capability("elogind");
        assert!(out.contains("implémentation connue"));
        assert!(out.contains("fournit logind"));
        assert!(out.contains("native"));
        // rsyslog ne fournit que journald, en modified.
        let out = render_capability("rsyslog");
        assert!(out.contains("fournit journald"));
        assert!(out.contains("modified"));
        assert!(!out.contains("logind"));
    }

    #[test]
    fn capability_unknown_lists_known_ids() {
        let out = render_capability("inexistant");
        assert!(out.contains("❌"));
        for cap in abstraction::Capability::ALL {
            assert!(out.contains(cap.id()));
        }
        assert!(out.contains("alias « init »"));
    }

    #[test]
    fn discover_fixture_snapd_like() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snap-confine-like.sh");
        std::fs::write(&path, SNAPD_LIKE).unwrap();
        let findings = discovery::scan_file(&path).unwrap();
        let out = render_findings(&findings);
        assert!(out.contains("4 dépendance(s) implicite(s)"));
        assert!(out.contains("ligne 5"));
        assert!(out.contains("ligne 6"));
        assert!(out.contains("cgroupfs"));
        assert!(out.contains("org.freedesktop.systemd1"));
        assert!(out.contains("cgroup.procs"));
        assert!(out.contains("liste de courses"));
        assert!(out.contains("Capacités uniques (3)"));
        // Le commentaire de la ligne 2 n'est pas une preuve.
        assert!(!out.contains("ligne 2"));
    }

    #[test]
    fn discover_clean_file_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clean.sh");
        std::fs::write(&path, "#!/bin/sh\necho hello\n").unwrap();
        let findings = discovery::scan_file(&path).unwrap();
        assert!(render_findings(&findings).contains("Aucune dépendance implicite"));
    }

    #[test]
    fn discover_missing_file_errors() {
        let args = DiscoverArgs {
            file: PathBuf::from("/nonexistent/omnitia-discover-fixture.sh"),
        };
        assert!(cmd_discover(&args).is_err());
    }

    #[test]
    fn glass_json_store_fixture() {
        let cfg = parse_glass_text(JSON_STORE);
        assert_eq!(cfg, glass::GlassConfig::default());
        let out = render_glass(&cfg, 1.0, "fixture.json");
        // mix(0.8, 9.0, 0.5) = 4.9 ; tint(0) = 0.22 ; rim(1, 0) = 0.10.
        assert!(out.contains("sigma   = 4.90"));
        assert!(out.contains("tint    = 0.22"));
        assert!(out.contains("rim     = 0.10"));
        assert!(out.contains("opacity = 1.00"));
        assert!(out.contains("fixture.json"));
    }

    #[test]
    fn glass_key_value_store_fixture() {
        let cfg = parse_glass_text(KV_STORE);
        assert!((cfg.blur - 0.1).abs() < 1e-6);
        assert!((cfg.rim - 2.0).abs() < 1e-6);
        let out = render_glass(&cfg, 1.0, "fixture.txt");
        // mix(0.8, 9.0, 0.1) = 1.62 ; rim(2, 0) = 0.20.
        assert!(out.contains("sigma   = 1.62"));
        assert!(out.contains("rim     = 0.20"));
    }

    #[test]
    fn glass_scale_multiplies_sigma() {
        let cfg = glass::GlassConfig::default();
        let out = render_glass(&cfg, 2.0, "test");
        assert!(out.contains("sigma   = 9.80"));
    }

    #[test]
    fn glass_reads_explicit_store_file() {
        let dir = tempfile::tempdir().unwrap();
        let json_path = dir.path().join("glass.json");
        std::fs::write(&json_path, JSON_STORE).unwrap();
        let (cfg, source) = load_glass_config(Some(&json_path)).unwrap();
        assert_eq!(cfg, glass::GlassConfig::default());
        assert!(source.contains("glass.json"));

        let kv_path = dir.path().join("glass.txt");
        std::fs::write(&kv_path, KV_STORE).unwrap();
        let (cfg, _) = load_glass_config(Some(&kv_path)).unwrap();
        assert!((cfg.blur - 0.1).abs() < 1e-6);
    }

    #[test]
    fn glass_missing_explicit_store_errors() {
        let err = load_glass_config(Some(Path::new("/nonexistent/omnitia-glass.json")));
        assert!(err.is_err());
    }

    #[test]
    fn glass_no_store_falls_back_to_defaults() {
        // Si un store par défaut traîne dans le répertoire de test, le repli
        // n'est pas observable : on ne teste que le cas sans store.
        if DEFAULT_STORES.iter().any(|c| Path::new(c).is_file()) {
            return;
        }
        let (cfg, source) = load_glass_config(None).unwrap();
        assert_eq!(cfg, glass::GlassConfig::default());
        assert!(source.contains("défauts"));
    }
}
