//! Stream 4 — intégration verre : store partagé JSON ↔ config omnitia.
//!
//! Le verre est partagé avec l'île Islansia/Vitreus via un store JSON plat
//! (`~/.config/velotia/glass.json`, clés `blur`/`smoke`/`rim`/`milk`/`opacity`/`pv`).
//! Ce module lit/écrit ce store via [`crate::glass`] (`parse_json_store`/`compute`)
//! et expose le verre comme paramètre de config aux côtés de la config omni
//! ([`crate::config::OmniConfig`]) : quand le store change, le verre est recalculé
//! ([`GlassBridge::refresh`]).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::OmniConfig;
use crate::glass::{self, Glass, GlassConfig};

/// Chemin par défaut du store partagé : `~/.config/velotia/glass.json`.
///
/// # Errors
///
/// Renvoie une erreur si le dossier de configuration utilisateur est introuvable.
pub fn default_store_path() -> Result<PathBuf> {
    let dir = dirs::config_dir().context("dossier de configuration utilisateur introuvable")?;
    Ok(dir.join("velotia").join("glass.json"))
}

/// Assainit une config de verre.
///
/// `blur`, `smoke`, `milk`, `opacity`, `pv` sont bornés à 0..=1 ; `rim` est un
/// multiplicateur (conservé tel quel, sauf non-fini). Toute valeur non finie
/// (`NaN`/inf) retombe sur le défaut.
#[must_use]
pub fn sanitize(cfg: &GlassConfig) -> GlassConfig {
    let d = GlassConfig::default();
    let unit = |v: f32, def: f32| {
        if v.is_finite() {
            v.clamp(0.0, 1.0)
        } else {
            def
        }
    };
    GlassConfig {
        blur: unit(cfg.blur, d.blur),
        smoke: unit(cfg.smoke, d.smoke),
        rim: if cfg.rim.is_finite() { cfg.rim } else { d.rim },
        milk: unit(cfg.milk, d.milk),
        opacity: unit(cfg.opacity, d.opacity),
        pv: unit(cfg.pv, d.pv),
    }
}

/// Lit le store et renvoie (config assainie, contenu brut) ; absent → défauts.
fn read_store(path: &Path) -> Result<(GlassConfig, Option<String>)> {
    match fs::read_to_string(path) {
        Ok(raw) => Ok((sanitize(&glass::parse_json_store(&raw)), Some(raw))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((GlassConfig::default(), None)),
        Err(e) => Err(e).with_context(|| format!("lecture du store de verre {}", path.display())),
    }
}

/// Lit le store de verre partagé (objet JSON plat, format île Vitreus).
///
/// - Fichier absent → [`GlassConfig::default`] (pas d'erreur).
/// - Contenu parsé via [`glass::parse_json_store`] puis assaini (clamp 0..=1,
///   `rim` multiplicateur conservé).
///
/// # Errors
///
/// Renvoie une erreur si le fichier existe mais ne peut pas être lu.
pub fn load_store(path: &Path) -> Result<GlassConfig> {
    read_store(path).map(|(cfg, _)| cfg)
}

/// Écrit le store de verre partagé (objet JSON plat `{"blur":…,"smoke":…,…}`).
///
/// Les valeurs sont assainies avant écriture ; le dossier parent est créé si
/// besoin. Le format est celui lu par l'île Vitreus (`glass::parse_json_store`).
///
/// # Errors
///
/// Renvoie une erreur si le dossier parent ne peut pas être créé ou le fichier
/// écrit.
pub fn save_store(path: &Path, cfg: &GlassConfig) -> Result<()> {
    let cfg = sanitize(cfg);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("création du dossier {}", parent.display()))?;
        }
    }
    let json = serde_json::json!({
        "blur": cfg.blur,
        "smoke": cfg.smoke,
        "rim": cfg.rim,
        "milk": cfg.milk,
        "opacity": cfg.opacity,
        "pv": cfg.pv,
    });
    let raw = serde_json::to_string(&json).context("sérialisation du store de verre")?;
    fs::write(path, raw)
        .with_context(|| format!("écriture du store de verre {}", path.display()))?;
    Ok(())
}

/// Calcule le verre rendu depuis la config de verre (formule Vitreus).
///
/// Pont direct vers [`glass::compute`] : `sigma = mix(0.8, 9.0, blur) * scale`,
/// `tint = 22% + 45% * smoke`, `rim = 10% * rim + 14% * pv * rim`.
#[must_use]
pub fn glass_from_config(cfg: &GlassConfig, scale: f32) -> Glass {
    glass::compute(cfg, scale)
}

/// Pont entre la config omni et le store de verre partagé.
///
/// Expose le verre comme paramètre de config ([`GlassBridge::glass_config`])
/// à côté de la config omni ([`GlassBridge::omni_config`]).
/// [`GlassBridge::refresh`] relit le store et recalcule le verre uniquement
/// quand son contenu change (comparaison du contenu brut, pas de la date).
pub struct GlassBridge {
    omni: OmniConfig,
    store_path: PathBuf,
    scale: f32,
    cfg: GlassConfig,
    glass: Glass,
    raw: Option<String>,
}

impl GlassBridge {
    /// Charge le store (défauts si absent) et calcule le verre (échelle 1.0).
    ///
    /// # Errors
    ///
    /// Renvoie une erreur si le store existe mais ne peut pas être lu.
    pub fn new(omni: &OmniConfig, store_path: PathBuf) -> Result<Self> {
        let (cfg, raw) = read_store(&store_path)?;
        let glass = glass_from_config(&cfg, 1.0);
        Ok(Self {
            omni: omni.clone(),
            store_path,
            scale: 1.0,
            cfg,
            glass,
            raw,
        })
    }

    /// Change l'échelle du blur et recalcule le verre.
    ///
    /// Une échelle non finie ou négative/nulle retombe sur 1.0.
    #[must_use]
    pub fn with_scale(mut self, scale: f32) -> Self {
        self.scale = if scale.is_finite() && scale > 0.0 {
            scale
        } else {
            1.0
        };
        self.glass = glass_from_config(&self.cfg, self.scale);
        self
    }

    /// Config omni portée par le pont.
    #[must_use]
    pub const fn omni_config(&self) -> &OmniConfig {
        &self.omni
    }

    /// Le verre comme paramètre de config (store partagé, assaini).
    #[must_use]
    pub const fn glass_config(&self) -> &GlassConfig {
        &self.cfg
    }

    /// Verre calculé : ce que le renderer applique.
    #[must_use]
    pub const fn glass(&self) -> &Glass {
        &self.glass
    }

    /// Chemin du store partagé.
    #[must_use]
    pub fn store_path(&self) -> &Path {
        &self.store_path
    }

    /// Relit le store ; recalcule le verre si le contenu a changé.
    ///
    /// Renvoie `true` si le verre a été recalculé, `false` si le store est
    /// inchangé. Un store supprimé retombe sur les défauts.
    ///
    /// # Errors
    ///
    /// Renvoie une erreur si le store existe mais ne peut pas être lu.
    pub fn refresh(&mut self) -> Result<bool> {
        let (cfg, raw) = read_store(&self.store_path)?;
        if raw == self.raw {
            return Ok(false);
        }
        self.cfg = cfg;
        self.raw = raw;
        self.glass = glass_from_config(&self.cfg, self.scale);
        Ok(true)
    }

    /// Met à jour le verre côté omni : écrit le store partagé puis recalcule.
    ///
    /// # Errors
    ///
    /// Renvoie une erreur si le store ne peut pas être écrit ou relu.
    pub fn set_glass_config(&mut self, cfg: &GlassConfig) -> Result<()> {
        save_store(&self.store_path, cfg)?;
        let (cfg, raw) = read_store(&self.store_path)?;
        self.cfg = cfg;
        self.raw = raw;
        self.glass = glass_from_config(&self.cfg, self.scale);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Comparaison champ à champ avec epsilon (pas de `==` sur les flottants).
    fn assert_cfg_close(a: &GlassConfig, b: &GlassConfig) {
        for (x, y) in [
            (a.blur, b.blur),
            (a.smoke, b.smoke),
            (a.rim, b.rim),
            (a.milk, b.milk),
            (a.opacity, b.opacity),
            (a.pv, b.pv),
        ] {
            assert!((x - y).abs() < 1e-6, "{x} != {y}");
        }
    }

    fn assert_glass_close(a: &Glass, b: &Glass) {
        for (x, y) in [
            (a.sigma, b.sigma),
            (a.tint, b.tint),
            (a.rim, b.rim),
            (a.opacity, b.opacity),
        ] {
            assert!((x - y).abs() < 1e-6, "{x} != {y}");
        }
    }

    fn sample() -> GlassConfig {
        GlassConfig {
            blur: 0.25,
            smoke: 0.75,
            rim: 2.0,
            milk: 0.1,
            opacity: 0.9,
            pv: 0.3,
        }
    }

    #[test]
    fn round_trip_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("glass.json");
        let cfg = sample();
        save_store(&path, &cfg).unwrap();
        // Format objet plat compatible île Vitreus : parse_json_store le relit.
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"blur\""));
        assert_cfg_close(&glass::parse_json_store(&raw), &cfg);
        assert_cfg_close(&load_store(&path).unwrap(), &cfg);
    }

    #[test]
    fn defaults_when_absent() {
        let dir = tempdir().unwrap();
        let cfg = load_store(&dir.path().join("absent.json")).unwrap();
        assert_cfg_close(&cfg, &GlassConfig::default());
    }

    #[test]
    fn load_clamps_out_of_range() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("glass.json");
        fs::write(
            &path,
            r#"{"blur":2.5,"smoke":-0.5,"rim":2.0,"milk":3.0,"opacity":-1.0,"pv":1.5}"#,
        )
        .unwrap();
        let cfg = load_store(&path).unwrap();
        assert!((cfg.blur - 1.0).abs() < 1e-6);
        assert!(cfg.smoke.abs() < 1e-6);
        assert!((cfg.rim - 2.0).abs() < 1e-6); // multiplicateur conservé
        assert!((cfg.milk - 1.0).abs() < 1e-6);
        assert!(cfg.opacity.abs() < 1e-6);
        assert!((cfg.pv - 1.0).abs() < 1e-6);
    }

    #[test]
    fn save_creates_parent_dirs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("sub").join("glass.json");
        save_store(&path, &sample()).unwrap();
        assert!(path.exists());
        assert_cfg_close(&load_store(&path).unwrap(), &sample());
    }

    #[test]
    fn partial_store_keeps_defaults() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("glass.json");
        fs::write(&path, r#"{"smoke":1.0}"#).unwrap();
        let cfg = load_store(&path).unwrap();
        assert!((cfg.smoke - 1.0).abs() < 1e-6);
        assert!((cfg.blur - 0.5).abs() < 1e-6);
        assert!((cfg.rim - 1.0).abs() < 1e-6);
    }

    #[test]
    fn save_sanitizes_before_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("glass.json");
        let cfg = GlassConfig {
            blur: 5.0,
            opacity: -2.0,
            ..Default::default()
        };
        save_store(&path, &cfg).unwrap();
        let loaded = load_store(&path).unwrap();
        assert!((loaded.blur - 1.0).abs() < 1e-6);
        assert!(loaded.opacity.abs() < 1e-6);
    }

    #[test]
    fn sanitize_non_finite_falls_back() {
        let cfg = GlassConfig {
            blur: f32::NAN,
            rim: f32::INFINITY,
            pv: f32::NEG_INFINITY,
            ..Default::default()
        };
        let s = sanitize(&cfg);
        assert!((s.blur - 0.5).abs() < 1e-6);
        assert!((s.rim - 1.0).abs() < 1e-6);
        assert!(s.pv.abs() < 1e-6);
    }

    #[test]
    fn glass_from_config_matches_vitreus() {
        let cfg = GlassConfig {
            blur: 0.5,
            smoke: 1.0,
            rim: 1.0,
            pv: 1.0,
            ..Default::default()
        };
        let g = glass_from_config(&cfg, 2.0);
        assert!((g.sigma - 9.8).abs() < 1e-6); // mix(0.8, 9.0, 0.5) * 2
        assert!((g.tint - 0.67).abs() < 1e-6);
        assert!((g.rim - 0.24).abs() < 1e-6);
        assert_glass_close(&g, &glass::compute(&cfg, 2.0));
    }

    #[test]
    fn bridge_recomputes_when_store_changes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("glass.json");
        let low = GlassConfig {
            blur: 0.1,
            ..Default::default()
        };
        save_store(&path, &low).unwrap();
        let mut bridge = GlassBridge::new(&OmniConfig::default(), path.clone()).unwrap();
        assert!((bridge.glass().sigma - 1.62).abs() < 1e-6);
        assert!(!bridge.refresh().unwrap()); // store inchangé → pas de recalcul
        let high = GlassConfig {
            blur: 0.9,
            ..Default::default()
        };
        save_store(&path, &high).unwrap(); // écriture « côté Islansia »
        assert!(bridge.refresh().unwrap());
        assert!((bridge.glass().sigma - 8.18).abs() < 1e-6); // mix(0.8, 9.0, 0.9)
        assert_cfg_close(bridge.glass_config(), &high);
        assert!(!bridge.refresh().unwrap());
    }

    #[test]
    fn bridge_set_glass_persists_to_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("glass.json");
        let mut bridge = GlassBridge::new(&OmniConfig::default(), path.clone()).unwrap();
        assert_cfg_close(bridge.glass_config(), &GlassConfig::default());
        let cfg = sample();
        bridge.set_glass_config(&cfg).unwrap();
        assert_cfg_close(&load_store(&path).unwrap(), &cfg);
        assert_glass_close(bridge.glass(), &glass_from_config(&cfg, 1.0));
        assert!(!bridge.refresh().unwrap());
    }

    #[test]
    fn bridge_store_deleted_falls_back_to_defaults() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("glass.json");
        save_store(&path, &sample()).unwrap();
        let mut bridge = GlassBridge::new(&OmniConfig::default(), path.clone()).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(bridge.refresh().unwrap());
        assert_cfg_close(bridge.glass_config(), &GlassConfig::default());
    }

    #[test]
    fn bridge_scale_and_omni_accessors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("glass.json");
        let omni = OmniConfig::default();
        let bridge = GlassBridge::new(&omni, path.clone())
            .unwrap()
            .with_scale(2.0);
        assert!((bridge.glass().sigma - 9.8).abs() < 1e-6); // blur défaut 0.5, scale 2
        assert_eq!(bridge.store_path(), path.as_path());
        assert_eq!(
            bridge.omni_config().general.max_parallel_jobs,
            omni.general.max_parallel_jobs
        );
        let bad = bridge.with_scale(f32::NAN);
        assert!((bad.glass().sigma - 4.9).abs() < 1e-6); // échelle invalide → 1.0
    }

    #[test]
    fn default_store_path_is_velotia_glass_json() {
        // Calcul de chemin uniquement : aucune écriture dans ~/.config réel.
        let path = default_store_path().unwrap();
        assert!(path.ends_with("velotia/glass.json"));
    }
}
