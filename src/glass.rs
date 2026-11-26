//! Module `glass` — réutilise la formule de verre Vitreus.
//!
//! Source de la formule (vérifiée) :
//!   - `islansia-vitreus/scenes/vitreus-blur.wgsl:4-6` : sigma = mix(0.8, 9.0, force) * scale
//!   - `bar_glass.plm` / INVENTAIRE-VITREUS : tint = 22% + 45%*smoke, rim = 10%*rim + 14%*pv*rim
//!
//! Le paramètre est PARTAGÉ avec Islansia : les deux lisent/écrivent le même
//! store de config (JSON, `glass.json`). Changer le verre dans l'app Paramètres
//! d'Islansia met à jour le store → omnitia recalcule son verre.

/// Paramètres de verre partagés (lus depuis le store commun Islansia/omnitia).
#[derive(Debug, Clone, PartialEq)]
pub struct GlassConfig {
    pub blur: f32,    // force 0..1 (slider Glass)
    pub smoke: f32,   // 0..1
    pub rim: f32,     // multiplicateur glass_rim
    pub milk: f32,    // 0..1
    pub opacity: f32, // 0..1
    pub pv: f32,      // beat / pression 0..1
}

impl Default for GlassConfig {
    fn default() -> Self {
        Self {
            blur: 0.5,
            smoke: 0.0,
            rim: 1.0,
            milk: 0.4,
            opacity: 1.0,
            pv: 0.0,
        }
    }
}

fn clamp01(x: f32) -> f32 {
    x.clamp(0.0, 1.0)
}

fn mix(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

/// Sigma du blur gaussien — `vitreus-blur.wgsl:4-6`.
/// `sigma = mix(0.8, 9.0, clamp(force, 0, 1)) * scale`
pub fn blur_sigma(force: f32, scale: f32) -> f32 {
    mix(0.8, 9.0, clamp01(force)) * scale
}

/// Tint du verre — `tint = 22% + 45% * smoke`.
pub fn tint(smoke: f32) -> f32 {
    0.22 + 0.45 * clamp01(smoke)
}

/// Rim du verre — `rim = 10% * glass_rim + 14% * pv * glass_rim`.
pub fn rim(glass_rim: f32, pv: f32) -> f32 {
    0.10 * glass_rim + 0.14 * clamp01(pv) * glass_rim
}

/// Verre calculé : ce que le renderer applique.
#[derive(Debug, Clone, PartialEq)]
pub struct Glass {
    pub sigma: f32,
    pub tint: f32,
    pub rim: f32,
    pub opacity: f32,
}

/// Calcule le verre depuis la config partagée.
pub fn compute(cfg: &GlassConfig, scale: f32) -> Glass {
    Glass {
        sigma: blur_sigma(cfg.blur, scale),
        tint: tint(cfg.smoke),
        rim: rim(cfg.rim, cfg.pv),
        opacity: clamp01(cfg.opacity),
    }
}

/// Parse le store partagé (key=value, une paire par ligne, `#` = commentaire).
pub fn parse_store(s: &str) -> GlassConfig {
    let mut cfg = GlassConfig::default();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v: f32 = v.trim().parse().unwrap_or(0.0);
            match k.trim() {
                "blur" => cfg.blur = v,
                "smoke" => cfg.smoke = v,
                "rim" => cfg.rim = v,
                "milk" => cfg.milk = v,
                "opacity" => cfg.opacity = v,
                "pv" => cfg.pv = v,
                _ => {}
            }
        }
    }
    cfg
}

/// Extrait la valeur numérique d'une clé dans un objet JSON plat (`"clé": nombre`).
/// Parseur minimal std-only pour le store de verre (objet plat de nombres).
fn json_num(s: &str, key: &str) -> Option<f32> {
    let pat = format!("\"{}\"", key);
    let idx = s.find(&pat)?;
    let rest = s[idx + pat.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let end = rest
        .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Parse le store partagé JSON (objet plat `{"blur":0.5,"smoke":0.0,...}`).
/// C'est le format lu par l'île Vitreus (`state/glass.json`, `files.read "json"`).
pub fn parse_json_store(s: &str) -> GlassConfig {
    let mut cfg = GlassConfig::default();
    if let Some(v) = json_num(s, "blur") {
        cfg.blur = v;
    }
    if let Some(v) = json_num(s, "smoke") {
        cfg.smoke = v;
    }
    if let Some(v) = json_num(s, "rim") {
        cfg.rim = v;
    }
    if let Some(v) = json_num(s, "milk") {
        cfg.milk = v;
    }
    if let Some(v) = json_num(s, "opacity") {
        cfg.opacity = v;
    }
    if let Some(v) = json_num(s, "pv") {
        cfg.pv = v;
    }
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigma_matches_vitreus() {
        // vitreus-blur.wgsl : mix(0.8, 9.0, force)
        assert!((blur_sigma(0.0, 1.0) - 0.8).abs() < 1e-6);
        assert!((blur_sigma(1.0, 1.0) - 9.0).abs() < 1e-6);
        assert!((blur_sigma(0.5, 1.0) - 4.9).abs() < 1e-6);
        // clamp hors bornes
        assert!((blur_sigma(2.0, 1.0) - 9.0).abs() < 1e-6);
    }

    #[test]
    fn tint_rim_match_vitreus() {
        assert!((tint(0.0) - 0.22).abs() < 1e-6);
        assert!((tint(1.0) - 0.67).abs() < 1e-6);
        assert!((rim(1.0, 0.0) - 0.10).abs() < 1e-6);
        assert!((rim(1.0, 1.0) - 0.24).abs() < 1e-6);
    }

    #[test]
    fn parse_store_reads_params() {
        let cfg = parse_store("blur=0.1\nsmoke=0.5\n# commentaire\nrim=2.0\n");
        assert!((cfg.blur - 0.1).abs() < 1e-6);
        assert!((cfg.smoke - 0.5).abs() < 1e-6);
        assert!((cfg.rim - 2.0).abs() < 1e-6);
    }

    #[test]
    fn compute_10pct_changes_glass() {
        // « je passe à 10% ça change » : blur 0.1 vs 0.5 → sigma différent.
        let low = compute(
            &GlassConfig {
                blur: 0.1,
                ..Default::default()
            },
            1.0,
        );
        let mid = compute(
            &GlassConfig {
                blur: 0.5,
                ..Default::default()
            },
            1.0,
        );
        assert!((low.sigma - 1.62).abs() < 1e-6); // mix(0.8,9.0,0.1)=1.62
        assert!((mid.sigma - 4.9).abs() < 1e-6);
        assert!(low.sigma != mid.sigma);
    }

    #[test]
    fn parse_json_store_matches_island_format() {
        let cfg = parse_json_store(
            r#"{"blur":0.1,"smoke":0.5,"rim":2.0,"milk":0.4,"opacity":1.0,"pv":0.0}"#,
        );
        assert!((cfg.blur - 0.1).abs() < 1e-6);
        assert!((cfg.smoke - 0.5).abs() < 1e-6);
        assert!((cfg.rim - 2.0).abs() < 1e-6);
        // clés absentes → défauts
        let partial = parse_json_store(r#"{"smoke":1.0}"#);
        assert!((partial.smoke - 1.0).abs() < 1e-6);
        assert!((partial.blur - 0.5).abs() < 1e-6);
    }
}
