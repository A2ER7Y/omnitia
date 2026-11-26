//! Tests d'intégration du module `glass` (store de verre partagé Islansia/omnitia).
//!
//! Couvre l'API publique de `omnitia::glass` :
//! - `parse_json_store` : objet plat, clés partielles -> défauts, valeurs invalides ;
//! - `compute` : sigma / tint / rim / opacity (formules Vitreus) ;
//! - round-trip du store sur dossier temporaire (jamais `~/.config`) ;
//! - clamp des paramètres dans 0..1.
//!
//! Aucune dépendance externe : uniquement `std` + le crate `omnitia`.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use omnitia::glass::{blur_sigma, compute, parse_json_store, parse_store, rim, tint, GlassConfig};

/// Tolérance de comparaison flottante (identique aux tests unitaires du module).
const EPS: f32 = 1e-6;

/// Assert `actual` ~= `expected` à `EPS` près.
fn assert_close(actual: f32, expected: f32) {
    assert!(
        (actual - expected).abs() < EPS,
        "attendu {expected}, obtenu {actual}"
    );
}

/// Sérialise une config en objet JSON plat (format du store `glass.json`).
fn to_json(cfg: &GlassConfig) -> String {
    let GlassConfig {
        blur,
        smoke,
        rim,
        milk,
        opacity,
        pv,
    } = *cfg;
    format!(
        "{{\"blur\":{blur},\"smoke\":{smoke},\"rim\":{rim},\
         \"milk\":{milk},\"opacity\":{opacity},\"pv\":{pv}}}"
    )
}

/// Sérialise une config au format key=value (une paire par ligne, `#` commentaire).
fn to_key_value(cfg: &GlassConfig) -> String {
    let GlassConfig {
        blur,
        smoke,
        rim,
        milk,
        opacity,
        pv,
    } = *cfg;
    format!(
        "# store verre partagé\nblur={blur}\nsmoke={smoke}\nrim={rim}\n\
         milk={milk}\nopacity={opacity}\npv={pv}\n"
    )
}

/// Compteur d'unicité des dossiers temporaires (threads de test parallèles).
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// Dossier temporaire unique sous `std::env::temp_dir()`, détruit au drop.
/// N'écrit jamais dans `~/.config` ni aucun emplacement réel de configuration.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "omnitia-glass-it-{}-{tag}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("création du dossier temporaire");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// parse_json_store : objet plat
// ---------------------------------------------------------------------------

#[test]
fn json_flat_object_all_keys() {
    let cfg =
        parse_json_store(r#"{"blur":0.1,"smoke":0.5,"rim":2.0,"milk":0.4,"opacity":0.8,"pv":0.3}"#);
    assert_close(cfg.blur, 0.1);
    assert_close(cfg.smoke, 0.5);
    assert_close(cfg.rim, 2.0);
    assert_close(cfg.milk, 0.4);
    assert_close(cfg.opacity, 0.8);
    assert_close(cfg.pv, 0.3);
}

#[test]
fn json_whitespace_around_keys_and_values() {
    let cfg = parse_json_store("{ \"blur\" : 0.3 , \"smoke\" : 0.7 }");
    assert_close(cfg.blur, 0.3);
    assert_close(cfg.smoke, 0.7);
}

#[test]
fn json_integer_and_out_of_range_values_are_parsed_raw() {
    // `parse_json_store` ne clamp pas : le clamp est fait par `compute`.
    let cfg = parse_json_store(r#"{"rim":2,"blur":-0.5,"smoke":3.0}"#);
    assert_close(cfg.rim, 2.0);
    assert_close(cfg.blur, -0.5);
    assert_close(cfg.smoke, 3.0);
}

#[test]
fn json_unknown_keys_are_ignored() {
    let cfg = parse_json_store(r#"{"theme":"dark","blur":0.2,"extra":42}"#);
    assert_close(cfg.blur, 0.2);
    let d = GlassConfig::default();
    assert_close(cfg.smoke, d.smoke);
    assert_close(cfg.rim, d.rim);
    assert_close(cfg.milk, d.milk);
    assert_close(cfg.opacity, d.opacity);
    assert_close(cfg.pv, d.pv);
}

// ---------------------------------------------------------------------------
// parse_json_store : clés partielles -> défauts
// ---------------------------------------------------------------------------

#[test]
fn json_partial_keys_fall_back_to_defaults() {
    let cfg = parse_json_store(r#"{"smoke":1.0}"#);
    assert_close(cfg.smoke, 1.0);
    let d = GlassConfig::default();
    assert_close(cfg.blur, d.blur);
    assert_close(cfg.rim, d.rim);
    assert_close(cfg.milk, d.milk);
    assert_close(cfg.opacity, d.opacity);
    assert_close(cfg.pv, d.pv);
}

#[test]
fn json_empty_object_and_empty_string_give_defaults() {
    assert_eq!(parse_json_store("{}"), GlassConfig::default());
    assert_eq!(parse_json_store(""), GlassConfig::default());
}

#[test]
fn json_malformed_input_gives_defaults() {
    assert_eq!(parse_json_store("pas du json"), GlassConfig::default());
    assert_eq!(parse_json_store("[0.1, 0.2]"), GlassConfig::default());
}

// ---------------------------------------------------------------------------
// parse_json_store : valeurs invalides -> défauts
// ---------------------------------------------------------------------------

#[test]
fn json_string_value_keeps_default() {
    let cfg = parse_json_store(r#"{"blur":"abc","smoke":0.5}"#);
    assert_close(cfg.blur, GlassConfig::default().blur);
    assert_close(cfg.smoke, 0.5);
}

#[test]
fn json_bare_word_value_keeps_default() {
    let cfg = parse_json_store(r#"{"smoke":not_a_number}"#);
    assert_close(cfg.smoke, GlassConfig::default().smoke);
}

#[test]
fn json_empty_value_keeps_default() {
    let cfg = parse_json_store(r#"{"opacity":}"#);
    assert_close(cfg.opacity, GlassConfig::default().opacity);
}

#[test]
fn json_nested_object_value_keeps_default() {
    // Le parseur ne gère que les objets plats de nombres.
    let cfg = parse_json_store(r#"{"blur":{"x":1},"smoke":0.5}"#);
    assert_close(cfg.blur, GlassConfig::default().blur);
    assert_close(cfg.smoke, 0.5);
}

// ---------------------------------------------------------------------------
// compute : sigma / tint / rim / opacity
// ---------------------------------------------------------------------------

#[test]
fn compute_blur_01_gives_sigma_162() {
    let cfg = GlassConfig {
        blur: 0.1,
        ..Default::default()
    };
    assert_close(compute(&cfg, 1.0).sigma, 1.62);
}

#[test]
fn compute_smoke_1_gives_tint_067() {
    let cfg = GlassConfig {
        smoke: 1.0,
        ..Default::default()
    };
    assert_close(compute(&cfg, 1.0).tint, 0.67);
}

#[test]
fn compute_default_config() {
    let g = compute(&GlassConfig::default(), 1.0);
    assert_close(g.sigma, 4.9); // mix(0.8, 9.0, 0.5)
    assert_close(g.tint, 0.22); // 0.22 + 0.45 * 0
    assert_close(g.rim, 0.10); // 0.10 * 1 + 0.14 * 0 * 1
    assert_close(g.opacity, 1.0);
}

#[test]
fn compute_applies_vitreus_formulas() {
    let cfg = GlassConfig {
        blur: 0.5,
        smoke: 0.5,
        rim: 2.0,
        milk: 0.4,
        opacity: 0.8,
        pv: 0.5,
    };
    let g = compute(&cfg, 2.0);
    assert_close(g.sigma, 9.8); // mix(0.8, 9.0, 0.5) * 2 = 4.9 * 2
    assert_close(g.tint, 0.445); // 0.22 + 0.45 * 0.5
    assert_close(g.rim, 0.34); // 0.10 * 2 + 0.14 * 0.5 * 2
    assert_close(g.opacity, 0.8);
}

#[test]
fn compute_scale_multiplies_sigma_only() {
    let cfg = GlassConfig::default();
    let g1 = compute(&cfg, 1.0);
    let g3 = compute(&cfg, 3.0);
    assert_close(g3.sigma, g1.sigma * 3.0);
    assert_close(g3.tint, g1.tint);
    assert_close(g3.rim, g1.rim);
    assert_close(g3.opacity, g1.opacity);
}

#[test]
fn compute_milk_does_not_change_glass() {
    // `milk` est stocké mais n'entre pas dans le verre calculé.
    let a = compute(
        &GlassConfig {
            milk: 0.0,
            ..Default::default()
        },
        1.0,
    );
    let b = compute(
        &GlassConfig {
            milk: 1.0,
            ..Default::default()
        },
        1.0,
    );
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Fonctions de formule + clamp 0..1
// ---------------------------------------------------------------------------

#[test]
fn blur_sigma_bounds_and_clamp() {
    assert_close(blur_sigma(0.0, 1.0), 0.8);
    assert_close(blur_sigma(1.0, 1.0), 9.0);
    assert_close(blur_sigma(0.5, 1.0), 4.9);
    assert_close(blur_sigma(0.1, 1.0), 1.62);
    // clamp de la force dans 0..1
    assert_close(blur_sigma(-1.0, 1.0), 0.8);
    assert_close(blur_sigma(2.0, 1.0), 9.0);
    // scale
    assert_close(blur_sigma(0.5, 2.0), 9.8);
    assert_close(blur_sigma(1.0, 0.0), 0.0);
}

#[test]
fn tint_bounds_and_clamp() {
    assert_close(tint(0.0), 0.22);
    assert_close(tint(1.0), 0.67);
    assert_close(tint(0.5), 0.445);
    assert_close(tint(-0.5), 0.22);
    assert_close(tint(1.5), 0.67);
}

#[test]
fn rim_formula_and_pv_clamp() {
    assert_close(rim(1.0, 0.0), 0.10);
    assert_close(rim(1.0, 1.0), 0.24);
    assert_close(rim(2.0, 0.5), 0.34);
    // pv clampé dans 0..1
    assert_close(rim(1.0, -1.0), 0.10);
    assert_close(rim(1.0, 2.0), 0.24);
    // glass_rim est un multiplicateur, non clampé
    assert_close(rim(0.0, 1.0), 0.0);
    assert_close(rim(3.0, 0.0), 0.30);
}

#[test]
fn compute_clamps_opacity_and_out_of_range_inputs() {
    let cfg = GlassConfig {
        blur: 5.0,
        smoke: -2.0,
        rim: 1.0,
        milk: 0.4,
        opacity: 1.5,
        pv: 9.0,
    };
    let g = compute(&cfg, 1.0);
    assert_close(g.sigma, 9.0); // blur clampé à 1
    assert_close(g.tint, 0.22); // smoke clampé à 0
    assert_close(g.rim, 0.24); // pv clampé à 1
    assert_close(g.opacity, 1.0); // opacity clampé à 1

    let low = GlassConfig {
        opacity: -0.5,
        ..Default::default()
    };
    assert_close(compute(&low, 1.0).opacity, 0.0);
}

// ---------------------------------------------------------------------------
// parse_store (key=value) — l'autre format du store partagé
// ---------------------------------------------------------------------------

#[test]
fn parse_store_key_value_with_comments_and_blank_lines() {
    let cfg = parse_store("# commentaire\nblur=0.1\n\nsmoke=0.5\nrim=2.0\n");
    assert_close(cfg.blur, 0.1);
    assert_close(cfg.smoke, 0.5);
    assert_close(cfg.rim, 2.0);
    assert_close(cfg.milk, GlassConfig::default().milk);
}

#[test]
fn parse_store_invalid_value_becomes_zero() {
    // Contrairement au JSON, une valeur invalide vaut 0.0 (unwrap_or).
    let cfg = parse_store("blur=abc\nsmoke=0.5\n");
    assert_close(cfg.blur, 0.0);
    assert_close(cfg.smoke, 0.5);
}

// ---------------------------------------------------------------------------
// Round-trip du store sur dossier temporaire
// ---------------------------------------------------------------------------

#[test]
fn round_trip_json_store_in_temp_dir() {
    let tmp = TempDir::new("json");
    let cfg = GlassConfig {
        blur: 0.1,
        smoke: 0.5,
        rim: 2.0,
        milk: 0.4,
        opacity: 0.8,
        pv: 0.3,
    };
    let file = tmp.path.join("glass.json");
    fs::write(&file, to_json(&cfg)).expect("écriture du store JSON");
    let read = fs::read_to_string(&file).expect("lecture du store JSON");
    let parsed = parse_json_store(&read);
    assert_eq!(parsed, cfg);
    // Bout en bout : le verre calculé est identique après round-trip.
    assert_eq!(compute(&parsed, 1.5), compute(&cfg, 1.5));
}

#[test]
fn round_trip_key_value_store_in_temp_dir() {
    let tmp = TempDir::new("kv");
    let cfg = GlassConfig {
        blur: 0.25,
        smoke: 0.75,
        rim: 1.5,
        milk: 0.2,
        opacity: 0.9,
        pv: 0.1,
    };
    let file = tmp.path.join("glass.store");
    fs::write(&file, to_key_value(&cfg)).expect("écriture du store key=value");
    let read = fs::read_to_string(&file).expect("lecture du store key=value");
    assert_eq!(parse_store(&read), cfg);
}

#[test]
fn json_and_key_value_stores_agree() {
    // Les deux formats du store partagé décrivent la même config.
    let tmp = TempDir::new("cross");
    let cfg = GlassConfig {
        blur: 0.3,
        smoke: 0.6,
        rim: 2.0,
        milk: 0.4,
        opacity: 0.7,
        pv: 0.2,
    };
    let json_file = tmp.path.join("glass.json");
    let kv_file = tmp.path.join("glass.store");
    fs::write(&json_file, to_json(&cfg)).expect("écriture JSON");
    fs::write(&kv_file, to_key_value(&cfg)).expect("écriture key=value");
    let from_json = parse_json_store(&fs::read_to_string(&json_file).expect("lecture JSON"));
    let from_kv = parse_store(&fs::read_to_string(&kv_file).expect("lecture key=value"));
    assert_eq!(from_json, cfg);
    assert_eq!(from_kv, cfg);
    assert_eq!(from_json, from_kv);
}

#[test]
fn round_trip_partial_json_keeps_defaults() {
    let tmp = TempDir::new("partial");
    let file = tmp.path.join("glass.json");
    fs::write(&file, r#"{"smoke":1.0}"#).expect("écriture du store partiel");
    let cfg = parse_json_store(&fs::read_to_string(&file).expect("lecture du store partiel"));
    assert_close(cfg.smoke, 1.0);
    assert_close(cfg.blur, GlassConfig::default().blur);
    assert_close(cfg.opacity, GlassConfig::default().opacity);
}

#[test]
fn store_update_changes_computed_glass() {
    // « je passe à 10% ça change » : Islansia réécrit le store, omnitia recalcule.
    let tmp = TempDir::new("update");
    let file = tmp.path.join("glass.json");

    fs::write(&file, r#"{"blur":0.1}"#).expect("écriture initiale");
    let before = compute(
        &parse_json_store(&fs::read_to_string(&file).expect("lecture initiale")),
        1.0,
    );

    fs::write(&file, r#"{"blur":0.9}"#).expect("mise à jour");
    let after = compute(
        &parse_json_store(&fs::read_to_string(&file).expect("lecture mise à jour")),
        1.0,
    );

    assert_close(before.sigma, 1.62);
    assert_close(after.sigma, 8.18); // mix(0.8, 9.0, 0.9)
    assert!(after.sigma > before.sigma);
}
