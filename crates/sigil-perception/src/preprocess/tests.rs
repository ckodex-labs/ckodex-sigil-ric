//! Parity is the gate: the Rust model view must equal the reference bytes
//! recorded in specimens.json (computed with Pillow / transformers, never with
//! this code).

use super::*;
use sha2::{Digest, Sha384};

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/multimodal")
        .join(name)
}

fn reference(key: &str) -> String {
    let specimens: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture("specimens.json")).expect("specimens"),
    )
    .expect("json");
    specimens["image"]["views"][key]
        .as_str()
        .expect("reference hash")
        .to_string()
}

fn source() -> Rgb8 {
    let img = image::ImageReader::open(fixture("attack_source.png"))
        .expect("open")
        .decode()
        .expect("decode")
        .to_rgb8();
    Rgb8 {
        width: img.width() as usize,
        height: img.height() as usize,
        data: img.into_raw(),
    }
}

fn sha384(bytes: &[u8]) -> String {
    Sha384::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn cv_ric_031_qwen2vl_view_is_bit_exact_with_the_reference() {
    let profile =
        builtin("qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow").expect("profile");
    let view = profile.model_view(&source()).expect("view");
    assert_eq!(view.parity, ConsumedParity::ReferenceMatched);
    assert_eq!((view.image.width, view.image.height), (644, 644));
    assert_eq!(
        sha384(&view.image.data),
        reference("qwen2vl_644_bicubic_rgb_sha384")
    );
}

#[test]
fn cv_ric_031_nearest_80_view_is_bit_exact_with_the_reference() {
    let profile = builtin("thumbnail/nearest-80").expect("profile");
    let view = profile.model_view(&source()).expect("view");
    assert_eq!(view.parity, ConsumedParity::ReferenceMatched);
    assert_eq!(sha384(&view.image.data), reference("nearest_80_rgb_sha384"));
}

#[test]
fn cv_ric_031_resampler_matches_pillow_across_sizes() {
    // Hashes produced by scripts/reference/pillow_parity.py (Pillow 13.0.0):
    // upscales, integer and non-integer downscales, odd and anisotropic sizes.
    let parity: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture("pillow_parity.json")).expect("parity fixture"),
    )
    .expect("json");
    // Every case follows the pass order Pillow 13's source picks. Where both
    // axes shrink, the fixture straddles the boundary, and the other order
    // must give different bytes there, so each such case discriminates.
    assert_eq!(parity["pillow"], "13.0.0");
    let src = source();
    let (mut mismatches, mut shrink_both) = (Vec::new(), [0, 0]);
    for case in parity["cases"].as_array().expect("cases") {
        let (w, h) = (
            case["width"].as_u64().expect("w") as usize,
            case["height"].as_u64().expect("h") as usize,
        );
        let expected = case["rgb_sha384"].as_str().expect("hash");
        let matches = match case["kernel"].as_str() {
            Some("bicubic") => {
                let order = pillow13_pass_order(src.width, src.height, w, h);
                if w < src.width && h < src.height {
                    shrink_both[usize::from(order == PassOrder::VerticalFirst)] += 1;
                    let other = match order {
                        PassOrder::HorizontalFirst => PassOrder::VerticalFirst,
                        PassOrder::VerticalFirst => PassOrder::HorizontalFirst,
                    };
                    assert_ne!(
                        sha384(&resize_bicubic(&src, w, h, other).data),
                        expected,
                        "{w}x{h} does not discriminate the order"
                    );
                }
                sha384(&resize_bicubic(&src, w, h, order).data) == expected
            }
            Some("nearest") => sha384(&resize_nearest(&src, w, h).data) == expected,
            other => panic!("unknown kernel {other:?}"),
        };
        if !matches {
            mismatches.push(format!("{} {w}x{h}", case["kernel"]));
        }
    }
    assert!(mismatches.is_empty(), "differs from Pillow: {mismatches:?}");
    assert!(
        shrink_both[0] >= 4 && shrink_both[1] >= 4,
        "both sides of the shrink-both boundary: {shrink_both:?}"
    );
}

#[test]
fn cv_ric_031_a_view_carries_its_profiles_parity_and_is_never_promoted() {
    // Pillow 13's pass order is known for every size (Resample.c), so a
    // reference-matched bicubic profile that shrinks both axes keeps its
    // parity, and the view is the bytes Pillow produces (the parity vector
    // above).
    let shrink = PreprocessorProfile {
        name: "test/bicubic-300".to_string(),
        spec: ProfileSpec::Image {
            kernel: ImageKernel::PillowBicubic,
            resize: ResizeRule::Fixed {
                width: 300,
                height: 300,
            },
            patching: None,
        },
        parity: ConsumedParity::ReferenceMatched,
    };
    let view = shrink.model_view(&source()).expect("view");
    assert_eq!(view.parity, ConsumedParity::ReferenceMatched);
    // An approximate profile is never promoted by any input.
    let mut approx = shrink.clone();
    approx.parity = ConsumedParity::Approximate;
    approx.spec = ProfileSpec::Image {
        kernel: ImageKernel::PillowBicubic,
        resize: ResizeRule::Fixed {
            width: 700,
            height: 700,
        },
        patching: None,
    };
    assert_eq!(
        approx.model_view(&source()).expect("view").parity,
        ConsumedParity::Approximate
    );
}

#[test]
fn smart_resize_matches_the_documented_rule() {
    assert_eq!(
        smart_resize(640, 640, 28, 3_136, 12_845_056),
        Some((644, 644))
    );
    // Python round() is half-to-even: 42 / 28 = 1.5 -> 2, 70 / 28 = 2.5 -> 2.
    assert_eq!(smart_resize(42, 70, 28, 0, u64::MAX), Some((56, 56)));
    // Below min_pixels the image grows to the minimum.
    assert_eq!(smart_resize(10, 10, 28, 3_136, 12_845_056), Some((56, 56)));
    assert_eq!(
        smart_resize(1, 500, 28, 3_136, 12_845_056),
        None,
        "aspect > 200"
    );
}

#[test]
fn placeholder_count_matches_the_processor() {
    let profile =
        builtin("qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow").expect("profile");
    assert_eq!(profile.placeholder_count(644, 644), Some(529));
}

#[test]
fn profile_identity_is_stable_and_field_sensitive() {
    let a = builtin("thumbnail/nearest-80").expect("profile");
    assert_eq!(a.digest(), a.clone().digest());
    let mut b = a.clone();
    b.spec = ProfileSpec::Image {
        kernel: ImageKernel::PillowBicubic,
        resize: ResizeRule::Fixed {
            width: 80,
            height: 80,
        },
        patching: None,
    };
    assert_ne!(a.digest(), b.digest(), "kernel is bound");
    let mut c = a.clone();
    c.parity = ConsumedParity::Approximate;
    assert_eq!(a.digest(), c.digest(), "parity is measured, not identity");
    let names: std::collections::HashSet<String> = BUILTIN_PROFILES
        .iter()
        .map(|n| builtin(n).expect("builtin").digest())
        .collect();
    assert_eq!(names.len(), BUILTIN_PROFILES.len());
}

#[test]
fn cv_ric_031_decimated_waveform_is_bit_exact_with_the_reference() {
    // specimens.json audio.waveform_16k_sha384.decimate_x6: sha384 over the
    // channel-0 int16 LE samples of x[::6], computed with numpy.
    let mut reader = hound::WavReader::open(fixture("attack_96k.wav")).expect("wav");
    let spec = reader.spec();
    let channels = usize::from(spec.channels);
    let channel0: Vec<i16> = reader
        .samples::<i16>()
        .step_by(channels)
        .collect::<Result<_, _>>()
        .expect("samples");
    let profile = builtin("audio/16k-decimate").expect("profile");
    let (view, parity) = profile
        .audio_view(&channel0, u64::from(spec.sample_rate))
        .expect("view");
    assert_eq!(parity, ConsumedParity::ReferenceMatched);
    let bytes: Vec<u8> = view.iter().flat_map(|s| s.to_le_bytes()).collect();
    let specimens: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture("specimens.json")).expect("specimens"),
    )
    .expect("json");
    assert_eq!(
        sha384(&bytes),
        specimens["audio"]["waveform_16k_sha384"]["decimate_x6"]
    );
    // 44.1 kHz has no whole decimation ratio to 16 kHz: no view, no claim.
    assert_eq!(profile.audio_view(&channel0, 44_100), None);
    // The filtered profile has no in-process implementation: no view.
    let filtered = builtin("whisper/16k-filtered").expect("profile");
    assert_eq!(filtered.audio_view(&channel0, 96_000), None);
}
