//! Identity v2 must change whenever anything that decides an extractor's
//! output changes, and only then.

use super::{EXTRACTOR_IDENTITY_V1, EXTRACTOR_IDENTITY_V2, ExtractorIdentity};

const BINARY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ENCODER_A: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ENCODER_B: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn asr(args: &[&str], models: &[&str]) -> ExtractorIdentity {
    ExtractorIdentity::bound(
        "external-transcript".to_string(),
        "external".to_string(),
        BINARY.to_string(),
        args.iter().map(ToString::to_string).collect(),
        models.iter().map(ToString::to_string).collect(),
    )
}

#[test]
fn matches_an_independent_reference_encoding() {
    // Expected value computed outside Rust (Python hashlib + struct.pack over
    // the encoding documented in the module header).
    let id = asr(&["ffmpeg"], &[ENCODER_B, ENCODER_A]);
    assert_eq!(
        id.identity_digest,
        "d2f8c8c5f9cd0f81734b6ce5d3a6e1b467102692dff6514759f8695e7c4eb6fb21b5d1de3858f0073c5acffec92e8218"
    );
    assert_eq!(id.identity_version, EXTRACTOR_IDENTITY_V2);
}

#[test]
fn in_process_identity_matches_the_reference_encoding() {
    let id = ExtractorIdentity::in_process(
        "x/spectral".to_string(),
        "realfft/3.5".to_string(),
        &[("window", "4096".to_string())],
    );
    assert_eq!(
        id.config_digest,
        "f790bb799e33a2de7cb549d23215c6e016e455568de656295c73b650b06116647de6ba64036ad759d2fe03c7a7b92c98"
    );
    assert_eq!(
        id.identity_digest,
        "975aea1e3260b5ff27f5c919d8235233fbd9890bbd9b17b756af4fcac1650347b216a417c758fe59727689fd22cac46a"
    );
}

#[test]
fn arguments_are_bound_cv_ric_022() {
    // The resample policy is an argument: same binary, same weights, a
    // different interpreter.
    let filtered = asr(&["ffmpeg"], &[ENCODER_A]);
    let decimated = asr(&["naive"], &[ENCODER_A]);
    assert_ne!(filtered.identity_digest, decimated.identity_digest);
    assert_eq!(
        filtered.config_digest, decimated.config_digest,
        "binary pin unchanged"
    );
}

#[test]
fn model_weights_are_bound_cv_ric_023() {
    let original = asr(&["ffmpeg"], &[ENCODER_A]);
    let swapped = asr(&["ffmpeg"], &[ENCODER_B]);
    assert_ne!(original.identity_digest, swapped.identity_digest);
    let undeclared = asr(&["ffmpeg"], &[]);
    assert_ne!(original.identity_digest, undeclared.identity_digest);
}

#[test]
fn identical_inputs_give_identical_identity_and_model_order_is_irrelevant() {
    let a = asr(&["ffmpeg"], &[ENCODER_A, ENCODER_B]);
    let b = asr(&["ffmpeg"], &[ENCODER_B, ENCODER_A]);
    assert_eq!(a, b);
}

#[test]
fn argument_order_is_part_of_the_identity() {
    // Argument vectors are positional; reordering can change meaning.
    assert_ne!(
        asr(&["-l", "eng"], &[]).identity_digest,
        asr(&["eng", "-l"], &[]).identity_digest
    );
}

#[test]
fn encoding_has_no_ambiguous_concatenation() {
    assert_ne!(
        asr(&["ab", "c"], &[]).identity_digest,
        asr(&["a", "bc"], &[]).identity_digest
    );
    assert_ne!(
        asr(&["abc"], &[]).identity_digest,
        asr(&["ab", "c"], &[]).identity_digest
    );
    // A value moved from the argument list to the model list.
    assert_ne!(
        asr(&[ENCODER_A], &[]).identity_digest,
        asr(&[], &[ENCODER_A]).identity_digest
    );
}

#[test]
fn v1_records_still_deserialize_and_are_marked_v1() {
    let v1 = r#"{"name":"external-ocr","version":"5.3.4","config_digest":"aa"}"#;
    let id: ExtractorIdentity = serde_json::from_str(v1).expect("v1 record reads");
    assert_eq!(id.identity_version, EXTRACTOR_IDENTITY_V1);
    assert!(id.args.is_empty() && id.model_digests.is_empty() && id.identity_digest.is_empty());
    assert!(!id.is_self_consistent(), "v1 carries no identity to check");
}

#[test]
fn v2_round_trips_and_detects_tampering() {
    let id = asr(&["ffmpeg"], &[ENCODER_A]);
    let json = serde_json::to_string(&id).expect("serialize");
    let back: ExtractorIdentity = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, id);
    assert!(back.is_self_consistent());

    let mut tampered = back.clone();
    tampered.args = vec!["naive".to_string()];
    assert!(!tampered.is_self_consistent());
    let mut reordered = back;
    reordered.model_digests = vec![ENCODER_B.to_string(), ENCODER_A.to_string()];
    reordered.identity_digest = asr(&["ffmpeg"], &[ENCODER_A, ENCODER_B]).identity_digest;
    assert!(
        !reordered.is_self_consistent(),
        "unsorted model list is not canonical"
    );
}

#[test]
fn in_process_identity_tracks_its_descriptor_not_the_artifact() {
    let a = ExtractorIdentity::in_process(
        "x/spectral".to_string(),
        "realfft/3.5".to_string(),
        &[("window", "4096".to_string())],
    );
    let b = ExtractorIdentity::in_process(
        "x/spectral".to_string(),
        "realfft/3.5".to_string(),
        &[("window", "2048".to_string())],
    );
    assert_ne!(a.config_digest, b.config_digest);
    assert_eq!(a.args, vec!["window=4096".to_string()]);
    assert!(a.is_self_consistent());
}
