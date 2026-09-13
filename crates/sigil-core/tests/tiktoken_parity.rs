use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use sigil_core::{SpecialTokenMode, Vocab};
use std::{collections::HashMap, process::Command};

#[derive(Debug, Serialize)]
struct OracleRequest {
    encodings: Vec<String>,
    samples: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OracleResponse {
    ordinary: HashMap<String, Vec<Vec<u32>>>,
}

#[test]
fn matches_upstream_tiktoken_for_randomized_corpus() {
    let encodings = supported_encodings();
    let samples = randomized_samples();
    let oracle = python_oracle(&encodings, &samples);

    for encoding in &encodings {
        let vocab = Vocab::tiktoken(encoding.clone());
        let expected = oracle
            .ordinary
            .get(encoding)
            .unwrap_or_else(|| panic!("missing oracle outputs for {encoding}"));

        for (sample, expected_tokens) in samples.iter().zip(expected.iter()) {
            let actual = vocab
                .encode_text(sample)
                .into_iter()
                .map(|token| token.token_id)
                .collect::<Vec<_>>();
            assert_eq!(
                actual, *expected_tokens,
                "ordinary parity mismatch for {encoding} sample {:?}",
                sample
            );

            let decoded = vocab.decode(&actual);
            assert_eq!(
                decoded, *sample,
                "decode round-trip mismatch for {encoding} sample {:?}",
                sample
            );
        }
    }
}

#[test]
fn matches_upstream_tiktoken_special_token_semantics() {
    for encoding in supported_encodings() {
        let vocab = Vocab::tiktoken(encoding.clone());
        let sample = special_token_sample(&encoding);

        let disallow = vocab.try_encode(&sample);
        assert!(
            disallow.is_err(),
            "expected disallowing specials to fail for {encoding}"
        );

        let actual = vocab
            .encode_with_specials(&sample, SpecialTokenMode::AllowAll)
            .into_iter()
            .map(|token| token.token_id)
            .collect::<Vec<_>>();

        let oracle = python_allowed_all(&encoding, &sample);
        assert_eq!(
            actual, oracle,
            "special-token parity mismatch for {encoding}"
        );
    }
}

fn supported_encodings() -> Vec<String> {
    [
        "gpt2",
        "r50k_base",
        "p50k_base",
        "p50k_edit",
        "cl100k_base",
        "o200k_base",
        "o200k_harmony",
    ]
    .into_iter()
    .map(|name| name.to_string())
    .collect()
}

fn randomized_samples() -> Vec<String> {
    let mut rng = StdRng::seed_from_u64(0x0053_4947_494c_554d_u64);
    let alphabet = [
        " ", "\n", "\t", "a", "b", "c", "I", "'", "t", "s", "m", "d", "l", "v", "r", "0", "1", "2",
        "3", "4", "5", "6", "7", "8", "9", ".", ",", "!", "?", "-", "_", "(", ")", "[", "]", "{",
        "}", ":", ";", "/", "\\", "<", ">", "|", "é", "ñ", "ü", "你", "好", "世", "界", "🧪", "🙂",
        "क", "ا", "ب", "\u{200d}", "\u{200b}", "\u{0301}",
    ];

    let mut samples = vec![
        String::new(),
        " leading whitespace".to_string(),
        "can't stop, won't stop".to_string(),
        "The quick brown fox jumps over the lazy dog.".to_string(),
        "mañana mañana".to_string(),
        "mixed こんにちは world 🧪".to_string(),
        "zero\u{200b}width\u{200d}joiner".to_string(),
        "line1\nline2\r\nline3".to_string(),
        "<|endoftext|>".to_string(),
        "prefix <|fim_prefix|> suffix".to_string(),
        "SIGIL <|endofprompt|> tokenizer".to_string(),
    ];

    for _ in 0..128 {
        let len = rng.gen_range(0..96);
        let mut sample = String::new();
        for _ in 0..len {
            sample.push_str(alphabet[rng.gen_range(0..alphabet.len())]);
        }
        samples.push(sample);
    }

    samples
}

fn special_token_sample(encoding: &str) -> String {
    match encoding {
        "gpt2" | "r50k_base" | "p50k_base" => "x <|endoftext|> y".to_string(),
        "p50k_edit" => "x <|fim_prefix|> y".to_string(),
        "cl100k_base" => "x <|endofprompt|> y".to_string(),
        "o200k_base" => "x <|endofprompt|> y".to_string(),
        "o200k_harmony" => "x <|startoftext|> y".to_string(),
        other => panic!("unsupported encoding {other}"),
    }
}

fn python_oracle(encodings: &[String], samples: &[String]) -> OracleResponse {
    let request = OracleRequest {
        encodings: encodings.to_vec(),
        samples: samples.to_vec(),
    };
    let script = r#"
import json, sys, tiktoken
payload = json.loads(sys.stdin.read())
ordinary = {}
for encoding_name in payload["encodings"]:
    enc = tiktoken.get_encoding(encoding_name)
    ordinary[encoding_name] = [enc.encode_ordinary(sample) for sample in payload["samples"]]
print(json.dumps({"ordinary": ordinary}))
"#;
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("launch python3");
    serde_json::to_writer(child.stdin.as_mut().expect("stdin"), &request)
        .expect("write oracle request");
    let output = child.wait_with_output().expect("wait for python3");
    assert!(
        output.status.success(),
        "python oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse oracle response")
}

fn python_allowed_all(encoding: &str, sample: &str) -> Vec<u32> {
    let script = r#"
import json, sys, tiktoken
payload = json.loads(sys.stdin.read())
enc = tiktoken.get_encoding(payload["encoding"])
print(json.dumps(enc.encode(payload["sample"], allowed_special="all")))
"#;
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("launch python3");
    let request = serde_json::json!({ "encoding": encoding, "sample": sample });
    serde_json::to_writer(child.stdin.as_mut().expect("stdin"), &request)
        .expect("write oracle request");
    let output = child.wait_with_output().expect("wait for python3");
    assert!(
        output.status.success(),
        "python oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse oracle response")
}
