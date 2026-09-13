use sigil_core::{SpecialTokenMode, TokenizerActor, Vocab};
use std::{sync::Arc, thread};

#[test]
fn batch_encode_decode_matches_sequential_and_is_thread_safe() {
    let actor = Arc::new(TokenizerActor::new(Vocab::tiktoken("cl100k_base")));
    let samples = vec![
        "hello world",
        "leading whitespace",
        "I can't do that.",
        "mañana",
        "mixed こんにちは world 🧪",
        "parallel actor coactor",
    ];

    let expected_encoded = samples
        .iter()
        .map(|sample| actor.vocab().encode(sample))
        .collect::<Vec<_>>();

    let batch_encoded = actor.encode_batch(&samples).expect("batch encode");
    assert_eq!(batch_encoded, expected_encoded);

    let token_batches = batch_encoded
        .iter()
        .map(|tokens| {
            tokens
                .iter()
                .map(|token| token.token_id)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let decoded = actor.decode_batch(&token_batches).expect("batch decode");
    let expected_decoded = samples
        .iter()
        .map(|sample| sample.to_string())
        .collect::<Vec<_>>();
    assert_eq!(decoded, expected_decoded);

    let special_encoded = actor
        .encode_batch_with_specials(
            &["x <|fim_prefix|> y", "x <|endofprompt|> y"],
            SpecialTokenMode::AllowAll,
        )
        .expect("batch specials");
    assert!(special_encoded.iter().all(|tokens| tokens.len() < 10));

    let handles = (0..8)
        .map(|_| {
            let actor = Arc::clone(&actor);
            let samples = samples
                .iter()
                .map(|sample| sample.to_string())
                .collect::<Vec<_>>();
            let expected_encoded = expected_encoded.clone();
            thread::spawn(move || {
                for _ in 0..64 {
                    let encoded = actor.encode_batch(&samples).expect("threaded encode");
                    assert_eq!(encoded, expected_encoded);
                }
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.join().expect("thread join");
    }
}
