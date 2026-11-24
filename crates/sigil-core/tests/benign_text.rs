//! D5 benign rate for text (RIC-MM-001 O-3): ordinary prose under the
//! default policy is admitted with no findings. The n-gram rarity detector,
//! which judged each input against its own n-gram counts, flagged every one
//! of these sentences before it became opt-in; with it enabled it still
//! flags them, so the opt-in keeps its behaviour.

use sigil_core::policy::Policy;
use sigil_core::types::{Provenance, TextSegment, Verdict};
use sigil_core::{Sigil, Vocab};

const PROSE: [&str; 4] = [
    "The quarterly report shows revenue grew in every region except the north, where supply problems delayed two product launches.",
    "Please summarise the attached meeting notes and list the action items with their owners and due dates.",
    "Hi team, the build is green again after the dependency update; thanks to everyone who helped track down the flaky test.",
    "After early nightfall, the yellow lamps would light up here and there the squalid quarter of the brothels.",
];

fn verdict(policy: Policy, text: &str) -> (Verdict, usize) {
    let output = Sigil::new(Vocab::tiktoken("cl100k_base"), policy)
        .expect("engine")
        .process_text_segments(&[TextSegment {
            text,
            provenance: Provenance::User,
        }])
        .expect("process");
    (output.assessment.verdict, output.assessment.threat_count)
}

#[test]
fn ordinary_prose_is_admitted_under_the_default_policy() {
    for text in PROSE {
        assert!(text.chars().count() > 55, "long enough to have tripped it");
        assert_eq!(
            verdict(Policy::default(), text),
            (Verdict::Allow, 0),
            "{text}"
        );
    }
}

#[test]
fn the_rarity_detector_is_opt_in_and_unchanged() {
    assert!(!Policy::default().scan.rare_pattern_detection);
    let mut policy = Policy::default();
    policy.scan.rare_pattern_detection = true;
    for text in PROSE {
        assert_ne!(verdict(policy.clone(), text).0, Verdict::Allow, "{text}");
    }
}
