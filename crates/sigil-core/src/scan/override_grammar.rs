//! Override grammar: an imperative override verb followed, within a bounded
//! window, by an authority object ("ignore … rules", "disregard all previous
//! instructions", "bypass the system prompt").
//!
//! The phrase list in `detectors.rs` matches fixed strings, so "IGNORE RULES"
//! and any rewording slipped past it. This detector matches the class:
//! - words are compared after case folding, removal of invisible characters
//!   and the UTS #39 confusable skeleton (`unicode_security::skeleton`), so
//!   Cyrillic look-alikes, `|` for `l` and zero-width splits fold onto
//!   the ASCII word (unicode-security 0.1.3, Unicode 18.0.0 data);
//! - verbs match in their inflected forms (listed, not derived);
//! - the object must follow within `MAX_GAP` words, inside one clause (a
//!   sentence end or `;` closes the window);
//! - the verb must stand in imperative position: first in its clause, or
//!   preceded only by imperative lead-ins ("please", "now", "you must",
//!   "I want you to"). "It is easy to forget how simple the rules were" is
//!   description, not command;
//! - a negation just before the verb ("do not ignore the rules") is not an
//!   override.

use super::types::TextMap;
use crate::types::{DetectorId, ScanFinding, Severity};
use std::sync::LazyLock;

/// Words allowed between the verb and the authority object ("ignore all
/// previous instructions" has two).
const MAX_GAP: usize = 4;
/// Words before the verb checked for a negation.
const NEGATION_REACH: usize = 2;

/// Override verbs with their inflected forms, written out (English
/// inflection is irregular: ignore → ignoring, forget → forgot). Verbs with
/// common benign objects ("skip the intro", "cancel the policy", "drop the
/// table") are left out on purpose.
const VERBS: &[&str] = &[
    "ignore",
    "ignores",
    "ignored",
    "ignoring",
    "disregard",
    "disregards",
    "disregarded",
    "disregarding",
    "forget",
    "forgets",
    "forgot",
    "forgotten",
    "forgetting",
    "override",
    "overrides",
    "overrode",
    "overridden",
    "overriding",
    "bypass",
    "bypasses",
    "bypassed",
    "bypassing",
    "circumvent",
    "circumvents",
    "circumvented",
    "circumventing",
    "discard",
    "discards",
    "discarded",
    "discarding",
    "nullify",
    "nullifies",
    "nullified",
    "nullifying",
];
/// Authority objects. "prompt" counts only as "system prompt" (see
/// `object_after`); "prior" / "the above" stay with the phrase list.
const OBJECTS: &[&str] = &[
    "rule",
    "rules",
    "instruction",
    "instructions",
    "guideline",
    "guidelines",
    "policy",
    "policies",
    "directive",
    "directives",
    "constraint",
    "constraints",
    "restriction",
    "restrictions",
    "guardrail",
    "guardrails",
    "safeguard",
    "safeguards",
    "programming",
];
const SYSTEM: &str = "system";
const PROMPT_FORMS: &[&str] = &["prompt", "prompts", "message", "messages"];
/// Words that may precede an imperative verb in its clause.
const LEADS: &[&str] = &[
    "please",
    "kindly",
    "now",
    "just",
    "simply",
    "then",
    "so",
    "also",
    "and",
    "first",
    "immediately",
    "always",
    "hereby",
    "okay",
    "ok",
    "from",
    "on",
    "you",
    "you're",
    "must",
    "should",
    "shall",
    "will",
    "need",
    "needs",
    "to",
    "have",
    "has",
    "can",
    "could",
    "may",
    "i",
    "want",
    "we",
    "required",
    "going",
];
const NEGATIONS: &[&str] = &[
    "not",
    "never",
    "don't",
    "dont",
    "cannot",
    "can't",
    "shouldn't",
    "mustn't",
    "won't",
    "no",
];
const CLAUSE_ENDS: &[char] = &['.', '!', '?', ';', ':', '\n'];

/// Folds a word for comparison: lowercase, invisible characters removed,
/// confusable skeleton, lowercase again (skeletons may map to capitals).
pub(crate) fn fold(word: &str) -> String {
    let visible: String = word
        .chars()
        .filter(|ch| !crate::intake::is_invisible_char(*ch))
        .flat_map(char::to_lowercase)
        .collect();
    unicode_security::skeleton(&visible)
        .flat_map(char::to_lowercase)
        .collect()
}

struct Lexicon {
    verbs: Vec<String>,
    objects: Vec<String>,
    system: String,
    prompt_forms: Vec<String>,
    leads: Vec<String>,
    negations: Vec<String>,
}

static LEXICON: LazyLock<Lexicon> = LazyLock::new(|| {
    let folded = |words: &[&str]| words.iter().map(|w| fold(w)).collect::<Vec<_>>();
    Lexicon {
        verbs: folded(VERBS),
        objects: folded(OBJECTS),
        system: fold(SYSTEM),
        prompt_forms: folded(PROMPT_FORMS),
        leads: folded(LEADS),
        negations: folded(NEGATIONS),
    }
});

/// One whitespace-separated word: its folded form, its text range, and
/// whether a clause ends right after it.
struct Word {
    folded: String,
    start: usize,
    end: usize,
    ends_clause: bool,
}

fn words(text: &str) -> Vec<Word> {
    let mut out = Vec::new();
    let mut start = None;
    let push = |out: &mut Vec<Word>, s: usize, e: usize| {
        let raw = &text[s..e];
        let ends_clause = raw
            .trim_end_matches(['"', '\'', ')', ']'])
            .ends_with(CLAUSE_ENDS);
        let core = raw.trim_matches(|c: char| c.is_ascii_punctuation() && c != '|' && c != '\'');
        if !core.is_empty() {
            out.push(Word {
                folded: fold(core),
                start: s,
                end: e,
                ends_clause,
            });
        }
    };
    for (idx, ch) in text.char_indices() {
        if ch.is_whitespace() {
            if let Some(s) = start.take() {
                push(&mut out, s, idx);
            }
        } else if start.is_none() {
            start = Some(idx);
        }
    }
    if let Some(s) = start {
        push(&mut out, s, text.len());
    }
    out
}

/// Override-grammar findings over a text view.
pub(crate) fn detect_override(map: &TextMap) -> Vec<ScanFinding> {
    let lexicon = &*LEXICON;
    let words = words(&map.text);
    let mut findings = Vec::new();
    for (i, verb) in words.iter().enumerate() {
        if !lexicon.verbs.contains(&verb.folded)
            || !imperative(&words, i, lexicon)
            || negated(&words, i, lexicon)
        {
            continue;
        }
        if let Some(object) = object_after(&words, i, lexicon) {
            findings.push(ScanFinding {
                byte_range: map.source_range_for(verb.start, object.end),
                severity: Severity::High,
                detectors: vec![DetectorId::InjectionGrammar],
                confidence: 0.85,
                evidence: format!(
                    "override grammar: {}",
                    map.snippet_for(verb.start, object.end)
                ),
            });
        }
    }
    findings
}

/// The verb opens its clause, or everything before it in the clause is an
/// imperative lead-in.
fn imperative(words: &[Word], verb: usize, lexicon: &Lexicon) -> bool {
    words[..verb]
        .iter()
        .rev()
        .take_while(|w| !w.ends_clause)
        .all(|w| lexicon.leads.contains(&w.folded) || lexicon.negations.contains(&w.folded))
}

fn negated(words: &[Word], verb: usize, lexicon: &Lexicon) -> bool {
    let from = verb.saturating_sub(NEGATION_REACH);
    words[from..verb]
        .iter()
        .any(|w| !w.ends_clause && lexicon.negations.contains(&w.folded))
}

fn object_after<'w>(words: &'w [Word], verb: usize, lexicon: &Lexicon) -> Option<&'w Word> {
    if words[verb].ends_clause {
        return None;
    }
    let window = words.iter().enumerate().skip(verb + 1).take(MAX_GAP + 1);
    for (index, word) in window {
        if lexicon.objects.contains(&word.folded) {
            return Some(word);
        }
        if word.ends_clause {
            return None;
        }
        if word.folded == lexicon.system
            && let Some(next) = words.get(index + 1)
            && lexicon.prompt_forms.contains(&next.folded)
        {
            return Some(next);
        }
    }
    None
}

#[cfg(test)]
mod tests;
