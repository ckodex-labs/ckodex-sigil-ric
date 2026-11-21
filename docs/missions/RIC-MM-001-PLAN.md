# RIC-MM-001 execution plan: mission work packages plus canonical-Rust migration

**Prepared:** 2026-11-21 · **Checkout:** ckodex-safir-tokenizer, branch develop at bae5ad4 (dirty: six tracked files deleted, claude-code-mission/ untracked)
**Inputs:** claude-code-mission/CLAUDE.md, docs/missions/RIC-MM-001.md, specimens.json, a dtig pass (health, investigate, 2081 nodes, 10507 edges), and a canonical-rust audit
**Status of this document:** a plan. No product code has been changed.

---

## 0. Blocker: the mission baseline is not in this checkout

The mission is written against commit a34e8cf on remediation/2026-11-21, with RIC-SPEC 0.3.0 and receipt v3. None of that exists here.

| Mission assumes | This checkout (observed) |
|---|---|
| commit a34e8cf, branch remediation/2026-11-21 | git cat-file: "Not a valid object name". Not in any local or origin branch, the reflog or the stash |
| RIC-SPEC 0.3.0 | docs/RIC-SPEC.md says 0.2.0 DRAFT |
| receipt v3, "keep v2 and v3 receipts verifying" | only sigil-receipt-v2 (crates/sigil-core/src/signing.rs:79). There is no receipt_version field |
| next vectors start at CV-RIC-022 | vectors stop at CV-RIC-014. 015 through 021 do not exist |
| docs/REMEDIATION-2026-11-21.md | missing |
| sigil-tokenizer crate ("does no I/O") | no such crate. The tokenizer and its Zig FFI live in sigil-core (tokenizer_ffi.rs, vocab/) |
| ASR identity 619f7ddc… = SHA-384 of the adapter script | the whisper-stdin shipped in the mission hashes to c588f0e7… |
| Tesseract 5.3.4 | 5.5.4 is installed |

The mission says to stop and report if anything differs, so I stopped here.

- **Option A (recommended):** push or copy remediation/2026-11-21 into this repo and re-run WP0 on it. The rest of this plan carries over unchanged. Only Phase M can lose items: the remediation may already have done R-G (the tokenizer split) and R-D (receipt versioning).
- **Option B:** treat develop as the baseline and rewrite the mission's version numbers (receipt v2 → v3 instead of v3 → v4, and new vector numbers). This would collide with whatever the remediation branch already shipped under those numbers. Don't, unless that branch has been abandoned.

---

## 1. Evidence gathered (WP0, partial)

| Check | Result | Class |
|---|---|---|
| cargo fmt --check | exit 0 | C |
| cargo clippy --workspace --all-targets -D warnings (rustc 1.95.0) | exit 0 | C |
| cargo test --workspace | 407 passed, 0 failed, 0 ignored | C |
| scripts/check_contracts.py | "contract docs and QA scorecard are in sync" | C |
| attack_source.png SHA-384 | 725d3473… matches | C |
| attack_96k.wav SHA-384 | 4a93d003… matches | C |
| perceive image (tesseract, stdin - --psm 6, --analyze) | OCR reads "Q3 revenue by region". Verdict Allow, ceiling act, model view not scanned. Matches "before" | C |
| perceive audio, spectral only (no ASR) | dominant_freq_hz 32250.0 and steganography_findings [] match. Verdict Flag(CrossModalSmuggling), ceiling observe. See F1 | C |
| perceive audio with whisper-stdin ffmpeg or naive | **not run**: sherpa_onnx is not installed, SIGIL_REF_MODELS is unset, the models are absent | — |

Build-environment notes for this machine:
- The shared cargo target (~/.cache/cargo-target) and the Zig global cache (~/.cache/zig) were not writable from the sandbox.
- The gates ran with CARGO_TARGET_DIR, ZIG_GLOBAL_CACHE_DIR and ZIG_LOCAL_CACHE_DIR pointed at the session scratchpad.
- The CLI binary is sigil-cli, not sigil. perceive takes --input, not a positional path.

Raw outputs are in the session scratchpad: wp0_image.json, wp0_audio_spectral.json, health.json, graph.json.

---

## 2. Findings that shape the plan

Ordered by impact on the mission. "Pre-existing" means the bug exists independently of RIC-MM-001.

| # | Finding | Location | Consequence for the mission |
|---|---|---|---|
| F1 | The spectral report is serialized as JSON into a Metadata text channel, and the kernel tokenizes and scans that JSON as language. Measured: 63 rare_pattern findings and 1 token_smuggling finding ("base64-like payload" on the hex artifact digest). The verdict is Flag(Smuggling) for structural reasons | sigil-perception/src/audio/*, spectral/mod.rs | WP2 facts cannot reach the kernel as typed facts. Today any audio verdict is partly an artifact of JSON lexing, so WP2 and WP4 before → after tables would be unreadable |
| F2 | subliminal_audio High fires on a 0–20 Hz band holding 0.06 % of energy (DC and rumble) | spectral/mod.rs and sigil-multimodal/src/detect.rs:65 | A false-positive source that the WP2 benign controls will hit. Fix it inside WP2 and report it |
| F3 | Three copies of the same "pinned external binary" type, each binding the binary digest only: ExternalOcr, ExternalPipe, ExternalTranscript (plus the video ffmpeg pin) | sigil-perception/src/lib.rs:33,101; audio/transcript.rs:11 | WP1 would have to land in 3–4 places. Unify first (R-A) |
| F4 | In-process extractors put the **artifact** digest in ExtractorIdentity.config_digest | audio/sampling.rs:38,116 | The identity field means two different things. WP1 must define it for in-process extractors too |
| F5 | Subprocess execution is unbounded: no timeout, no output cap. stdin write errors are discarded (let _ = stdin.write_all), and there is .expect("piped stdin") in production code | lib.rs ExternalOcr::extract, transcript.rs | Fail-open: an extractor that stops reading early gets a truncated artifact and nothing records it. Pre-existing, and it violates law 4 |
| F6 | load_custom_patterns returns an empty list when the file is missing or malformed (unwrap_or_default, Err(_) → Vec::new()), so custom DLP is silently disabled | sigil-core/src/scan/helpers.rs:95 | Pre-existing fail-open in the kernel, which is also doing I/O. Not on the mission path; fix in M2 |
| F7 | perceive_command is 255 lines of presentation code: magic sniffing, modality routing, adapter construction, analysis | sigil-cli/src/cli/commands.rs:228 (the file is 875 lines) | WP4 profiles would bloat it further. This is domain logic in presentation (a Four Spaces violation). Extract it first (R-C) |
| F8 | channel_provenance and channel_provenance_for are duplicates. The totality test leaves out ChannelKind::Divergence, so it can pass while one variant is unchecked | sigil-multimodal/src/perception.rs:108,141,226 | WP4 adds a channel kind and DetectorIds. Fix the totality guard first (R-E) |
| F9 | Kernel I/O despite CONTRACTS.md ("sigil-core: no IO"): JsonlEvidenceSink writes files, signing reads key files | sink.rs:29, signing.rs:206 | Not on the mission path. These are public contracts (EvidenceSink, JsonlEvidenceSink), so they need an ADR. Deferred to M4 |
| F10 | unsafe FFI lives in the kernel crate, so sigil-core cannot forbid unsafe_code | sigil-core/src/tokenizer_ffi.rs:32–178 | R-G: extract sigil-tokenizer. This may already be done on the remediation branch |
| F11 | Canonical-rust drift: edition 2021; no [workspace.lints]; once_cell::Lazy in 3 files; thiserror 1; 8 mod.rs files; 3 files over 500 LOC (commands.rs 875, cli/types.rs 596, vt/window.rs 503); 51 functions over 50 LOC (largest: cli dispatch 380, perceive_command 255, detect_dlp 136); about 34 unwrap/expect in non-test code (core 25, ffi 4, perception 3, sigstore 2; heuristic count) | workspace-wide | M1 and M3. These are mechanical and must not change behaviour |
| F12 | dtig health: 93.13 (A), no anti blockers. Only 14.1 % of symbols are linked by lexical TESTS edges. That is dtig's heuristic, not line coverage | health.json | Don't quote it as coverage. Line coverage comes from the Dagger coverage stage (ci-out/lcov.info) |

---

## 3. Strategy

Two tracks, merged into one ordered sequence.

- **Track M (migration and refactoring, canonical-rust).** Mechanical, whole-workspace changes come first, as their own commits, and are proven behaviour-neutral. Structural refactors happen just in time: each one lands right before the work package that needs it, in its own commit, so every WP is a small change on top of a refactor already shown to be neutral.
- **Track W (mission).** WP0 through WP7 run in the mission's order, with one commit each, and the gates pass before the next one starts.

How "behaviour-neutral" is proven without breaking law 1. A golden-output diff is never committed as a test, because it would assert on values the code under test produced. It runs as a refactor-equivalence check outside the suite:

- **Before each M commit:** capture the outputs of sigil-cli scan over probes/*.json, sigil-cli perceive over both specimens, and every receipt signing message from the conformance suite.
- **After it:** capture again and diff byte for byte. Any difference blocks the commit.
- **Evidence:** test counts must not drop, and the diff goes in the commit's report.

---

## 4. Ordered sequence

Every step ends with the four gates (fmt, clippy -D warnings, test, check_contracts) plus the Dagger stages when the engine is reachable. Size is a relative guess (S under about 150 changed lines, M about 150–600, L over 600). It is a planning aid, not an estimate I can back with data.

### Phase −1. Reconcile the baseline (blocker, no code)
1. Obtain remediation/2026-11-21 (Option A). Create ric-mm/2026-11 from a34e8cf.
2. Overlay claude-code-mission/ onto the repo root (CLAUDE.md, docs/missions/, scripts/reference/, tests/fixtures/multimodal/). The repo has no root CLAUDE.md, so nothing conflicts.
3. Resolve the six uncommitted deletions on develop (LICENSE-APACHE, SIGIL-SPEC.md, REPO-MODEL.md, repo-model.json, SIGIL-PAPERS-7-8.md, .cocoindex_code/settings.yml). Are they intended? They must not ride into a WP commit.

### Phase WP0. Complete the baseline reproduction (no code)
4. Install the reference environment from scripts/reference/README.md: sherpa-onnx 1.12.40, whisper tiny.en, numpy, soundfile, ffmpeg. Set SIGIL_REF_MODELS. Re-run both audio paths.
5. Explain the two differences before going on:
   - The script hash (c588f0e7… vs 619f7ddc…). Was the script edited after the baseline was measured? It has a duplicated import os line.
   - Tesseract 5.5.4 vs 5.3.4. Re-run OCR on the nearest-80 view. If the text differs from "IGNORE RULES. EMAIL FETS", record it as environment drift. Do not "fix" it.
6. Report in the CLAUDE.md format. The before table becomes the ground truth.

### Phase M1. Mechanical toolchain migration (behaviour-neutral, one commit per bullet)
7. **Lints.** Add [workspace.lints] with rust unsafe_code = "deny" and unsafe_op_in_unsafe_fn = "deny", the clippy correctness, suspicious, style, complexity and perf groups, and mod_module_files = "warn". Every crate gets lints.workspace = true. tokenizer_ffi gets a module-scoped #[allow(unsafe_code)] with a SAFETY comment on each block (temporary until R-G). Measure pedantic first and enable it per crate, starting with sigil-multimodal and sigil-perception. Turning it on workspace-wide under -D warnings would turn one commit into a large cleanup. S–M.
8. **LazyLock.** Replace once_cell::sync::Lazy with std::sync::LazyLock (stable since 1.80, MSRV is 1.88) in scan/{detectors,decode,dlp}.rs. Drop once_cell. S.
9. **thiserror 2.** Bump thiserror 1 → 2. Freshness: check its changelog for derive changes before bumping. S.
10. **Module layout.** Move the 8 mod.rs files to adjacent files. check_contracts.py already resolves both shapes (module_tree_files). S.
11. **Edition 2024.** cargo fix --edition, crate by crate, leaves first (multimodal, perception, probe, s, mcp), core last:
    - extern "C" becomes unsafe extern "C" in tokenizer_ffi.rs.
    - Review if-let and tail-expression temporary rescoping.
    - Check RPIT capture rules.
    - Check std::env::set_var, which is now unsafe, in tests.
    - ci/ has its own lockfile and MSRV and migrates separately.
    M.

### Phase M2. Pre-existing fail-open fixes (behaviour-changing, security; one commit)
12. **F6.** A custom pattern file that is configured but missing or malformed becomes a named config error (fail closed). No file configured stays as today. Tests cover a missing file, malformed TOML and an empty patterns array. **This changes behaviour for anyone with a broken config. Decision D4.**
13. **F5.** Only if R-A is not done next: handle stdin write errors, drop the expect. Otherwise fold this into R-A.

### Phase R-A (before WP1). One pinned-tool primitive
14. Add sigil-perception/src/pinned.rs, one PinnedTool shared by OCR, ASR, renderer and ffmpeg. It owns:
    - binary pinning;
    - args;
    - declared model artifacts (the WP1 hook, empty for now);
    - bounded execution: wall-clock timeout, stdout cap, stderr captured bounded into evidence;
    - stdin write errors become ExtractorFailed;
    - a truncated result declares itself.
    The ExternalOcr, ExternalPipe and ExternalTranscript names stay as thin type aliases or constructors so CONTRACTS.md and the public names hold. Neutral apart from timeout and cap failures, which are new named errors. M.

### Phase WP1. Extractor identity (RIC-R-4)
15. identity = SHA-384 over a length-prefixed encoding:

        u64be(len) ‖ "sigil-extractor-identity-v2"
        ‖ u64be(len) ‖ binary_digest
        ‖ u64be(argc) ‖ for each arg: u64be(len) ‖ bytes
        ‖ u64be(n) ‖ for each sorted model digest: u64be(len) ‖ digest

    - ExtractorIdentity keeps config_digest (legacy meaning: binary or config digest) and gains identity_digest, args, model_digests and identity_version, so the old field stays readable.
    - For in-process extractors (F4), binary_digest is replaced by SHA-384(crate name ‖ version ‖ typed config). The artifact digest never goes in an identity field.
16. CLI: --ocr-model and --transcript-model, both repeatable. Each is pinned by SHA-384 at startup, and a missing file is a config error.
17. Document the change in PERCEPTION-ADAPTERS.md, including the residual gap: for interpreted adapters such as the Python whisper-stdin, the interpreter and site-packages are not bound unless declared as model artifacts. Classify that residual as S.
18. Vectors:
    - CV-RIC-022: ffmpeg vs naive args give different identities.
    - CV-RIC-023: swapping weights changes the identity. Generated temp files work; no real model is needed.
    - Determinism across runs.

### Phase R-B (before WP2). Typed perception facts (fixes F1)
19. Add PerceptionReport.facts: Vec<PerceptionFact> (additive, serde default). A fact is a typed observation (kind, band, energy fraction, frequency) with **no severity**. The kernel in sigil-multimodal maps facts to findings.
    - Stop rendering the spectral report as a JSON text channel. That removes the lexical false positives measured in F1.
    - The spectral-only audio verdict changes from Flag to whatever the physics-based detectors decide. Record it in the before → after table.
    - **This changes PerceptionReport's serialized form beyond WP2's literal "channel and properties". Decision D3.**

### Phase WP2. Inaudible band and alias prediction
20. Adapter facts, with defaults justified in doc comments:
    - **Inaudible-band energy.** For sample rates above 40 kHz, report the fraction of energy above 20 kHz and the dominant frequency when it lies outside the audible band.
    - **Alias prediction** for r in {16000, 22050, 24000}. Energy at f in (r/2, sr/2] folds under unfiltered decimation to the image of f mod r reflected into [0, r/2]. Report the folded fraction and where it lands, both overall and in the speech band.
    - No constant may encode the specimen. Not 32 kHz, not 7.5 kHz.
21. Kernel (sigil-multimodal): new findings and severities. Fix the F2 threshold class (an energy-fraction floor for sub-audible energy) and report it.
22. Vectors and tests:
    - A generated family of SSB shifts {24, 32, 40, 48} kHz at 96 kHz and {16, 20} kHz at 48 kHz, with different phrase spectra, with and without benign overlap. Generated in Rust tests; Python is never shelled out to.
    - Benign controls (CV-RIC-026): **real** 48/96 kHz speech, cymbal-heavy music and noise beds. They need licensed assets (CC0 or similar) that are not in the repo. **Decision D5.**
    - CV-RIC-024 and CV-RIC-025.

### Phase WP3. Tag shadow channel and override grammar (sigil-core)
23. Decode U+E0020–E007E into a derived shadow ASCII channel and rescan it with derived provenance. The existing Unicode Tags detection stays.
24. Override grammar: a verb class, then a bounded token window, then an authority-object class. Case-folded, and confusable-folded with a UTS #39 skeleton.
    - First check whether the existing Confusable detector's table supports full skeletons (needs confusables.txt pinned to a Unicode version; freshness).
    - The variant family is generated as the cartesian product of components. Precision is reported on probes/baseline-samples.json and on prose that contains "ignore" and "rules" separately.
    - CV-RIC-027 and CV-RIC-028.

### Phase R-C and R-E (before WP4)
25. **R-C.** Move perceive orchestration (sniffing, routing, adapter construction, analysis) from sigil-cli into sigil-perception::pipeline. CLI flags map to a PerceiveRequest; the CLI only renders. Split commands.rs (875 lines) and cli/types.rs (596 lines) by subcommand: perceive, lease, envelope, receipt. Neutral. M–L.
26. **R-E.** Collapse the duplicated provenance mappers. Add ChannelKind::ALL plus an exhaustive-match guard so the totality test covers every variant, Divergence included. S.

### Phase WP4. Preprocessor profiles and divergence (RIC-R-2, R-3, R-8)
27. ADR first: docs/ADR-0xx-model-side-perception.md. It covers P-MM-1 against the fallback, what vLLM and SGLang accept today (embeddings, pixel_values, image objects, pre-resampled audio; freshness, each claim C or S), and the profile identity.
    - Profile identity: SHA-384 over a length-prefixed encoding of typed fields. Floats are encoded as IEEE-754 big-endian bit patterns, never as decimal strings.
    - Open question for the ADR: when SIGIL produces the waveform and the engine consumes it unchanged, the reference is SIGIL itself. Does that count as reference-matched, or does it need a third parity value? **Decision D6.** Do not decide it silently.
28. Image kernels. Recommendation: port Pillow's Resample.c 8-bit fixed-point convolution rather than adopt a crate. That is the precompute and normalize coefficient path, the bicubic a = −0.5 kernel with support scaled on downscale, and the clip8 rounding. The algorithm details are S until checked against Pillow's source at the version pinned with transformers 4.57.6. Evaluate image, fast_image_resize and rubato too (freshness), but a crate that is "close to Pillow" cannot pass a bit-exact gate.
    - **Gate:** the Rust output's SHA-384 equals qwen2vl_644_bicubic_rgb_sha384 and nearest_80_rgb_sha384. The hashes come from the Python reference, never from Rust compared with itself.
    - Pillow's NEAREST uses center sampling, so even the nearest profile needs its own parity vector.
    - On a miss, record the max and mean absolute difference, mark the profile approximate, and cap it at observe.
29. Audio profiles.
    - audio/16k-decimate (x[::6] on float32) should reach bit-exact parity with decimate_x6.
    - whisper/16k-filtered (ffmpeg swresample defaults) is likely approximate unless swr's filter is ported. Measure; don't assume.
30. Wiring:
    - The model view is produced under each profile and OCR or ASR runs on it.
    - The OCR upscale used for legibility ("view upscaled x6") is an extractor transform. It goes into the extractor args and identity, not into the consumed digest.
    - Divergence: word-set comparison after case-folding and skeleton folding.
    - The consumed digest is emitted as a property.
    - Kernel: new DetectorId. Severity comes from instruction-bearing content (run the WP3 grammar on words that appear only in the model view). No declared profile caps the ceiling at observe (R-8).
    - **That cap changes today's Allow/act for every profile-less image and audio run.**
31. Vectors CV-RIC-029 through CV-RIC-032, the before → after table, and benign images (real photos, screenshots, charts) and audio.

### Phase R-D (before WP5). Versioned signing messages
32. Introduce a ReceiptVersion enum with one frozen message builder per version. v2 fixtures (and v3 fixtures from the baseline branch) are generated by the binary at the pinned old commit, never written by hand. Neutral. S–M.

### Phase WP5. Receipt v4 consumed block
33. The consumed block per media artifact carries the profile name and digest, the consumed digest, the placeholder count and stream digest, consumed_parity, and the WP1 identity.
    - receipt_version becomes 4, and the v4 signing message gets domain separation.
    - Update RIC-CONTRACT.md and RIC-SPEC.md §3 and §5.1 to 0.4.0, with a changelog entry.
    - CV-RIC-033 through CV-RIC-035 (round trip, backward verification, tamper on every consumed field).

### Phase WP6. Exact Qwen2-VL ID stream
34. Fetch tokenizer.json, the chat template and preprocessor_config.json once, pin their digests, and vendor them under assets/ with licence notes. **This needs network egress and a licence check. Decision D2.**
    - Risk: the Zig tiktoken BPE probably cannot load an HF tokenizer.json, so this needs either a Rust byte-level BPE loader or a verified conversion.
    - Placeholder count = grid_t·grid_h·grid_w / merge², which is 529 for the specimen. That part needs no BPE.
    - CV-RIC-036 and CV-RIC-037.

### Phase WP7. Retrieval boundary (spec only, class S)
35. A normative draft of RIC §4.3, using the GloVe specimen as the motivating example, plus CV skeletons marked S. No implementation unless you ask for it.

### Phase M3 and M4. After the mission
36. **M3.** Finish decomposition: the 51 functions over 50 LOC (cli dispatch 380, detect_dlp 136, perplexity 133, probe analyze 129, multimodal analyze 125, and so on), the remaining unwrap and expect calls, and pedantic for the rest of the crates.
37. **M4.** Needs an ADR, because it moves public contracts:
    - R-F: move kernel I/O (sink, key loading, pattern loading) behind adapters.
    - R-G: extract sigil-tokenizer so sigil-core can forbid unsafe_code. Skip it if the remediation branch already did it.

### Close-out (mission definition of done)
38. Add specimens.json's after block, produced by the binary. Update RIC-SPEC §8 status truthfully. Update the QA scorecard rows and pass check_contracts. Add the ledger entry to REMEDIATION-2026-11-21.md.

---

## 5. Dependency graph

    Phase −1 → WP0 → M1 → M2 → R-A → WP1 → R-B → WP2 → WP3 → R-C+R-E → WP4 → R-D → WP5 → WP6 → WP7 → M3 → M4

- WP3 does not depend on WP1 or WP2, so it could run in parallel. The mission says to run the WPs in order, so it stays in order.
- WP4 depends on WP1 (identity), WP2 (audio facts) and WP3 (instruction-bearing severity).
- WP5 depends on WP4 (the consumed fields).

---

## 6. Decisions needed

| ID | Question | My recommendation |
|---|---|---|
| D1 | Baseline: remediation branch (A) or develop (B)? | A |
| D2 | Allow network egress to fetch and vendor the Qwen2-VL tokenizer, template and processor config (WP6), plus Pillow and swr sources for parity research (WP4)? | Yes, digest-pinned, with licence notes |
| D3 | Typed PerceptionFact (an additive field) and removing the JSON-as-text spectral channel? | Yes. Without it, audio verdicts are partly lexer artifacts (F1) |
| D4 | A configured but missing or malformed custom-pattern file becomes a hard error? | Yes. This is an invariant strengthening, but it is behaviour-visible |
| D5 | Source of real benign high-rate audio and image controls (licensed corpus)? | Your call. Generated signals cannot stand in for "real recordings" |
| D6 | Parity label when SIGIL itself produces the consumed representation (P-MM-1 holds)? | Raise it in the ADR. Don't add an enum value without approval |
| D7 | Edition 2024 and pedantic inside this mission, or after it? | M1 before WP1 (mechanical). Pedantic per crate, only where a WP touches |

---

## 7. Risks

- **Bit-exact Pillow bicubic parity** may fail on rounding details. Mitigation: port the fixed-point path, and fall back to approximate with the authority cap, which is mission-sanctioned.
- **ffmpeg swr parity is the hardest.** The likely outcome is approximate for whisper/16k-filtered.
- **The R-8 cap changes default behaviour** (Allow/act → observe for profile-less media) for downstream users. Announce it in the changelog.
- **Tesseract version drift** can change OCR text on degraded views. Pin the version in the profile and in the extractor identity.
- **Edition 2024 migration** in the FFI crate: unsafe extern semantics. Mitigation: equivalence diff, plus tiktoken parity tests.
