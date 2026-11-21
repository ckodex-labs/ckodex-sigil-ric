//! Real-process tests for the pinned-tool primitive. Each tool is a tiny
//! `/bin/sh` script written to the temp dir, so spawn, pipes, exit status and
//! kill all run for real.

use super::{ExecLimits, PinnedTool};
use sigil_multimodal::PerceptionError;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Larger than any OS pipe buffer, so an unread input is always observed.
const LARGE_INPUT: usize = 1 << 20;

struct Script(PathBuf);

impl Script {
    fn new(tag: &str, body: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("sigil-pinned-{tag}-{}", std::process::id()));
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        Self(path)
    }

    fn tool(&self) -> PinnedTool {
        PinnedTool::pin(self.0.clone(), Vec::new(), "test".to_string()).expect("pin")
    }
}

impl Drop for Script {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn failure_message(err: PerceptionError) -> String {
    match err {
        PerceptionError::ExtractorFailed(message) => message,
        other => panic!("expected ExtractorFailed, got {other:?}"),
    }
}

#[test]
fn stdin_reaches_the_tool_and_stdout_comes_back() {
    let script = Script::new("cat", "exec cat");
    let run = script.tool().run(b"artifact bytes").expect("run");
    assert_eq!(run.output, b"artifact bytes");
    assert!(run.input_complete);
}

#[test]
fn a_tool_that_reads_everything_is_complete_even_for_large_input() {
    let script = Script::new("drain", "cat >/dev/null; echo ok");
    let run = script.tool().run(&vec![b'a'; LARGE_INPUT]).expect("run");
    assert_eq!(run.output, b"ok\n");
    assert!(run.input_complete);
}

#[test]
fn a_tool_that_exits_without_reading_its_input_is_declared_incomplete() {
    // Closing stdin then exiting 0 is what a tool that stops at the end of an
    // embedded image does with bytes appended after it.
    let script = Script::new("early", "exec 0<&-; echo partial");
    let run = script
        .tool()
        .run(&vec![b'a'; LARGE_INPUT])
        .expect("clean exit is output");
    assert_eq!(run.output, b"partial\n");
    assert!(
        !run.input_complete,
        "unread input must be declared, never silent"
    );
}

#[test]
fn non_zero_exit_is_an_error_carrying_the_stderr_tail() {
    let script = Script::new("fail", "echo 'model file missing' >&2; exit 3");
    let message = failure_message(script.tool().run(b"x").expect_err("must fail"));
    assert!(message.contains("exited with"), "{message}");
    assert!(message.contains("model file missing"), "{message}");
}

#[test]
fn a_wedged_tool_is_killed_at_the_deadline() {
    let script = Script::new("wedge", "exec sleep 30");
    let limits = ExecLimits {
        timeout: Duration::from_millis(300),
        ..ExecLimits::default()
    };
    let started = Instant::now();
    let err = script
        .tool()
        .with_limits(limits)
        .run(b"")
        .expect_err("must time out");
    assert!(failure_message(err).contains("timed out"));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the deadline bounds the run"
    );
}

#[test]
fn stdout_beyond_the_cap_is_an_error_not_a_truncated_result() {
    let script = Script::new("flood", "head -c 4096 /dev/zero");
    let limits = ExecLimits {
        max_stdout_bytes: 1024,
        ..ExecLimits::default()
    };
    let err = script
        .tool()
        .with_limits(limits)
        .run(b"")
        .expect_err("must refuse");
    assert!(failure_message(err).contains("more than 1024 bytes"));
}

#[test]
fn stdout_exactly_at_the_cap_is_accepted() {
    let script = Script::new("atcap", "head -c 1024 /dev/zero");
    let limits = ExecLimits {
        max_stdout_bytes: 1024,
        ..ExecLimits::default()
    };
    let run = script
        .tool()
        .with_limits(limits)
        .run(b"")
        .expect("at the cap is fine");
    assert_eq!(run.output.len(), 1024);
}

#[test]
fn extract_rejects_non_utf8_output() {
    let script = Script::new("binary", "printf '\\377\\376'");
    let message = failure_message(script.tool().extract(b"x").expect_err("non-UTF-8"));
    assert!(message.contains("non-UTF-8"), "{message}");
}

#[test]
fn extra_args_follow_the_pinned_args() {
    let script = Script::new("args", "printf '%s,' \"$@\"");
    let mut tool = script.tool();
    tool.args = vec!["pinned".to_string()];
    let run = tool.run_with(b"", &["extra".to_string()]).expect("run");
    assert_eq!(run.output, b"pinned,extra,");
}

#[test]
fn identity_records_the_name_and_the_pinned_digest() {
    let script = Script::new("ident", "true");
    let tool = script.tool();
    assert_eq!(tool.binary_digest.len(), 96, "SHA-384 hex");
    let id = tool.identity("external-ocr");
    assert_eq!(id.name, "external-ocr");
    assert_eq!(id.config_digest, tool.binary_digest);
}

#[test]
fn pinning_a_missing_binary_fails() {
    let missing = PathBuf::from("/nonexistent/sigil-no-such-tool");
    assert!(PinnedTool::pin(missing, Vec::new(), "v".to_string()).is_err());
}
