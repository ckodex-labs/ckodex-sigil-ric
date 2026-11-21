//! One primitive for every pinned external tool (OCR, ASR, renderers, ffmpeg).
//!
//! A [`PinnedTool`] is a binary pinned by SHA-384 at construction plus a fixed
//! argument vector. Execution is bounded and fail-closed:
//! - artifact bytes travel on stdin, never in an argument;
//! - a wall-clock timeout and a stdout cap bound every run; exceeding either is
//!   a named [`PerceptionError::ExtractorFailed`], never a partial result;
//! - a non-zero exit is an error carrying a bounded stderr tail;
//! - a tool that exits cleanly without reading all of its input yields output
//!   with [`ToolOutput::input_complete`] = false, which callers surface as a
//!   truncated channel. Detection is exact when the tool closes stdin before
//!   the write finishes (always for inputs larger than the OS pipe buffer);
//!   smaller inputs are absorbed by the pipe buffer and read as complete.
//!
//! A stdout or stderr handle inherited by a grandchild can outlive the killed
//! child; the reader thread then ends when that grandchild exits. The run
//! itself still returns at the deadline.

use sha2::{Digest, Sha384};
use sigil_multimodal::{ExtractorIdentity, PerceptionError};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use crate::hex_digest;

/// Extractor-identity name for OCR text channels.
pub const OCR_EXTRACTOR: &str = "external-ocr";
/// Extractor-identity name for ASR transcript channels.
pub const TRANSCRIPT_EXTRACTOR: &str = "external-transcript";

/// Bytes of stderr kept for error messages (the tail, where tools report).
const STDERR_TAIL_BYTES: usize = 2048;
/// Granularity of the post-EOF exit wait. Only reached after the tool has
/// closed stdout, so the loop runs a handful of times at most.
const EXIT_POLL: Duration = Duration::from_millis(5);

/// Resource bounds for one tool run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecLimits {
    /// Wall-clock bound from spawn to exit.
    pub timeout: Duration,
    /// Largest stdout accepted. One byte more is an error, not a truncation.
    pub max_stdout_bytes: usize,
}

impl ExecLimits {
    /// 120 s. OCR or ASR over one admitted artifact takes seconds on CPU; the
    /// bound exists to stop a wedged tool, not to race a slow one.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
    /// 256 MiB. The largest legitimate stdout is the video frame pipe (a
    /// capped run of PNG frames); text tools stay far below it.
    pub const DEFAULT_MAX_STDOUT_BYTES: usize = 256 * 1024 * 1024;
}

impl Default for ExecLimits {
    fn default() -> Self {
        Self {
            timeout: Self::DEFAULT_TIMEOUT,
            max_stdout_bytes: Self::DEFAULT_MAX_STDOUT_BYTES,
        }
    }
}

/// A successful run's output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolOutput<T> {
    /// What the tool wrote to stdout.
    pub output: T,
    /// False when the tool exited without reading all of its input.
    pub input_complete: bool,
}

/// A digest-pinned external binary with fixed arguments.
#[derive(Clone, Debug)]
pub struct PinnedTool {
    /// Path to the binary. Pinned by digest at construction.
    pub binary: PathBuf,
    /// Arguments passed to the binary.
    pub args: Vec<String>,
    /// Human-readable version label recorded in extractor identity.
    pub version: String,
    /// SHA-384 over the binary, computed at pin time.
    pub binary_digest: String,
    /// Execution bounds.
    pub limits: ExecLimits,
}

impl PinnedTool {
    /// Pins a binary: reads it and records its SHA-384 digest.
    ///
    /// # Errors
    ///
    /// The I/O error from reading the binary (missing, unreadable).
    pub fn pin(binary: PathBuf, args: Vec<String>, version: String) -> io::Result<Self> {
        let bytes = std::fs::read(&binary)?;
        let binary_digest = hex_digest(&Sha384::digest(&bytes));
        Ok(Self {
            binary,
            args,
            version,
            binary_digest,
            limits: ExecLimits::default(),
        })
    }

    /// Replaces the execution bounds.
    #[must_use]
    pub fn with_limits(mut self, limits: ExecLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The extractor identity recorded on channels this tool produced.
    #[must_use]
    pub fn identity(&self, name: &str) -> ExtractorIdentity {
        ExtractorIdentity {
            name: name.to_string(),
            version: self.version.clone(),
            config_digest: self.binary_digest.clone(),
        }
    }

    /// Runs the tool and decodes stdout as UTF-8 text.
    ///
    /// # Errors
    ///
    /// Everything [`PinnedTool::run_with`] reports, plus non-UTF-8 output.
    pub fn extract(&self, bytes: &[u8]) -> Result<ToolOutput<String>, PerceptionError> {
        let run = self.run(bytes)?;
        let text = String::from_utf8(run.output)
            .map_err(|_| self.failure("wrote non-UTF-8 output".to_string()))?;
        Ok(ToolOutput {
            output: text,
            input_complete: run.input_complete,
        })
    }

    /// Runs the tool with its pinned arguments.
    ///
    /// # Errors
    ///
    /// See [`PinnedTool::run_with`].
    pub fn run(&self, bytes: &[u8]) -> Result<ToolOutput<Vec<u8>>, PerceptionError> {
        self.run_with(bytes, &[])
    }

    /// Runs the tool with per-invocation arguments appended after the pinned
    /// set (e.g. `-f N -l N` to select one page). Callers record appended
    /// arguments as evidence.
    ///
    /// # Errors
    ///
    /// [`PerceptionError::ExtractorFailed`] naming the cause: spawn failure,
    /// timeout, stdout over the cap, or a non-zero exit (with a stderr tail).
    pub fn run_with(
        &self,
        bytes: &[u8],
        extra_args: &[String],
    ) -> Result<ToolOutput<Vec<u8>>, PerceptionError> {
        let deadline = Instant::now() + self.limits.timeout;
        let mut child = Command::new(&self.binary)
            .args(&self.args)
            .args(extra_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| self.failure(format!("could not spawn: {err}")))?;
        let pipes = self.take_pipes(&mut child)?;
        let writer = self.spawn_io(&mut child, "stdin", write_all(pipes.0, bytes.to_vec()))?;
        let stdout = self.spawn_io(&mut child, "stdout", read_capped(pipes.1, self.limits))?;
        let stderr = self.spawn_io(&mut child, "stderr", read_tail(pipes.2))?;

        let output = self.await_stdout(&mut child, &stdout, deadline)?;
        let status = self.await_exit(&mut child, deadline)?;
        if !status.success() {
            let tail = stderr.recv_timeout(EXIT_POLL * 20).unwrap_or_default();
            return Err(self.failure(format!("exited with {status}{}", stderr_suffix(&tail))));
        }
        let input_complete = matches!(writer.recv_timeout(EXIT_POLL * 20), Ok(Ok(())));
        Ok(ToolOutput {
            output,
            input_complete,
        })
    }

    fn failure(&self, what: String) -> PerceptionError {
        let name = self.binary.file_name().map_or_else(
            || self.binary.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        PerceptionError::ExtractorFailed(format!("pinned tool {name} ({}) {what}", self.version))
    }

    fn take_pipes(
        &self,
        child: &mut Child,
    ) -> Result<(ChildStdin, ChildStdout, ChildStderr), PerceptionError> {
        match (child.stdin.take(), child.stdout.take(), child.stderr.take()) {
            (Some(stdin), Some(stdout), Some(stderr)) => Ok((stdin, stdout, stderr)),
            _ => {
                kill(child);
                Err(self.failure("started without its stdio pipes".to_string()))
            }
        }
    }

    fn spawn_io<T: Send + 'static>(
        &self,
        child: &mut Child,
        stream: &str,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<Receiver<T>, PerceptionError> {
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name(format!("sigil-pinned-{stream}"))
            .spawn(move || {
                // The receiver may have given up (timeout); nothing to report.
                let _ = tx.send(work());
            })
            .map(|_| rx)
            .map_err(|err| {
                kill(child);
                self.failure(format!("could not start the {stream} thread: {err}"))
            })
    }

    fn await_stdout(
        &self,
        child: &mut Child,
        stdout: &Receiver<io::Result<Capped>>,
        deadline: Instant,
    ) -> Result<Vec<u8>, PerceptionError> {
        let received = stdout.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        match received {
            Ok(Ok(Capped::Complete(bytes))) => Ok(bytes),
            Ok(Ok(Capped::Overflow)) => {
                kill(child);
                Err(self.failure(format!(
                    "wrote more than {} bytes to stdout",
                    self.limits.max_stdout_bytes
                )))
            }
            Ok(Err(err)) => {
                kill(child);
                Err(self.failure(format!("stdout read failed: {err}")))
            }
            Err(_) => {
                kill(child);
                Err(self.timed_out())
            }
        }
    }

    fn await_exit(
        &self,
        child: &mut Child,
        deadline: Instant,
    ) -> Result<ExitStatus, PerceptionError> {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) if Instant::now() < deadline => thread::sleep(EXIT_POLL),
                Ok(None) => {
                    kill(child);
                    return Err(self.timed_out());
                }
                Err(err) => {
                    kill(child);
                    return Err(self.failure(format!("wait failed: {err}")));
                }
            }
        }
    }

    fn timed_out(&self) -> PerceptionError {
        self.failure(format!("timed out after {:?}", self.limits.timeout))
    }
}

enum Capped {
    Complete(Vec<u8>),
    Overflow,
}

fn kill(child: &mut Child) {
    // Best effort: the child may already have exited.
    let _ = child.kill();
    let _ = child.wait();
}

fn write_all(mut stdin: ChildStdin, payload: Vec<u8>) -> impl FnOnce() -> io::Result<()> {
    move || {
        stdin.write_all(&payload)?;
        stdin.flush()
    }
}

fn read_capped(stdout: ChildStdout, limits: ExecLimits) -> impl FnOnce() -> io::Result<Capped> {
    move || {
        let cap = limits.max_stdout_bytes;
        let mut buffer = Vec::new();
        let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
        stdout.take(limit).read_to_end(&mut buffer)?;
        Ok(if buffer.len() > cap {
            Capped::Overflow
        } else {
            Capped::Complete(buffer)
        })
    }
}

fn read_tail(mut stderr: ChildStderr) -> impl FnOnce() -> String {
    move || {
        let mut tail: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(read) = stderr.read(&mut chunk) {
            if read == 0 {
                break;
            }
            tail.extend_from_slice(&chunk[..read]);
            if tail.len() > STDERR_TAIL_BYTES {
                tail.drain(..tail.len() - STDERR_TAIL_BYTES);
            }
        }
        String::from_utf8_lossy(&tail).trim().to_string()
    }
}

fn stderr_suffix(tail: &str) -> String {
    if tail.is_empty() {
        String::new()
    } else {
        format!("; stderr: {tail}")
    }
}

#[cfg(test)]
mod tests;
