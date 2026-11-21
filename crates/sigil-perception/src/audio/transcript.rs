/// ASR extractor: a [`PinnedTool`](crate::PinnedTool) whose stdout is the
/// transcript. Artifact bytes stream on stdin, never in an argument.
pub type ExternalTranscript = crate::PinnedTool;
