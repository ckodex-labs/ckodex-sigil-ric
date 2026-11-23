use super::Context;
use crate::cli::commands::*;
use crate::cli::helpers::*;
use crate::cli::types::*;
use crate::cli::{human_reports, vlm};
use anyhow::Result;
use sigil_core::Vocab;
use sigil_core::types::{Provenance, TextSegment};
use sigil_mcp::{EvidenceSink, McpEvidenceRecord, McpGate, McpScanConfig, McpSession};
use sigil_multimodal::{ModalInput, Modality};
use sigil_probe::{
    BaselineProfile, BoundaryProbe, CanaryCase, FingerprintProbe, ProbeConfig, ProbeEngine,
    ProbeSample,
};
use sigil_s::{SentinelModel, compose_with_sigil};
use std::sync::{Arc, Mutex};

pub(super) fn mcp(ctx: Context, command: McpCommand) -> Result<()> {
    let printer = ctx.printer;
    let gate = McpGate::new(ctx.policy, McpScanConfig::default(), ctx.vocab)?;
    let mut session = match &ctx.evidence_sink {
        Some(sink) => {
            let sink: Arc<Mutex<dyn EvidenceSink<McpEvidenceRecord> + Send>> = sink.clone();
            McpSession::with_evidence_sink(gate, sink)
        }
        None => McpSession::new(gate),
    };
    let response = read_command_text(&command.input, &command.text)?;
    let schema = match command.schema {
        Some(path) => Some(parse_schema(&path)?),
        None => None,
    };
    let inspection = session.inspect_response(
        &command.server_id,
        &command.request_hash,
        &response,
        schema.as_ref(),
    )?;
    printer.emit(&inspection, |i| human_reports::render_mcp(i, printer.color))?;
    exit_on_verdict(&inspection.verdict, command.fail_on);
    Ok(())
}

pub(super) fn probe(ctx: &Context, command: &ProbeCommand) -> Result<()> {
    let printer = ctx.printer;
    let samples: Vec<ProbeSample> = load_json_array(command.samples.as_ref())?;
    let canaries: Vec<CanaryCase> =
        load_json_array(command.canaries.as_ref()).unwrap_or_else(|_| Vec::new());
    let fingerprints: Vec<FingerprintProbe> =
        load_json_array(command.fingerprints.as_ref()).unwrap_or_else(|_| Vec::new());
    let boundaries: Vec<BoundaryProbe> =
        load_json_array(command.boundaries.as_ref()).unwrap_or_else(|_| Vec::new());
    let engine = ProbeEngine::new(
        BaselineProfile::from_samples(&samples),
        ProbeConfig::default(),
    );
    let report = engine.analyze(&samples, &canaries, &fingerprints, &boundaries);
    printer.emit(&report, |r| human_reports::render_probe(r, printer.color))
}

pub(super) fn multimodal(ctx: Context, command: MultimodalCommand) -> Result<()> {
    let printer = ctx.printer;
    let engine = build_multimodal_engine(ctx.policy, ctx.vocab, ctx.receipt_signer.as_ref())?;
    let fail_on = command.fail_on;
    let inputs = modal_inputs(command);
    let assessment = engine.analyze(&inputs)?;
    printer.emit(&assessment, |a| {
        human_reports::render_multimodal(a, printer.color)
    })?;
    exit_on_verdict(&assessment.verdict, fail_on);
    Ok(())
}

/// One `ModalInput` per channel the caller supplied, in fixed channel order.
fn modal_inputs(command: MultimodalCommand) -> Vec<ModalInput> {
    let channels = [
        (Modality::Text, command.system, Provenance::System, "system"),
        (Modality::Text, command.text, Provenance::User, "user"),
        (
            Modality::Vision,
            command.vision,
            Provenance::McpTool,
            "vision",
        ),
        (Modality::Audio, command.audio, Provenance::McpTool, "audio"),
        (Modality::Video, command.video, Provenance::McpTool, "video"),
        (Modality::Code, command.code, Provenance::User, "code"),
        (
            Modality::Document,
            command.document,
            Provenance::Retrieval,
            "document",
        ),
    ];
    channels
        .into_iter()
        .filter_map(|(modality, content, provenance, source_id)| {
            content.map(|content| ModalInput {
                modality,
                content,
                provenance,
                source_id: Some(source_id.to_string()),
                ..Default::default()
            })
        })
        .collect()
}

pub(super) fn perceive(ctx: Context, command: PerceiveCommand) -> Result<()> {
    let printer = ctx.printer;
    let fail_on = command.fail_on;
    let outcome = perceive_command(command, ctx.policy, ctx.vocab, ctx.receipt_signer.as_ref())?;
    printer.emit(&outcome, |o| {
        human_reports::render_perceive(o, printer.color)
    })?;
    if let Some(analysis) = &outcome.analysis {
        exit_on_verdict(&analysis.verdict, fail_on);
    }
    Ok(())
}

pub(super) fn vlm_request(ctx: &Context, command: &VlmRequestCommand) -> Result<()> {
    let outcome = vlm::vlm_request_command(command)?;
    ctx.printer.emit(&outcome, vlm::render_vlm_request)
}

pub(super) fn sentinel(ctx: Context, command: &SentinelCommand) -> Result<()> {
    let printer = ctx.printer;
    let model = SentinelModel::default();
    let text = read_command_text(&command.input, &command.text)?;
    let sigil_output = build_sigil(
        Vocab::tiktoken("cl100k_base"),
        ctx.policy,
        ctx.receipt_signer.as_ref(),
        ctx.evidence_sink.as_ref(),
    )?
    .process_text_segments(&[TextSegment {
        text: &text,
        provenance: Provenance::User,
    }])?;
    let sentinel = model.classify(&text, Some(&sigil_output.assessment));
    if command.compose {
        let composite = compose_with_sigil(&sigil_output.assessment, &sentinel);
        printer.emit(&composite, |c| {
            human_reports::render_composite(c, printer.color)
        })?;
        exit_on_verdict(&composite.final_verdict, command.fail_on);
    } else {
        printer.emit(&sentinel, |s| {
            human_reports::render_sentinel(s, printer.color)
        })?;
    }
    Ok(())
}
