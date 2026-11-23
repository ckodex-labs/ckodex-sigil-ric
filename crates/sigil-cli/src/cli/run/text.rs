use super::Context;
use crate::cli::helpers::*;
use crate::cli::results::*;
use crate::cli::types::*;
use crate::cli::{human, human_reports};
use anyhow::Result;
use clap::CommandFactory;
use sigil_core::types::{Provenance, TextSegment};
use sigil_core::vocab::SpecialTokenMode;

pub(super) fn completions(command: &CompletionsCommand) {
    clap_complete::generate(
        command.shell,
        &mut Cli::command(),
        "sigil-cli",
        &mut std::io::stdout(),
    );
}

/// `tokenize` and `scan` run the same pipeline; only the subcommand name differs.
pub(super) fn scan(ctx: Context, command: &TextCommand) -> Result<()> {
    let printer = ctx.printer;
    let sigil = build_sigil(
        ctx.vocab,
        ctx.policy,
        ctx.receipt_signer.as_ref(),
        ctx.evidence_sink.as_ref(),
    )?;
    let text = read_text(command)?;
    let output = sigil.process_text_segments(&[TextSegment {
        text: &text,
        provenance: Provenance::User,
    }])?;
    let envelope = SigilJson {
        output: &output,
        techniques: collect_techniques(&output),
        mitigations: collect_mitigations(&output),
    };
    printer.emit(&envelope, |w| {
        human::render_sigil(w.output, Some(&text), command.explain, printer.color)
    })?;
    exit_on_verdict(&output.assessment.verdict, command.fail_on);
    Ok(())
}

pub(super) fn tokenize_batch(ctx: &Context, command: &BatchTextCommand) -> Result<()> {
    let printer = ctx.printer;
    let inputs = read_batch_text(command)?;
    let encoded = if command.allow_specials {
        ctx.actor
            .encode_batch_with_specials(&inputs, SpecialTokenMode::AllowAll)?
    } else {
        ctx.actor.encode_batch(&inputs)?
    };
    let result = BatchTokenizeResult::from_encoded(inputs, encoded);
    printer.emit(&result, |r| {
        human_reports::render_batch_tokenize(r, printer.color)
    })
}

pub(super) fn decode(ctx: &Context, command: &TokenIdsCommand) -> Result<()> {
    let printer = ctx.printer;
    let ids = read_token_ids(command)?;
    let text = ctx.vocab.decode(&ids);
    let result = DecodeResult { ids, text };
    printer.emit(&result, |r| human_reports::render_decode(r, printer.color))
}

pub(super) fn decode_batch(ctx: &Context, command: &TokenIdsBatchCommand) -> Result<()> {
    let printer = ctx.printer;
    let batches = read_token_batches(command)?;
    let texts = ctx.actor.decode_batch(&batches)?;
    let result = BatchDecodeResult { batches, texts };
    printer.emit(&result, |r| {
        human_reports::render_batch_decode(r, printer.color)
    })
}
