use super::Context;
use crate::cli::commands::*;
use crate::cli::human_reports;
use crate::cli::types::*;
use anyhow::Result;

pub(super) fn keygen(ctx: &Context, command: &KeygenCommand) -> Result<()> {
    let printer = ctx.printer;
    let outcome = keygen_command(command)?;
    printer.emit(&outcome, |o| human_reports::render_keygen(o, printer.color))
}

pub(super) fn verify_receipt(ctx: &Context, command: &VerifyReceiptCommand) -> Result<()> {
    let printer = ctx.printer;
    let outcome = verify_receipt_command(command)?;
    printer.emit(&outcome, |o| {
        human_reports::render_verification(
            o.valid,
            &format!(
                "  algorithm   {}\n  key id      {}\n",
                o.algorithm.as_deref().unwrap_or("-"),
                o.key_id.as_deref().unwrap_or("-")
            ),
            o.error.as_deref(),
            printer.color,
        )
    })?;
    exit_unless_valid(outcome.valid);
    Ok(())
}

pub(super) fn attest(ctx: &Context, command: &AttestCommand) -> Result<()> {
    let printer = ctx.printer;
    let envelope = attest_command(command)?;
    printer.emit(&envelope, |e| {
        human_reports::render_attest(e, printer.color)
    })
}

pub(super) fn verify_attestation(ctx: &Context, command: &VerifyAttestationCommand) -> Result<()> {
    let printer = ctx.printer;
    let outcome = verify_attestation_command(command)?;
    printer.emit(&outcome, |o| {
        human_reports::render_verification(
            o.valid,
            &format!(
                "  payload     {}\n",
                o.payload_type.as_deref().unwrap_or("-")
            ),
            o.error.as_deref(),
            printer.color,
        )
    })?;
    exit_unless_valid(outcome.valid);
    Ok(())
}

pub(super) fn lease_create(ctx: &Context, command: &LeaseCreateCommand) -> Result<()> {
    let printer = ctx.printer;
    let lease = lease_create_command(command, ctx.receipt_signer.as_deref())?;
    printer.emit(&lease, |l| human_reports::render_lease(l, printer.color))
}

pub(super) fn lease_verify(ctx: &Context, command: &LeaseVerifyCommand) -> Result<()> {
    let printer = ctx.printer;
    let outcome = lease_verify_command(command)?;
    printer.emit(&outcome, |o| {
        human_reports::render_lease_verification(o, printer.color)
    })?;
    exit_unless_valid(outcome.valid);
    Ok(())
}

pub(super) fn envelope_create(ctx: &Context, command: &EnvelopeCreateCommand) -> Result<()> {
    let printer = ctx.printer;
    let envelope = envelope_create_command(command, ctx.receipt_signer.as_deref())?;
    printer.emit(&envelope, |e| {
        human_reports::render_envelope(e, printer.color)
    })
}

pub(super) fn envelope_verify(ctx: &Context, command: &EnvelopeVerifyCommand) -> Result<()> {
    let printer = ctx.printer;
    let outcome = envelope_verify_command(command)?;
    printer.emit(&outcome, |o| {
        human_reports::render_envelope_verification(o, printer.color)
    })?;
    exit_unless_valid(outcome.valid);
    Ok(())
}

pub(super) fn lease_revoke(ctx: &Context, command: &LeaseRevokeCommand) -> Result<()> {
    let printer = ctx.printer;
    let registry = lease_revoke_command(command)?;
    printer.emit(&registry, |r| {
        human_reports::render_lease_revoke(r, printer.color)
    })
}

/// Verification subcommands exit 1 after printing an invalid outcome.
fn exit_unless_valid(valid: bool) {
    if !valid {
        std::process::exit(1);
    }
}
