#!/bin/sh
# The `after` block of tests/fixtures/multimodal/specimens.json: what the
# sigil-cli binary does with the two specimens under every profile of their
# modality, produced by running it (RIC-MM-001 definition of done; never
# written by hand). Needs Tesseract, ffmpeg and the reference ASR
# (scripts/reference/fetch_reference_set.sh).
#
#   scripts/specimens_after.sh <sigil-cli> > after.json
set -eu
bin=$1
models=${SIGIL_REF_MODELS:-.ref-models}
fx=tests/fixtures/multimodal
tess=$(command -v tesseract)
ffmpeg=$(command -v ffmpeg)
qwen=qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow

# shellcheck disable=SC2016 # a jq program, not shell
summary='.result as $r | $r.analysis as $a
  | [$a.vision, $a.audio, $a.text] | map(select(. != null) | .findings[]?) as $f
  | {parity: $r.report.consumed.parity, read: ($r.report.consumed.extractor != null),
     consumed_sha384: $r.report.consumed.digest,
     placeholders: $r.report.consumed.placeholders,
     verdict: ($a.verdict | if type == "object" then keys[0] else . end),
     ceiling: $a.authority_ceiling,
     findings: [$f[] | "\(.kind):\(.severity)"] | unique,
     model_view_transcript: ([$r.report.channels[] | select(.extractor.name == "external-transcript/model-view") | .content | rtrimstr("\n")] | first),
     divergence: ([$r.report.channels[] | select(.channel_kind == "divergence") | .content] | first)}
  | with_entries(select(.value != null))'

image() {
  # shellcheck disable=SC2086 # $2 is extra flags or empty
  "$bin" --format json perceive --input "$fx/attack_source.png" --profile "$1" --analyze \
    --ocr-binary "$tess" --ocr-args "stdin - --psm 6" $2 | jq -c "$summary"
}
audio() {
  # shellcheck disable=SC2086 # $2 is extra flags or empty
  SIGIL_REF_MODELS=$models "$bin" --format json perceive --input "$fx/attack_96k.wav" --profile "$1" --analyze \
    --transcript-binary "$models/venv/bin/python" \
    --transcript-args "scripts/reference/whisper-stdin ffmpeg" $2 | jq -c "$summary"
}

jq -n \
  --arg commit "$(git rev-parse --short HEAD)" \
  --arg version "$("$bin" --version)" \
  --arg tesseract "$(tesseract --version 2>&1 | head -1)" \
  --arg ffmpeg "$(ffmpeg -version | head -1 | cut -d' ' -f1-3)" \
  --argjson qwen "$(image "$qwen" "--vlm-assets $models/qwen2-vl-2b")" \
  --argjson nearest "$(image thumbnail/nearest-80 "")" \
  --argjson decimate "$(audio audio/16k-decimate "")" \
  --argjson filtered "$(audio whisper/16k-filtered "--resampler-binary $ffmpeg")" \
  '{sigil_commit: $commit, sigil_cli: $version, tools: {tesseract: $tesseract, ffmpeg: $ffmpeg, asr: "sherpa-onnx 1.12.40, whisper tiny.en"},
    image: {"qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow": $qwen, "thumbnail/nearest-80": $nearest},
    audio: {"audio/16k-decimate": $decimate, "whisper/16k-filtered": $filtered}}'
