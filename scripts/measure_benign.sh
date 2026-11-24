#!/bin/sh
# D5 benign-rate measurement (RIC-MM-001 O-3): run sigil-cli perceive over a
# directory of benign media under every profile of its modality and print one
# JSON line per (file, profile): verdict, authority ceiling, and divergence
# findings. A benign input with a divergence finding is a false positive.
#
#   scripts/measure_benign.sh <sigil-cli> <dir> > results.jsonl
#
# Images run with Tesseract (--psm 6). Audio runs with the reference ASR
# (scripts/reference/whisper-stdin in the .ref-models venv) and ffmpeg.
set -eu
bin=$1
dir=$2
models=${SIGIL_REF_MODELS:-.ref-models}
tess=$(command -v tesseract)
ffmpeg=$(command -v ffmpeg)

row() { # file profile json
  printf '%s' "$3" | jq -c --arg file "$(basename "$1")" --arg profile "$2" \
    --arg sha "$(shasum -a 384 "$1" | cut -d' ' -f1)" '
    .result.analysis as $a
    | [$a.vision, $a.audio, $a.text] | map(select(. != null) | .findings[]?) as $f
    | {file: $file, sha384: $sha, profile: $profile,
       verdict: ($a.verdict | if type == "object" then keys[0] else . end),
       ceiling: $a.authority_ceiling,
       divergence: [$f[] | select(.kind == "representation_divergence") | .severity],
       findings: [$f[] | .kind] }'
}

refused() { # file profile message: the profile does not apply (fail closed)
  jq -cn --arg file "$(basename "$1")" --arg profile "$2" --arg error "$3" \
    '{file: $file, profile: $profile, refused: ($error | fromjson? // {error: $error} | .error)}'
}

for f in "$dir"/*; do
  case "$f" in
    *.png|*.jpg|*.jpeg)
      for p in qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow thumbnail/nearest-80; do
        out=$("$bin" --format json perceive --input "$f" --profile "$p" --analyze \
          --ocr-binary "$tess" --ocr-args "stdin - --psm 6" 2>&1) || { refused "$f" "$p" "$out"; continue; }
        row "$f" "$p" "$out"
      done ;;
    *.wav)
      for p in audio/16k-decimate whisper/16k-filtered; do
        extra=""
        [ "$p" = whisper/16k-filtered ] && extra="--resampler-binary $ffmpeg"
        # shellcheck disable=SC2086 # extra is two words or none
        out=$(SIGIL_REF_MODELS=$models "$bin" --format json perceive --input "$f" --profile "$p" --analyze \
          --transcript-binary "$models/venv/bin/python" \
          --transcript-args "scripts/reference/whisper-stdin ffmpeg" $extra 2>&1) || { refused "$f" "$p" "$out"; continue; }
        row "$f" "$p" "$out"
      done ;;
  esac
done
