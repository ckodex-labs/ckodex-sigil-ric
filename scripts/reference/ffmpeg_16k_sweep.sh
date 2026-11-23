#!/bin/sh
# Run the audio specimen through ffmpeg's 16 kHz path (the whisper/16k-filtered
# reference command) in several distribution and static ffmpeg builds, under
# Dagger, and print the SHA-384 of each s16le output. Evidence for O-8
# (docs/reference-models/FFMPEG-16K.md). Run from the repository root.
set -eu
out=${1:-.ref-models/ffmpeg-16k}
mkdir -p "$out"
apt='export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null && apt-get install -y -qq ffmpeg >/dev/null'
apk='apk add --no-cache ffmpeg >/dev/null'
run() { # image install ffmpeg-path
  tag=$(printf %s "$1" | tr '/:' '__')
  pre=""
  [ -n "$2" ] && pre="| with-exec -- sh -c '$2' "
  dagger -c "container | from $1 $pre| with-file /in.wav \$(host | file tests/fixtures/multimodal/attack_96k.wav) | with-exec -- $3 -loglevel error -i /in.wav -f s16le -ac 1 -ar 16000 /out.raw | file /out.raw | export $out/$tag.raw" >/dev/null
  ver=$(dagger -c "container | from $1 $pre| with-exec -- $3 -version | stdout" | head -1)
  echo "$ver  $(shasum -a 384 "$out/$tag.raw" | cut -d' ' -f1)  $1"
}
for img in debian:bookworm debian:trixie ubuntu:20.04 ubuntu:22.04 ubuntu:24.04; do run "$img" "$apt" ffmpeg; done
for img in alpine:3.16 alpine:3.18 alpine:3.20 alpine:3.22; do run "$img" "$apk" ffmpeg; done
for v in 6.0 6.1.1 7.0.2 7.1 8.0; do run "mwader/static-ffmpeg:$v" "" /ffmpeg; done
