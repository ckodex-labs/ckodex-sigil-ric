#!/bin/sh
# Fetch the public reference files the RIC-MM-001 reference runs need, into
# .ref-models/ (gitignored; nothing here is redistributed). Prints the SHA-384
# of every file it fetched, for docs/reference-models/README.md.
#
#   SIGIL_REF_MODELS=.ref-models scripts/reference/fetch_reference_set.sh
#
# - sherpa-onnx-whisper-tiny.en (k2-fsa/sherpa-onnx release asr-models): the
#   ASR behind scripts/reference/whisper-stdin (O-1) and embeddings.py
# - glove-wiki-gigaword-100 (RaRe-Technologies/gensim-data release), as
#   glove100.gz, for embeddings.py (O-2)
# - the Pillow 13.0.0 source distribution from PyPI, to read Resample.c (O-10)
# - a Python 3.13 venv with sherpa-onnx 1.12.40 and the scripts' imports
set -eu

dest=${SIGIL_REF_MODELS:-.ref-models}
mkdir -p "$dest"

sha384() {
  if command -v sha384sum >/dev/null 2>&1; then sha384sum "$1" | cut -d' ' -f1
  else shasum -a 384 "$1" | cut -d' ' -f1; fi
}

fetch() { # url file
  [ -f "$2" ] || curl -fL --retry 3 -o "$2.part" "$1" && { [ -f "$2" ] || mv "$2.part" "$2"; }
  echo "$(sha384 "$2")  $2  <- $1"
}

fetch https://github.com/k2-fsa/sherpa-onnx/releases/download/asr-models/sherpa-onnx-whisper-tiny.en.tar.bz2 \
  "$dest/sherpa-onnx-whisper-tiny.en.tar.bz2"
[ -d "$dest/sherpa-onnx-whisper-tiny.en" ] || tar -xjf "$dest/sherpa-onnx-whisper-tiny.en.tar.bz2" -C "$dest"

fetch https://github.com/RaRe-Technologies/gensim-data/releases/download/glove-wiki-gigaword-100/glove-wiki-gigaword-100.gz \
  "$dest/glove100.gz"

sdist=$(curl -fsSL https://pypi.org/pypi/pillow/13.0.0/json \
  | python3 -c 'import json,sys; print(next(u["url"] for u in json.load(sys.stdin)["urls"] if u["packagetype"]=="sdist"))')
fetch "$sdist" "$dest/pillow-13.0.0.tar.gz"
[ -d "$dest/pillow-13.0.0" ] || { mkdir -p "$dest/pillow-13.0.0" && tar -xzf "$dest/pillow-13.0.0.tar.gz" -C "$dest/pillow-13.0.0" --strip-components 1; }

[ -x "$dest/venv/bin/python" ] || uv venv --python 3.13 "$dest/venv"
uv pip install --python "$dest/venv/bin/python" --quiet \
  sherpa-onnx==1.12.40 numpy soundfile onnx regex
"$dest/venv/bin/python" -c 'import sherpa_onnx; print("sherpa-onnx", sherpa_onnx.__version__)'
