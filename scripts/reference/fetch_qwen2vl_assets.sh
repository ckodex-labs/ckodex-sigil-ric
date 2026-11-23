#!/bin/sh
# Fetch the Qwen2-VL-2B interpreter files SIGIL's tests run against.
#
# SIGIL does not redistribute these files. They come from their original
# Hugging Face repository at a pinned revision, and each is checked against
# the SHA-384 that crates/sigil-perception/src/vlm/qwen2vl.rs (QWEN2_VL_2B)
# pins; the loader rejects any file that differs, so a wrong download fails
# the tests rather than passing them. See docs/reference-models/QWEN2-VL-2B.md.
# A file already present with the pinned digest is not fetched again.
#
#   scripts/reference/fetch_qwen2vl_assets.sh [dest]   (default .ref-models/qwen2-vl-2b)
set -eu

dest=${1:-.ref-models/qwen2-vl-2b}
repo=mlx-community/Qwen2-VL-2B-4bit
rev=949a35dce2ee94a3337551e02051ab00dde3e3b4

sha384() {
  if command -v sha384sum >/dev/null 2>&1; then sha384sum "$1" | cut -d' ' -f1
  else shasum -a 384 "$1" | cut -d' ' -f1; fi
}

mkdir -p "$dest"
while read -r name digest; do
  file="$dest/$name"
  if [ -f "$file" ] && [ "$(sha384 "$file")" = "$digest" ]; then
    continue
  fi
  curl -fsSL --retry 3 -o "$file.part" "https://huggingface.co/$repo/resolve/$rev/$name"
  got=$(sha384 "$file.part")
  if [ "$got" != "$digest" ]; then
    rm -f "$file.part"
    echo "fetch_qwen2vl_assets: $name has SHA-384 $got, expected $digest" >&2
    exit 1
  fi
  mv "$file.part" "$file"
done <<'PINS'
tokenizer.json 30aedba44ef99e56dd9ed1b3d87639bcf53a3b340f1141ce31c7f8b8614f19c38a0b4012f05cd95d0f4e10178d5bb876
chat_template.json f5a8f61b5506abec91df2b22d5ce7831ecb3839a6dc8295cc05b33f60f04f6db696b4aaaeec0228ffb356f3609579237
preprocessor_config.json 4ec0b01c8eeb212bca1510da729737625a3ee0374ac0ad3ba4f384f5351997b67a464853625cfe3678ef55612530c082
config.json 997410891ba417414080c97d7a11394c2424dbb37e501786c951000d5d6c3c5a40e8ac4820074ae0352369bb694d122f
README.md 3cf9f08d4c58c337d41e02687ba824ee20065d51bcbda557e7c8fa7774f19ed3a2b1e257cd36d395fb35b604967b8140
PINS
