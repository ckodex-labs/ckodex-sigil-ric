#!/usr/bin/env bash
# Build `sigil.wasm` — the wasm32-freestanding reactor-module artifact
# (spec §4 Delivery Artifacts).
#
# Reactor shape (build-exe -fno-entry -rdynamic): a self-contained module
# exporting `memory` + the full `zig_tiktoken_*` ABI with data relocations
# already applied. The `-dynamic` alternative produces an experimental
# shared-library wasm that needs `__wasm_apply_data_relocs` at load time —
# not what edge/browser consumers want.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${SIGIL_WASM_OUT:-$REPO_ROOT/zig/tiktoken/zig-out}"
OUT="$OUT_DIR/sigil.wasm"

mkdir -p "$OUT_DIR"

zig build-exe \
    -target wasm32-freestanding \
    -O ReleaseSmall \
    -rdynamic \
    -fno-entry \
    -femit-bin="$OUT" \
    "$REPO_ROOT/zig/tiktoken/src/lib.zig"

echo "sigil.wasm → $OUT"

if command -v wasm-tools >/dev/null 2>&1; then
    wasm-tools validate "$OUT" >/dev/null
    echo "wasm-tools validate: OK"
fi
