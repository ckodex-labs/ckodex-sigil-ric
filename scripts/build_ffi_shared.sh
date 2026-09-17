#!/usr/bin/env bash
# Link the libsigil shared artifact from the staticlib produced by
# `cargo build -p sigil-ffi --release`.
#
# rustc version-scripts every cdylib it links on GNU targets
# ({ global: <rust exports>; local: *; }), which localizes — and therefore
# un-exports — the zig_tiktoken_* symbols bundled from the Zig archive.
# Performing the final link here keeps the documented ABI exported.
set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE="${SIGIL_FFI_PROFILE:-release}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
STATIC_LIB="$TARGET_DIR/$PROFILE/libsigil.a"
MAP="crates/sigil-ffi/sigil.map"

if [ ! -f "$STATIC_LIB" ]; then
    echo "error: $STATIC_LIB not found — run 'cargo build -p sigil-ffi --$PROFILE' first" >&2
    exit 1
fi

os="$(uname -s)"
case "$os" in
    Linux)
        out="$TARGET_DIR/$PROFILE/libsigil.so"
        cc -shared -o "$out" \
            -Wl,-u,sigil_ffi_pin -Wl,-u,sigil_version \
            -Wl,"--version-script=$MAP" \
            "$STATIC_LIB"
        ;;
    Darwin)
        out="$TARGET_DIR/$PROFILE/libsigil.dylib"
        # ld64's -exported_symbols_list does not trigger archive extraction
        # and masks -u — use per-symbol -exported_symbol flags instead.
        export_flags=()
        while read -r sym; do
            export_flags+=("-Wl,-exported_symbol,_$sym")
        done < <(grep -E '^ +(zig_tiktoken|sigil_)' "$MAP" | tr -d ' ;')
        clang -dynamiclib -o "$out" \
            -Wl,-u,_sigil_ffi_pin -Wl,-u,_sigil_version \
            "${export_flags[@]}" \
            "$STATIC_LIB"
        ;;
    *)
        echo "error: unsupported host '$os' — link $STATIC_LIB manually with your platform's shared-library linker" >&2
        exit 1
        ;;
esac

echo "built $out"
