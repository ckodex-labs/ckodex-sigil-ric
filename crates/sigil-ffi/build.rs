use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root");
    let zig_dir = repo_root.join("zig/tiktoken");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let out_lib = out_dir.join("libzig_tiktoken.a");

    for source in [
        "src/lib.zig",
        "src/unicode_props.zig",
        "src/assets/r50k_base.tiktoken",
        "src/assets/p50k_base.tiktoken",
        "src/assets/cl100k_base.tiktoken",
        "src/assets/o200k_base.tiktoken",
    ] {
        println!("cargo:rerun-if-changed={}", zig_dir.join(source).display());
    }

    let status = Command::new("zig")
        .current_dir(&zig_dir)
        .arg("build-lib")
        .arg("-O")
        .arg("ReleaseSafe")
        .arg("-fPIC")
        .arg("-fcompiler-rt")
        .arg("-fno-stack-check")
        .arg(format!("-femit-bin={}", out_lib.display()))
        .arg("src/lib.zig")
        .status()
        .expect("failed to invoke zig");

    if !status.success() {
        panic!("zig build-lib failed with status {status}");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=zig_tiktoken");

    // rustc's cdylib exports only `#[no_mangle]` Rust items — the linked
    // Zig symbols arrive hidden. Re-export the documented ABI explicitly
    // (bindings/c/sigil_tiktoken.h is the contract).
    let os = env::var("CARGO_CFG_TARGET_OS").expect("target os");
    for symbol in [
        "zig_tiktoken_open",
        "zig_tiktoken_close",
        "zig_tiktoken_encode_ordinary",
        "zig_tiktoken_encode_piece",
        "zig_tiktoken_free_tokens",
        "zig_tiktoken_encode_single_token",
        "zig_tiktoken_decode_bytes",
        "zig_tiktoken_free_bytes",
        "zig_tiktoken_special_token_id",
    ] {
        match os.as_str() {
            // ld64 wants the leading-underscore name.
            "macos" => println!("cargo:rustc-link-arg-cdylib=-Wl,-exported_symbol,_{symbol}"),
            "windows" => println!("cargo:rustc-link-arg-cdylib=/EXPORT:{symbol}"),
            _ => println!("cargo:rustc-link-arg-cdylib=-Wl,--export-dynamic-symbol={symbol}"),
        }
    }
}
