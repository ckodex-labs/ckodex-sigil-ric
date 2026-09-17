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

    // The Zig archive is bundled into libsigil.a; scripts/build_ffi_shared.sh
    // performs the final shared-object link with the ABI version script.
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=zig_tiktoken");
}
