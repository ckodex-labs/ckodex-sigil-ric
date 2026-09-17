//! Container bases — toolchain images with caches mounted.
//!
//! Every lane runs in a `rust:<ver>-bookworm` container with the repo
//! mounted at `/src` and persistent cache volumes for the cargo
//! registry, git checkouts, and the target dir (keyed per toolchain so
//! MSRV and 1.90 artifacts never mix).

use dagger_sdk::{Container, Directory, HostDirectoryOpts, Query};

/// Product MSRV — mirrors `rust-version` in the workspace Cargo.toml.
/// Floor is 1.88: image 0.25.10 / icu 2.3.x / idna_adapter declare it,
/// and clap_lex 1.x needs edition-2024-capable Cargo to even parse.
pub const MSRV: &str = "1.88";

/// Repo checkout mounted read-only-ish (target/ is a cache overlay).
pub fn source(client: &Query) -> Directory {
    client.host().directory_opts(
        ".",
        HostDirectoryOpts {
            exclude: Some(vec!["target", "ci/target", ".git", "ci-out"]),
            include: None,
            no_cache: None,
            gitignore: None,
        },
    )
}

/// rust:<ver> + rustfmt + llvm-tools-preview + pinned Zig, cargo
/// caches mounted. Zig is a workspace build dependency — sigil-core's
/// build.rs compiles libzig_tiktoken.a unconditionally.
pub fn rust(client: &Query, version: &str) -> Container {
    let image = format!("rust:{version}-bookworm");
    let target_cache = client.cache_volume(format!("sigil-target-{version}"));
    client
        .container()
        .from(image)
        .with_exec(sh(
            "rustup component add rustfmt clippy llvm-tools-preview && \
             apt-get update -qq && apt-get install -y -qq python3 xz-utils curl ca-certificates",
        ))
        .with_exec(sh(ZIG_INSTALL))
        .with_mounted_directory("/src", source(client))
        .with_mounted_cache(
            "/usr/local/cargo/registry",
            client.cache_volume("sigil-cargo-registry"),
        )
        .with_mounted_cache("/usr/local/cargo/git", client.cache_volume("sigil-cargo-git"))
        .with_mounted_cache("/src/target", target_cache)
        .with_workdir("/src")
}

/// `rust()` plus the Go 1.22 toolchain — only the bindings lane
/// compiles/tests Go code.
pub fn rust_go(client: &Query, version: &str) -> Container {
    rust(client, version).with_exec(sh(GO_INSTALL))
}

/// Wrap a shell string for `with_exec`.
pub fn sh(cmd: &str) -> Vec<String> {
    vec!["sh".to_string(), "-c".to_string(), cmd.to_string()]
}

const ZIG_INSTALL: &str = r#"arch=$(uname -m) && \
curl -fsSL "https://ziglang.org/download/0.15.2/zig-${arch}-linux-0.15.2.tar.xz" \
  | tar -xJ -C /opt && \
ln -sf /opt/zig-${arch}-linux-0.15.2/zig /usr/local/bin/zig && zig version"#;

const GO_INSTALL: &str = r#"arch=$(uname -m) && \
[ "$arch" = x86_64 ] && goarch=amd64 || goarch=arm64; \
curl -fsSL "https://go.dev/dl/go1.22.12.linux-${goarch}.tar.gz" \
  | tar -xzC /usr/local && \
ln -sf /usr/local/go/bin/go /usr/local/bin/go && go version"#;

/// cargo-llvm-cov pinned binary (taiki-e v0.6.16).
pub const LLVM_COV_INSTALL: &str = r#"arch=$(uname -m) && \
curl -fsSL "https://github.com/taiki-e/cargo-llvm-cov/releases/download/v0.6.16/cargo-llvm-cov-${arch}-unknown-linux-gnu.tar.gz" \
  | tar -xz -C /usr/local/cargo/bin && cargo llvm-cov --version"#;
