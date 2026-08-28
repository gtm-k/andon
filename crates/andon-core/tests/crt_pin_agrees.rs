//! Guards the two declarations behind MSVC CRT parity (ruling E71).
//!
//! `dist-workspace.toml` says `msvc-crt-static = true`, which makes cargo-dist
//! put `-Ctarget-feature=+crt-static` into RUSTFLAGS for every MSVC build; and
//! `.cargo/config.toml` pins the same flag for `x86_64-pc-windows-msvc` so that
//! CI, developers and `scripts/self-measure.sh` link the same runtime. They must
//! agree. An environment RUSTFLAGS *replaces* the config table rather than
//! merging with it, so flipping the dist key to `false` would silently unpin
//! the release build alone — the self-report would attest a binary the release
//! never contained, and nothing would say so. This test says so.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("andon-core lives two levels below the workspace root")
        .to_path_buf()
}

fn read_toml(rel: &str) -> toml::Value {
    let path = workspace_root().join(rel);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    toml::from_str(&text).unwrap_or_else(|e| panic!("{}: not TOML: {e}", path.display()))
}

#[test]
fn dist_and_cargo_config_agree_on_the_msvc_c_runtime() {
    // cargo-dist's default for a missing key is `true`; an absent key therefore
    // reads as static, matching what `dist build` would do.
    let dist = read_toml("dist-workspace.toml");
    let dist_static = dist
        .get("dist")
        .and_then(|d| d.get("msvc-crt-static"))
        .is_none_or(|v| v.as_bool().expect("msvc-crt-static is a boolean"));

    let config = read_toml(".cargo/config.toml");
    let config_static = config
        .get("target")
        .and_then(|t| t.get("x86_64-pc-windows-msvc"))
        .and_then(|t| t.get("rustflags"))
        .and_then(|f| f.as_array())
        .is_some_and(|flags| {
            flags
                .iter()
                .any(|f| f.as_str().is_some_and(|s| s.contains("+crt-static")))
        });

    assert_eq!(
        dist_static,
        config_static,
        "dist-workspace.toml says msvc-crt-static = {dist_static} but .cargo/config.toml \
         {} pin +crt-static for x86_64-pc-windows-msvc. The two must agree: dist puts its \
         flag in the RUSTFLAGS environment, which replaces the config table, so a release \
         built with one and a self-measure built with the other are different bytes (E71).",
        if config_static { "does" } else { "does not" }
    );
}
