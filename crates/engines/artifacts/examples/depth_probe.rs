//! The P4-R1 reproduction, kept runnable.
//!
//! ```text
//! cargo run -p andon-engine-artifacts --example depth_probe -- 2000
//! ```
//!
//! Builds a deeply nested XML document and hands it to the public parser. Before
//! the depth guard this overflowed the stack and **aborted**: exit 127, no
//! panic, nothing a `Result` or a `catch_unwind` could observe. The input is
//! about 14 KB, so the 32 MiB size cap never came near it.
//!
//! It lives here rather than only as a test because the failure it reproduces is
//! one a test *cannot* report: a stack overflow takes the test binary with it, so
//! the run says nothing at all rather than saying "failed". A reviewer re-running
//! this by hand and seeing `PROCESS ALIVE` with exit 0 is the evidence.
//!
//! Measured abort thresholds for `roxmltree` 0.20 on this workspace, which are
//! where `MAX_ELEMENT_DEPTH = 64` comes from: a debug build survives 165 and
//! aborts at 170; a release build survives 500 and aborts at 2000.

fn main() {
    let depth: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(2000);
    let mut doc = String::from("<coverage>");
    for _ in 0..depth {
        doc.push_str("<a>");
    }
    doc.push_str("<packages/>");
    for _ in 0..depth {
        doc.push_str("</a>");
    }
    doc.push_str("</coverage>");

    eprintln!("doc bytes: {}", doc.len());
    match andon_engine_artifacts::report::CoverageReport::parse("coverage.xml", doc.as_bytes()) {
        Ok(report) => eprintln!("PARSED ok, files={}", report.files.len()),
        Err(err) => eprintln!("REFUSED: {err}"),
    }
    eprintln!("PROCESS ALIVE");
}
