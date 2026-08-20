//! The documented convergence run PLAN P6 requires: a real block, a real fix,
//! a real pass, with the loop counter behaving — through the MCP server, over
//! its real transport, reading only what an agent would read.
//!
//! # Why this is one test and not three
//!
//! The subject is a *loop*: the block, the fix, and the pass have to happen to
//! one repository in one order, and the iteration counter's behaviour across
//! them is the evidence. Splitting it would hand each half a fresh repository
//! and assert nothing about the transition, which is the part A2 cares about:
//! an agent that gets blocked and cannot converge to a pass uninstalls the
//! tool.
//!
//! # What "reading only the tool output" means here
//!
//! Every assertion below is over the bytes the MCP client received. Nothing
//! peeks at the store, the record on disk, or library internals: if the
//! payload does not carry enough for the next step, the test fails the way
//! the agent would — which is exactly the acceptance question.

mod common;

use common::{scratch_repo, Server};
use serde_json::{json, Value};

fn profile_of(result: &Value) -> Value {
    assert_ne!(result["isError"], true, "{result}");
    serde_json::from_str(result["content"][0]["text"].as_str().expect("text"))
        .expect("the payload is one JSON document")
}

#[test]
fn a_block_is_fixed_and_passes_with_the_loop_counter_behaving() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    server.initialize("2025-11-25");

    // ---- the block ---------------------------------------------------------
    let blocked = profile_of(&server.call_tool("measure_change", json!({})));
    assert_eq!(blocked["verdict"], "block", "{blocked}");
    assert_eq!(
        blocked["iteration"]["count"], 1,
        "the first attempt at this change is pass 1"
    );

    // The finding an agent would act on: MED+, actionable inside the change,
    // and located to path, span, and symbol — the P6 consumer bar.
    let finding = blocked["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|f| {
            matches!(f["severity"].as_str(), Some("medium" | "high" | "critical"))
                && f["diff_actionable"] == true
        })
        .expect("a MED+ diff-actionable finding is what a block hands the agent");
    let scope = finding["scope"].as_str().expect("a scope string");
    let (path, rest) = scope.split_once(':').expect("scope carries more than a path");
    let (span, symbol) = rest.split_once(':').expect("scope carries span and symbol");
    assert_eq!(path, "src.ts");
    assert_eq!(symbol, "classify");
    let (start, end) = span.split_once('-').expect("a start-end span");
    assert!(
        start.parse::<u32>().is_ok() && end.parse::<u32>().is_ok(),
        "the span is two line numbers an agent can jump to, got {span}"
    );

    // ---- a failed fix: measuring again without changing anything -----------
    // Re-reading one snapshot is not attempting, so the counter must hold.
    let reread = profile_of(&server.call_tool("measure_change", json!({})));
    assert_eq!(reread["verdict"], "block");
    assert_eq!(
        reread["iteration"]["count"], 1,
        "re-measuring an unchanged snapshot counts once, not per call"
    );

    // ---- the fix -----------------------------------------------------------
    // The agent rewrites the function the finding located: still a change
    // against the base (a fix that byte-restores the base would leave nothing
    // in flight to measure), just no longer tangled.
    std::fs::write(
        repo.path().join(path),
        "export function classify(x: number): number {\n  \
         const positive = x > 0 ? 1 : 0;\n  \
         const negative = x < 0 && x > -10 ? -1 : 0;\n  \
         return positive + negative;\n}\n",
    )
    .expect("the fix is written");

    // ---- the pass ----------------------------------------------------------
    let passed = profile_of(&server.call_tool("measure_change", json!({})));
    assert_eq!(passed["verdict"], "pass", "{passed}");
    assert_eq!(
        passed["iteration"]["count"], 0,
        "a clean pass over a complete measurement ends the loop and resets the counter"
    );
    assert_eq!(passed["iteration"]["escalated"], false);
}

#[test]
fn grinding_past_the_cap_escalates_to_a_human() {
    // The other exit from the loop: the change keeps being blocked, each
    // attempt genuinely different, and at the policy cap the tool stops
    // asking the agent and asks a person. PREMORTEM A2's uninstall loop is an
    // agent ground forever; the cap is what makes "stop trying" a verdict the
    // agent can read.
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    server.initialize("2025-11-25");

    let first = profile_of(&server.call_tool("measure_change", json!({})));
    assert_eq!(first["verdict"], "block");
    let cap = first["iteration"]["cap"].as_u64().expect("a cap");

    // Each iteration edits the file without resolving the finding: a distinct
    // change, still tangled. A trailing comment is enough to change the
    // snapshot.
    let mut verdicts = vec![first["verdict"].clone()];
    let mut last = first;
    for attempt in 2..=(cap + 1) {
        let mut tangled = common::tangled_source().to_string();
        tangled.push_str(&format!("// attempt {attempt}\n"));
        std::fs::write(repo.path().join("src.ts"), tangled).expect("another attempt");
        last = profile_of(&server.call_tool("measure_change", json!({})));
        verdicts.push(last["verdict"].clone());
    }

    assert_eq!(
        last["verdict"], "escalate_to_human",
        "past the cap the loop is over, verdict history: {verdicts:?}"
    );
    assert_eq!(last["iteration"]["escalated"], true);
    assert_eq!(last["iteration"]["cap"], cap);
}
