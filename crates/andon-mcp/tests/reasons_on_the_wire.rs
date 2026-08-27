//! A blocked agent can read WHY, from the bytes it actually receives.
//!
//! P6's F1 (E61, CRITICAL) was found by driving this server over stdio JSON-RPC:
//! an agent got `"verdict":"block"` with nothing in the payload explaining it.
//! `AgentProfile` had no `reasons` field, and `policy-change-loosening` — the
//! code that fires exactly when an agent edits `.andon.toml` mid-change — had no
//! backing `MeasurementResult`, so no path into the agent JSON at all.
//!
//! D1 added the field. The fix was then verified everywhere except where the
//! finding lived: `agent_profile.rs` asserts `total_reasons` at 1, 10 and 20, and
//! a recursive grep for `reasons` across this crate returned **nothing** — source
//! or tests. `conformance.rs` asserts `profile`, `verdict`, `total_findings` and
//! the byte budget, never `reasons`; its own coverage note is explicitly about
//! the budget ("both layers hold the same bound"), which does not extend to
//! field presence. So the one claim that mattered to F1 was pinned at the layer
//! where it was never in doubt and absent at the layer where it was (D41).
//!
//! This file holds it where the wire is. The behaviour was already correct when
//! measured — a scratch measurement returns `block` carrying `severity-med-plus`
//! and `measurement-incomplete` — so this pins a working surface rather than
//! fixing a broken one. That is the point: F1's regression would be silent
//! without it, because nothing else on this path reads the field.

mod common;

use common::{scratch_repo, Server};
use serde_json::{json, Value};

#[test]
fn a_blocking_verdict_reaches_the_agent_with_its_reasons_attached() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    server.initialize("2025-11-25");
    let result = server.call_tool("measure_change", json!({}));

    assert_ne!(
        result["isError"], true,
        "an ordinary measurement is not an error: {result}"
    );
    let payload = result["content"][0]["text"].as_str().expect("text content");
    let profile: Value = serde_json::from_str(payload).expect("one JSON document");

    // Guard against the whole test passing vacuously. F1 is a claim about what
    // an agent sees when it is STOPPED; a fixture that sailed through would
    // assert nothing about that, and would do it quietly.
    let verdict = profile["verdict"].as_str().expect("a verdict string");
    assert!(
        matches!(verdict, "block" | "escalate_to_human"),
        "this fixture must produce a decisive verdict or it cannot test F1 — got {verdict:?}. \
         If the fixture legitimately became clean, make it dirty again rather than \
         relaxing this: a green test that never sees a block is how F1 shipped."
    );

    // The field exists on the wire, not merely on the struct.
    let reasons = profile["reasons"]
        .as_array()
        .expect("`reasons` is absent from the agent payload — this is F1 exactly");
    let total = profile["total_reasons"]
        .as_u64()
        .expect("`total_reasons` is absent from the agent payload");

    assert!(
        !reasons.is_empty(),
        "the agent was blocked and handed an empty `reasons` array, which is F1 \
         with the field present: {profile}"
    );
    assert!(
        total >= reasons.len() as u64,
        "total_reasons ({total}) is below the number rendered ({}) — the count \
         that tells an agent whether the list was truncated is wrong",
        reasons.len()
    );

    // A reason an agent cannot act on is the same silence in a different shape.
    for reason in reasons {
        let code = reason["code"].as_str().unwrap_or_default();
        let message = reason["message"].as_str().unwrap_or_default();
        assert!(
            !code.is_empty(),
            "a reason reached the wire with no code: {reason}"
        );
        assert!(
            !message.is_empty(),
            "reason `{code}` reached the wire with no message, so an agent is told \
             that something is wrong and not what: {reason}"
        );
    }
}
