//! MCP conformance: the server, over its real stdio transport.
//!
//! Every test here drives the `andon-mcp` binary as a subprocess and speaks
//! raw newline-delimited JSON-RPC to it, for the reason `first_run.rs` gives
//! for driving `andon`: a library-level test would leave the transport — the
//! part an agent actually connects to — unexercised. Raw JSON rather than an
//! rmcp client, because two of these tests need to say things a well-behaved
//! client never says (an unknown protocol version), and because a test that
//! used rmcp on both ends would let one bug agree with itself.
//!
//! # The version pin
//!
//! `an_unknown_version_is_answered_with_the_servers_own` asserts the literal
//! version string the server falls back to. That literal is the pin PLAN P6
//! requires: bumping the rmcp dependency in a way that changes what this
//! server negotiates fails a named test, so a protocol-version change is a
//! reviewed event and never a side effect of `cargo update`.
//!
//! # The budget
//!
//! `measure_change_stays_inside_the_declared_budget` measures the actual
//! serialized tool-output bytes — the thing an agent's context pays for — and
//! asserts them against `[agent]` in policy, the way P5b's
//! `agent_profile_budget` asserts the projection. Both layers hold the same
//! bound; this one holds it where the wire is.

mod common;

use common::{scratch_repo, Server};
use serde_json::{json, Value};

/// The declared agent-payload budget in bytes for a repository with no
/// `.andon.toml`: the policy defaults, read from the same type the server
/// reads them from.
fn default_budget_bytes() -> usize {
    let policy = andon_core::policy::Policy::default();
    (policy.agent.profile_token_budget as usize) * (policy.agent.bytes_per_token as usize)
}

#[test]
fn a_supported_requested_version_is_echoed() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    // Not the newest version rmcp knows, so an echo cannot be mistaken for
    // the server ignoring the request and stating its own default.
    let result = server.initialize("2025-06-18");
    assert_eq!(
        result["protocolVersion"], "2025-06-18",
        "a version the server supports must be echoed back, per MCP version negotiation"
    );
}

#[test]
fn an_unknown_version_is_answered_with_the_servers_own() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    let result = server.initialize("1999-01-01");
    // THE PIN. rmcp `=3.1.4` speaks 2025-11-25 as its current version; if a
    // dependency bump changes this answer, this named test is the loud event
    // the compatibility policy promises.
    assert_eq!(result["protocolVersion"], "2025-11-25");
    assert_eq!(
        result["protocolVersion"],
        serde_json::to_value(rmcp::model::ProtocolVersion::LATEST).expect("a version serializes"),
        "the fallback must be the pinned SDK's own current version, not a second list"
    );
}

#[test]
fn initialize_names_the_server_and_instructs_the_agent() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    let result = server.initialize("2025-11-25");
    assert_eq!(result["serverInfo"]["name"], "andon");
    let instructions = result["instructions"].as_str().expect("instructions");
    // The A2 surface: the first thing an agent reads must say when to call
    // what, not merely that tools exist.
    assert!(instructions.contains("measure_change"));
    assert!(instructions.contains("diff_actionable"));
}

#[test]
fn tools_list_names_exactly_the_five_tools() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    server.initialize("2025-11-25");
    let result = server.request("tools/list", json!({}));
    let tools = result["tools"].as_array().expect("a tool list");
    let mut names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("a name"))
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "await_results",
            "explain_finding",
            "get_ledger",
            "get_results",
            "measure_change"
        ]
    );
    for tool in tools {
        assert!(
            !tool["description"].as_str().unwrap_or("").is_empty(),
            "{} has no description — the tool list is what tells an agent when to call it",
            tool["name"]
        );
        assert_eq!(
            tool["inputSchema"]["type"], "object",
            "{} must declare an object input schema",
            tool["name"]
        );
    }
}

#[test]
fn measure_change_returns_the_agent_profile_and_stays_inside_the_declared_budget() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    server.initialize("2025-11-25");
    let result = server.call_tool("measure_change", json!({}));

    assert_ne!(
        result["isError"], true,
        "an ordinary measurement is not an error: {result}"
    );
    let payload = result["content"][0]["text"].as_str().expect("text content");

    // The payload parses, names its view, and is a verdict about the change.
    let profile: Value = serde_json::from_str(payload).expect("the payload is one JSON document");
    assert_eq!(profile["profile"], "agent-mode");
    assert!(profile["verdict"].is_string());
    assert!(
        profile["total_findings"].as_u64().expect("a count") > 0,
        "a real change measured to nothing is PREMORTEM A1 on the agent surface"
    );

    // The bound, measured where the wire is: every byte of text an agent
    // receives from this call, against the budget the policy declares.
    let total: usize = result["content"]
        .as_array()
        .expect("content array")
        .iter()
        .map(|block| block["text"].as_str().unwrap_or("").len())
        .sum();
    assert!(
        total <= default_budget_bytes(),
        "tool output of {total} bytes exceeds the declared budget of {} bytes",
        default_budget_bytes()
    );
}

#[test]
fn the_budget_is_read_from_the_repositorys_own_policy() {
    let repo = scratch_repo();
    // Declare a budget well below the default. The findings this change
    // produces overflow it, so the profile must truncate and say so — which
    // proves the server reads the repository's policy rather than a constant.
    std::fs::write(
        repo.path().join(".andon.toml"),
        "schema_version = 1\n\n[agent]\nprofile_token_budget = 300\nbytes_per_token = 4\n",
    )
    .expect("policy written");

    let mut server = Server::start(repo.path());
    server.initialize("2025-11-25");
    let result = server.call_tool("measure_change", json!({}));
    let payload = result["content"][0]["text"].as_str().expect("text content");
    assert!(
        payload.len() <= 1200,
        "the declared 1200-byte budget did not bound the payload: {} bytes",
        payload.len()
    );
    let profile: Value = serde_json::from_str(payload).expect("still one JSON document");
    assert_eq!(
        profile["truncated"], true,
        "a cut payload must announce itself, never silently shrink"
    );
}

#[test]
fn get_results_before_any_measurement_says_what_to_do_next() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    server.initialize("2025-11-25");
    let result = server.call_tool("get_results", json!({}));
    assert_eq!(result["isError"], true);
    let message = result["content"][0]["text"].as_str().expect("text");
    assert!(
        message.contains("measure_change"),
        "the refusal must name the tool this actor can actually call, got: {message}"
    );
}

#[test]
fn await_results_reports_the_lane_beside_the_profile() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    server.initialize("2025-11-25");
    server.call_tool("measure_change", json!({}));
    let result = server.call_tool("await_results", json!({}));
    assert_ne!(result["isError"], true);
    let profile: Value = serde_json::from_str(
        result["content"][0]["text"]
            .as_str()
            .expect("profile block"),
    )
    .expect("profile parses");
    assert_eq!(profile["profile"], "agent-mode");
    let lane_report = result["content"][1]["text"].as_str().expect("lane block");
    assert!(
        lane_report.contains("async"),
        "the lane report says what the async lane owes, got: {lane_report}"
    );
}

#[test]
fn explain_finding_answers_for_a_metric_the_measurement_produced() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    server.initialize("2025-11-25");
    let measured = server.call_tool("measure_change", json!({}));
    let profile: Value =
        serde_json::from_str(measured["content"][0]["text"].as_str().expect("profile"))
            .expect("parses");
    // Derived, not restated: explain whatever metric the measurement actually
    // led with, so this test cannot drift from the shipped roster.
    let metric_id = profile["findings"][0]["metric_id"]
        .as_str()
        .expect("a finding with a metric id");

    let result = server.call_tool("explain_finding", json!({ "id": metric_id }));
    assert_ne!(result["isError"], true, "{result}");
    let answer = result["content"][0]["text"].as_str().expect("text");
    assert!(
        answer.contains("What this number does NOT tell you"),
        "the field this tool exists for is missing from: {answer}"
    );
}

#[test]
fn explain_finding_refuses_an_unknown_id_with_directions() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    server.initialize("2025-11-25");
    let result = server.call_tool("explain_finding", json!({ "id": "no-such-metric" }));
    assert_eq!(result["isError"], true);
    let message = result["content"][0]["text"].as_str().expect("text");
    assert!(
        !message.trim().is_empty(),
        "a refusal must say something the caller can act on"
    );
}

#[test]
fn get_ledger_reads_what_measure_change_recorded() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    server.initialize("2025-11-25");

    // Before any measurement: the empty ledger names the CLI that writes one.
    let empty = server.call_tool("get_ledger", json!({}));
    let empty_text = empty["content"][0]["text"].as_str().expect("text");
    assert!(
        empty_text.contains("No measurement is recorded"),
        "got: {empty_text}"
    );

    // measure_change records to the ledger — the P6 instrumentation — so the
    // listing now carries one record whose invocation source is visible.
    server.call_tool("measure_change", json!({}));
    let listed = server.call_tool("get_ledger", json!({}));
    let listing = listed["content"][0]["text"].as_str().expect("text");
    assert!(
        listing.contains("1 record(s)"),
        "the agent-initiated measurement must be in the ledger, got: {listing}"
    );
    assert!(
        listing.contains("AgentInitiated"),
        "the invocation source is the dimension the dogfood protocol counts, got: {listing}"
    );
}

#[test]
fn a_nonexistent_repository_is_refused_with_prose() {
    let repo = scratch_repo();
    let mut server = Server::start(repo.path());
    server.initialize("2025-11-25");
    let result = server.call_tool(
        "measure_change",
        json!({ "repo": repo.path().join("not-here").to_string_lossy() }),
    );
    assert_eq!(result["isError"], true);
    let message = result["content"][0]["text"].as_str().expect("text");
    assert!(
        !message.starts_with('{'),
        "a refusal is prose with directions, never a struct dump: {message}"
    );
}
