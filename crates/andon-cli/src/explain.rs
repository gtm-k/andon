//! `andon explain` — where a number meets the evidence it stands on.
//!
//! # This subcommand is the product
//!
//! Every phase before this one existed so that a number could carry its
//! evidence: claim tuples scoped to an implementation, a version, a language and
//! a predicted outcome; a tier that says how strong the evidence is; a citation
//! somebody can go and read; an expiry after which the claim demotes in public;
//! and the honesty field — *what this number is not evidence for* — which is
//! required and non-empty because a claim that predicts everything predicts
//! nothing.
//!
//! All of that reaches a human here. A tool that reported `cognitive complexity:
//! 20` and nothing else would be one more metric dashboard, and the argument
//! against metric dashboards is that nobody can tell which of their numbers mean
//! anything. So this command answers two questions about any number the tool can
//! produce, and it answers them whether or not a measurement has been taken:
//!
//! - **Why should I believe this?** — tier, citation, population, effect, and
//!   the date the claim is next re-reviewed.
//! - **What does it not tell me?** — every `does_not_predict` line, verbatim.
//!
//! And two more that decide what the number can *do*:
//!
//! - **Can it stop the line?** — its class, its tier, and the ceiling the policy
//!   in force puts on that tier.
//! - **Is it in the compare set?** — whether the verifier will recompute it and
//!   compare digests, or whether it is CI-authoritative only.
//!
//! # Nothing here is restated
//!
//! Every value printed is read from the registry, the ladder declaration, or the
//! policy — never from a sentence in this file that says what one of them
//! contains. That is E21's rule, and it is the defect class this project has
//! shipped three times: a statement that reads the field it describes cannot
//! drift from it.

use std::fmt::Write as _;

use andon_core::date::Date;
use andon_core::policy::Policy;
use andon_core::registry::ResolvedClaim;
use andon_core::schema::enums::{EvidenceTier, MetricClass, Severity};
use andon_core::schema::payload::MeasurementRecord;
use andon_core::schema::payload::MeasurementResult;
use andon_core::verdict::ladder::{SeverityLadder, Threshold};
use andon_core::verdict::severity;

use crate::measure;
use crate::shipped;

/// What `explain` was asked about.
#[derive(Debug)]
pub enum Subject {
    /// A metric this build can emit.
    Metric(String),
    /// A claim in the registry.
    Claim(String),
}

/// Resolve a free-text argument to a subject, or say what is available.
pub fn subject_of(query: &str) -> Result<Subject, String> {
    if shipped::engine_for_metric(query).is_some() {
        return Ok(Subject::Metric(query.to_string()));
    }
    if query.contains('@') && query.contains('|') {
        return Ok(Subject::Claim(query.to_string()));
    }
    // A near miss is more useful than a list of forty. Prefix and substring, in
    // that order, because a reader who typed `cognitive` meant the family.
    let all = shipped::all_metric_ids();
    let near: Vec<&String> = all.iter().filter(|id| id.contains(query)).collect();
    if near.len() == 1 {
        return Ok(Subject::Metric(near[0].clone()));
    }
    let suggestion = if near.is_empty() {
        format!(
            "This build emits {} metric(s). `andon explain --list` prints them.",
            all.len()
        )
    } else {
        format!(
            "Did you mean one of these?\n  {}",
            near.iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n  ")
        )
    };
    Err(format!(
        "no metric or claim matches '{query}'.\n{suggestion}"
    ))
}

/// Every metric this build can emit, with the engine that emits it.
pub fn list() -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\nEvery number this build can produce, and the engine that produces it.\n"
    );
    for engine in shipped::SHIPPED {
        let _ = writeln!(out, "  {}", engine.engine_id);
        let mut descriptors = (engine.metrics)();
        descriptors.sort_by(|a, b| a.metric_id.cmp(&b.metric_id));
        for descriptor in descriptors {
            let _ = writeln!(
                out,
                "    {:<44} {}",
                descriptor.metric_id,
                match descriptor.class {
                    MetricClass::DiffActionable => "diff-actionable",
                    MetricClass::ContextInformational => "context-informational",
                }
            );
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(
        out,
        "  `andon explain <metric-id>` prints the claim behind one of them.\n"
    );
    out
}

/// What `run` produced: the explanation, and anything the caller must show
/// beside it.
///
/// The notice is returned rather than printed because this body is shared with
/// the MCP server, and there `eprintln!` reaches nobody who matters. A tool
/// result is built from the return value alone — subprocess stderr is host-side
/// logging and never becomes part of what the model reads. So a refusal written
/// to stderr closed the gap for the CLI reader and left it open for the agent,
/// which is the surface this project calls its primary consumer.
pub struct Explained {
    /// The rendered explanation.
    pub answer: String,
    /// Present when a record existed and could not be used. The explanation is
    /// still complete; what it lacks is the measurement it would have cited.
    pub notice: Option<String>,
}

/// The whole `explain` question for one query, from a repository path to the
/// rendered answer: load the policy in force, load the registry under it,
/// resolve the query to a subject, and explain it beside the last measurement.
///
/// One function rather than a recipe in each caller, because the CLI and the
/// MCP server both answer this question and two assemblies of the same steps
/// is how two surfaces drift. Outside a repository the conservative defaults
/// apply — which is what the binary would have measured under anyway — but a
/// `.andon.toml` that exists and cannot be read is surfaced rather than
/// defaulted, the same rule `measure` applies.
pub fn run(
    repo: &std::path::Path,
    registry_dir: Option<&std::path::Path>,
    query: &str,
) -> Result<Explained, String> {
    let git = andon_core::git::Git::open(repo).ok();
    let policy = match &git {
        Some(git) => measure::load_policy(git, &measure::PolicySource::Worktree)
            .map_err(|e| e.to_string())?,
        None => Policy::default(),
    };
    let as_of = Date::today_utc().map_err(|_| "the system clock could not be read".to_string())?;
    let registry =
        measure::load_registry(registry_dir, &policy, as_of).map_err(|e| e.to_string())?;
    let subject = subject_of(query)?;
    // `explain` works without a record, and a fresh checkout has none — that
    // absence stays silent. A record that EXISTS and refuses to read is a
    // different fact: swallowing it into the same `None` would render the page
    // as if nothing were recorded, which is exactly the invisible-refusal shape
    // `verify_seals` exists to prevent. The reader is told and the explanation
    // still prints.
    //
    // On stderr rather than stdout because this body is shared with the MCP
    // server's `explain_finding`, where stdout carries the protocol and a stray
    // line on it is a transport error rather than a message.
    let mut notice = None;
    let record = git
        .as_ref()
        .and_then(|git| match crate::store::read_last(git) {
            Ok(record) => Some(record),
            Err(why) => {
                if crate::store::last_record_path(git).exists() {
                    notice = Some(format!(
                        "the last measurement exists and was not used: {why}"
                    ));
                }
                None
            }
        });
    let answer = explain(&subject, &policy, &registry, record.as_ref())?;
    Ok(Explained { answer, notice })
}

/// Explain a subject against the registry this binary compiles in.
pub fn explain(
    subject: &Subject,
    policy: &Policy,
    registry: &andon_core::payload::registry_load::LoadedRegistry,
    record: Option<&MeasurementRecord>,
) -> Result<String, String> {
    let mut out = String::new();
    let claim_id = match subject {
        Subject::Claim(id) => id.clone(),
        Subject::Metric(metric_id) => {
            let (engine, descriptor) = shipped::engine_for_metric(metric_id)
                .ok_or_else(|| format!("no engine declares '{metric_id}'"))?;
            metric_header(&mut out, metric_id, engine.engine_id, &descriptor, policy);
            ladder(&mut out, metric_id);
            descriptor.claim_id
        }
    };

    let resolved = registry
        .registry
        .claims
        .get(&claim_id)
        .ok_or_else(|| format!("the registry does not declare claim '{claim_id}'"))?;
    claim(&mut out, resolved, registry.as_of);

    if let Subject::Metric(metric_id) = subject {
        let (_, descriptor) = shipped::engine_for_metric(metric_id).expect("resolved above");
        reach(
            &mut out,
            resolved.claim.tier,
            descriptor.class,
            policy,
            shipped::ladder_for(metric_id),
        );
    }

    if let (Subject::Metric(metric_id), Some(record)) = (subject, record) {
        observed(&mut out, metric_id, record);
    }
    Ok(out)
}

fn metric_header(
    out: &mut String,
    metric_id: &str,
    engine_id: &str,
    descriptor: &andon_core::engine::MetricDescriptor,
    policy: &Policy,
) {
    let _ = writeln!(out, "\n  {metric_id}");
    let _ = writeln!(out, "  {}", "─".repeat(metric_id.len().max(24)));
    let _ = writeln!(out, "  emitted by      {engine_id}");
    let _ = writeln!(
        out,
        "  class           {}",
        match descriptor.class {
            MetricClass::DiffActionable =>
                "diff-actionable — an agent can fix this inside its own change, so policy may \
                 let it stop the line",
            MetricClass::ContextInformational =>
                "context-informational — true and worth knowing, about the surrounding code. \
                 It never stops the line and never advances the iteration counter.",
        }
    );
    let _ = writeln!(
        out,
        "  compare set     {}",
        if descriptor.deterministic {
            "yes — seed-free and byte-reproducible, so the CI verifier recomputes it and \
             compares digests"
        } else {
            "no — seeded or timing-dependent, so it is CI-authoritative only and never \
             digest-compared"
        }
    );
    let _ = writeln!(
        out,
        "  policy in force MED+ is admitted for tiers {}{}",
        policy
            .severity
            .med_plus_tiers
            .iter()
            .map(|t| format!("{t:?}"))
            .collect::<Vec<_>>()
            .join(", "),
        if policy.severity.med_plus_requires_diff_actionable {
            ", and only on diff-actionable metrics"
        } else {
            ""
        }
    );
}

fn ladder(out: &mut String, metric_id: &str) {
    let Some(ladder) = shipped::ladder_for(metric_id) else {
        return;
    };
    let _ = writeln!(out, "\n  How its numbers become a severity");
    match ladder {
        SeverityLadder::NoOpinion => {
            let _ = writeln!(
                out,
                "    This metric declines to rank itself. It reports a number and takes no view \
                 on how bad that number is — which is a declaration, not an omission."
            );
        }
        SeverityLadder::PerResult => {
            let _ = writeln!(
                out,
                "    Ranked per result by the detector that produced it, rather than by a \
                 threshold on the value."
            );
        }
        SeverityLadder::Flag(severity) => {
            let _ = writeln!(
                out,
                "    A flag: {:?} when it fires, and nothing when it does not.",
                severity
            );
        }
        SeverityLadder::Thresholds(rungs) => {
            let _ = writeln!(out, "    below every rung              Info");
            for rung in rungs {
                let _ = writeln!(
                    out,
                    "    at or above {:<21} {:?}",
                    threshold_label(&rung.at),
                    rung.severity
                );
            }
        }
    }
    let _ = writeln!(
        out,
        "    A number computed over a file the parser could not fully read is capped below the \
         blocking band whatever this ladder says."
    );
}

fn threshold_label(threshold: &Threshold) -> String {
    match threshold {
        Threshold::Count(n) => n.to_string(),
        Threshold::Integer(n) => n.to_string(),
        Threshold::Ratio(r) => format!("{r}"),
        Threshold::Millis(ms) => format!("{ms} ms"),
    }
}

fn claim(out: &mut String, resolved: &ResolvedClaim, as_of: Date) {
    let claim = &resolved.claim;
    let _ = writeln!(out, "\n  The claim this number stands on");
    let _ = writeln!(out, "    id            {}", claim.claim_id);
    let _ = writeln!(
        out,
        "    tuple         {} at version {} · {} · predicts {}",
        claim.implementation, claim.implementation_version, claim.language, claim.outcome
    );
    let _ = writeln!(
        out,
        "    tier          {:?} — {}",
        claim.tier,
        tier_meaning(claim.tier)
    );
    let _ = writeln!(out, "    citation      {}", claim.citation);
    if let Some(reference) = &claim.citation_ref {
        let _ = writeln!(out, "                  {reference}");
    }
    let _ = writeln!(out, "    population    {}", claim.population);
    let _ = writeln!(out, "    effect        {}", claim.effect);
    let _ = writeln!(out, "    owner         {}", claim.owner);
    let _ = writeln!(
        out,
        "    re-reviewed   {}{}",
        claim.expiry,
        if resolved.stale {
            format!(
                " — STALE as of {as_of}. Past its re-review date, and shown as stale \
                     everywhere it is cited until somebody checks it again."
            )
        } else {
            String::new()
        }
    );

    let _ = writeln!(out, "\n  What this number does NOT tell you");
    for line in &claim.does_not_predict {
        let _ = writeln!(out, "    · {line}");
    }
}

/// The strongest severity a finding on this metric could reach, and why.
///
/// # Computed, never described
///
/// The tempting version of this section is a sentence per policy field: *"tier A
/// is admitted to the MED+ band, so this can stop the line"*. That sentence is
/// wrong for every context-informational metric in the tool, because a second
/// ceiling it does not mention caps them below the band — and a reader acting on
/// it would be told a tier-A churn count could block, which it cannot.
///
/// So the answer comes from [`severity::ceiling`], the one implementation of the
/// composition, asked about a result carrying this metric's declared tier, class
/// and a complete reading. Nothing here restates a rule; a ceiling added to that
/// function shows up in this output without an edit.
fn reach(
    out: &mut String,
    tier: EvidenceTier,
    class: MetricClass,
    policy: &Policy,
    ladder: Option<SeverityLadder>,
) {
    let ceiling = severity::ceiling(&query_result(tier, class), &policy.severity);
    let declared = ladder.map(|l| l.strongest());

    let _ = writeln!(out, "\n  The strongest this finding can be");
    if let Some(declared) = declared {
        let _ = writeln!(
            out,
            "    its own ladder reaches at most        {declared:?}"
        );
    }
    let _ = writeln!(out, "    the policy in force caps it at       {ceiling:?}");
    // Both halves, because either can be the binding one and a reader needs to
    // know which. A ladder that never reaches Medium is not the same situation
    // as a policy that will not admit one that does.
    let reachable = declared.map(|d| d.min(ceiling)).unwrap_or(ceiling);
    let _ = writeln!(
        out,
        "    so in this repository, at most       {reachable:?}{}",
        if reachable.is_med_plus() {
            " — this can stop the line"
        } else {
            " — this can advise; it cannot stop the line"
        }
    );
    if !policy.severity.med_plus_tiers.contains(&tier) {
        let _ = writeln!(
            out,
            "      because tier {tier:?} is not among the tiers this policy admits to the \
             blocking band"
        );
    }
    if tier == EvidenceTier::C {
        let _ = writeln!(
            out,
            "      because C-tier evidence is capped at {:?} by policy, whatever the ladder says",
            policy.severity.max_severity_for_c_tier
        );
    }
    if policy.severity.med_plus_requires_diff_actionable
        && class == MetricClass::ContextInformational
    {
        let _ = writeln!(
            out,
            "      because this metric is context-informational and this policy admits only \
             diff-actionable findings to the blocking band"
        );
    }
    let _ = writeln!(
        out,
        "      and a number computed over input the parser could not fully read is capped \
         below the band whatever else is true"
    );
}

/// A result carrying nothing but the three facts [`severity::ceiling`] reads.
///
/// A query object, not a measurement. It never enters a payload, it is never
/// sealed, and it names no engine — `payload::prepare` would refuse it on the
/// first count and `run_engine` on the second. It exists so that this surface
/// asks the real function instead of restating its rules, which is the whole
/// argument of DEFERRED-APPROVALS E21.
fn query_result(tier: EvidenceTier, class: MetricClass) -> MeasurementResult {
    use andon_core::schema::enums::{Completeness, EngineClass, EngineFamily};
    use andon_core::schema::payload::{
        CacheState, EvidenceRef, Freshness, MetricValue, ResultScope, ScopeKind,
    };
    MeasurementResult {
        metric_id: String::new(),
        claim_id: String::new(),
        engine_id: String::new(),
        family: EngineFamily::Static,
        engine_class: EngineClass::StaticSafe,
        metric_class: class,
        scope: ResultScope {
            kind: ScopeKind::Change,
            path: None,
            blob_oid: None,
            symbol: None,
            line_span: None,
        },
        value: MetricValue::Count(0),
        delta: None,
        // The question is what policy allows at full strength, so the ladder's
        // own answer is supplied separately and this stands at the top.
        severity: Severity::Critical,
        // A complete reading, because the completeness ceiling is reported as a
        // standing caveat rather than folded into the headline number.
        completeness: Completeness::Complete,
        measurement_regime: andon_core::schema::regime::MeasurementRegime::Static {
            engine_version: String::new(),
            spec_revision: String::new(),
            grammars: Default::default(),
        },
        evidence: EvidenceRef {
            claim_id: String::new(),
            tier,
            citation: String::new(),
            does_not_predict: Vec::new(),
            stale: false,
        },
        deterministic: true,
        digest: String::new(),
        freshness: Freshness {
            measured_at: String::new(),
            duration_ms: 0,
            lane: andon_core::schema::enums::Lane::Fast,
            cache: CacheState::Cold,
        },
    }
}

fn tier_meaning(tier: EvidenceTier) -> &'static str {
    match tier {
        EvidenceTier::A => "validated against outcomes at scale",
        EvidenceTier::B => "published validation, narrower population or weaker linkage",
        EvidenceTier::C => "weak or contested on its own",
        EvidenceTier::D => "critiqued; not to be used as a headline",
        EvidenceTier::N => "novel and unvalidated — motivated by evidence, not yet supported by it",
    }
}

fn observed(out: &mut String, metric_id: &str, record: &MeasurementRecord) {
    let observed: Vec<_> = record
        .results
        .iter()
        .filter(|r| r.metric_id == metric_id)
        .collect();
    if observed.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "\n  In the last measurement of this checkout ({})",
        crate::resolve::change_line(&record.compare_context)
    );
    for result in observed {
        let _ = writeln!(
            out,
            "    {:<7} {:<44} {}",
            crate::render::severity_word(result.severity),
            measure::scope_label(result),
            measure::value_label(&result.value)
        );
        if result.completeness != andon_core::schema::enums::Completeness::Complete {
            let _ = writeln!(
                out,
                "            {}: {}",
                format!("{:?}", result.completeness).to_lowercase(),
                crate::render::completeness_note(result.completeness)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> andon_core::payload::registry_load::LoadedRegistry {
        let policy = Policy::default();
        measure::load_registry(None, &policy, Date::today_utc().expect("a clock"))
            .expect("the compiled-in registry loads")
    }

    #[test]
    fn every_shipped_metric_can_be_explained() {
        // The claim this subcommand makes, checked over the whole shipped set
        // rather than over one example: there is no number this tool can produce
        // that it cannot account for.
        let policy = Policy::default();
        let registry = registry();
        for metric_id in shipped::all_metric_ids() {
            let subject = subject_of(&metric_id)
                .unwrap_or_else(|e| panic!("{metric_id} does not resolve: {e}"));
            let text = explain(&subject, &policy, &registry, None)
                .unwrap_or_else(|e| panic!("{metric_id}: {e}"));
            assert!(text.contains(&metric_id), "{metric_id}");
        }
    }

    #[test]
    fn every_explanation_states_what_the_number_does_not_predict() {
        // The honesty field is the reason this command exists. A metric whose
        // explanation reached a reader without it would be the tool doing the
        // thing it was built to stop.
        let policy = Policy::default();
        let registry = registry();
        for metric_id in shipped::all_metric_ids() {
            let subject = subject_of(&metric_id).expect("resolves");
            let text = explain(&subject, &policy, &registry, None).expect("explains");
            assert!(
                text.contains("does NOT tell you"),
                "{metric_id} was explained without its does-not-predict lines"
            );
            let (_, descriptor) = shipped::engine_for_metric(&metric_id).expect("declared");
            let claim = &registry.registry.claims[&descriptor.claim_id].claim;
            assert!(!claim.does_not_predict.is_empty(), "{metric_id}");
            for line in &claim.does_not_predict {
                assert!(text.contains(line.as_str()), "{metric_id}: {line}");
            }
        }
    }

    #[test]
    fn an_unknown_query_names_what_is_available_rather_than_failing_blankly() {
        let err = subject_of("no-such-metric").expect_err("refuses");
        assert!(err.contains("andon explain --list"), "{err}");
    }

    #[test]
    fn a_substring_that_matches_exactly_one_metric_resolves_to_it() {
        let subject = subject_of("unmeasured-files").expect("resolves");
        assert!(matches!(subject, Subject::Metric(id) if id == "static.unmeasured-files"));
    }
}
