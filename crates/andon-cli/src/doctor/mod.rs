//! `andon doctor` — the self-report bundle a false-positive issue is filed
//! with (PLAN P10a-adoption; round-1 5.2, the S6 disconnection replacement).
//!
//! # What it is for
//!
//! The S6 false-positive budget is measured on one repository — this one —
//! through `andon ledger fp-window`, over a window whose every record accrues
//! from one machine. After the public flip the population that matters is
//! strangers' repositories, and none of it is observable from here: the tool
//! stops the line on someone's honest change, and the only signal that ever
//! reaches a maintainer is an issue. An issue that says "it blocked me" cannot
//! be triaged. The one that can carries the version, the rule pack, the regime
//! each engine measured under, the policy in force and how it differs from the
//! defaults, and the verdict with its reasons and the locations that drove it.
//! This command writes that, in one file, so the person filing the issue does
//! not have to know which of those things matter.
//!
//! # The design constraint is redaction
//!
//! The bundle goes into a **public** issue, so what it must not contain is
//! the property it is built around. It carries no source, no file contents, no
//! absolute path, no path beyond the repository's basename, no author, no
//! commit message. Every field is composed from values the tool computed —
//! versions, hashes, enum spellings, counts, metric ids — never from anything
//! read out of the working tree.
//!
//! One call is hard, and it is made rather than avoided: a finding's location.
//! A false-positive report without `src/orders.ts:orderTotal` is a report about
//! nothing — the maintainer cannot tell a rung set too low from a metric that
//! misread a construct without knowing which construct — so the bundle carries
//! each finding's **repository-relative path, symbol and line span**, and
//! never the bytes at that location. The path is git's own spelling of it
//! (forward slashes, relative to the root), not a filesystem path. The reader
//! learns that a function named `classify` in `src.ts` reached a rung, and
//! nothing about what `classify` does.
//!
//! # Derived, never restated
//!
//! Nothing here is a second copy of a fact the workspace already states:
//!
//! - The measurement regimes are read off the last record's results, exactly
//!   as `fp-window` reads them — [`andon_ledger::stats::regime_family`] and
//!   [`andon_ledger::stats::regime_label`] over every result, absences
//!   included, deduplicated per record. With no record there is nothing to
//!   read, and the list is empty rather than a guess at what a measurement
//!   would have stamped. Composing a regime here from the engines' constants
//!   would be a hand-written twin of each engine's `regime()`, correct on the
//!   day it was written and silently wrong the first time one moved.
//! - The policy in force and its diff against the conservative defaults go
//!   through the path `fp-window` uses: [`crate::measure::load_policy`], which
//!   is `policy_change::resolve` with the file read attached, and
//!   [`andon_core::verdict::policy_change::evaluate`] against
//!   `Policy::default()`. The deltas are carried as `describe()` spells them,
//!   so the bundle and the window report cannot disagree about one edit.
//! - The rule pack is [`andon_engine_tamper::syntax::RULE_PACK_VERSION`]
//!   itself; the version is this package's; the git version is the one
//!   [`Git::open`] probed.
//! - `truncated` and `total_reasons` are the agent profile's own fields, from
//!   [`build_agent_profile`] under the `[agent]` budget in force — the view an
//!   agent would have been handed, so a report that says "the agent saw no
//!   reason" can be checked against whether one was cut.
//!
//! # The scrub is a guard, not the mechanism
//!
//! Two channels carry text authored somewhere else: policy values (a test
//! command, an exclusion pattern) and engine failure reasons inside a verdict's
//! message. Either could, in principle, spell an absolute path. So after the
//! bundle is composed, every string in it is scrubbed of the roots this process
//! knows — the repository, its git directory, the current directory, the
//! temporary directory, the home directory, in both separator forms, longest
//! first — and the number of replacements is written into the bundle as
//! `redactions`. The count is the observable: a bundle that says `2` tells its
//! reader that something was cut, and a scrub that did its work in silence
//! would be exactly the kind of handling this project treats as a failure.
//! Construction is what keeps the bundle clean; the scrub is what catches a
//! channel construction did not foresee.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use andon_core::git::Git;
use andon_core::policy::Policy;
use andon_core::schema::agent_profile::{build_agent_profile, AgentProfileBounds};
use andon_core::schema::enums::{Attestation, Completeness, Severity, Verdict};
use andon_core::schema::payload::{
    HeadKind, IterationState, LineSpan, MeasurementRecord, MetricValue, ScopeKind,
};
use andon_ledger::stats::{regime_family, regime_label};

use crate::args::Flags;
use crate::{measure, render, store};

/// The file written into the current directory.
pub const BUNDLE_FILE: &str = "andon-doctor.json";

/// The bundle's own schema version, so a reader can tell which shape it holds.
pub const BUNDLE_SCHEMA_VERSION: u32 = 1;

/// The redaction rule, stated inside the bundle for the person reading the
/// issue — who has the file and not this module.
const REDACTION_RULE: &str = "This bundle carries versions, hashes, regime labels, policy \
                              deltas, verdict reasons, and each finding's repository-relative \
                              path, symbol and line span. It carries no source, no file \
                              contents, no absolute paths, no authors and no commit messages.";

const DOCTOR_USAGE: &str = "\
andon doctor [--repo <PATH>]

  Writes andon-doctor.json into the current directory: the self-report bundle to
  paste into a false-positive issue. It carries this build's version and rule
  pack, the OS and git version, the measurement regime of every engine in the
  last measurement, the policy hash and its diff against the conservative
  defaults, and the last measurement's verdict, reasons and finding locations.

  It carries NO source, file contents, absolute paths, authors or commit
  messages. Finding locations are the one deliberate inclusion — the
  repository-relative path, the symbol and the line span, never the code there
  — because a false-positive report without them cannot be triaged.

  Nothing is measured. With no measurement taken in this checkout yet, the
  bundle still writes, with `last_measurement: null`.";

/// `andon doctor`: write the bundle, and return the one line for stdout.
///
/// Returned rather than printed, so the binary writes it through its one
/// fallible stdout writer and a closed pipe is a quiet exit rather than a
/// panic (`main.rs`).
pub fn cmd_doctor(flags: &Flags) -> Result<String, String> {
    if flags.on("help") {
        return Ok(DOCTOR_USAGE.to_string());
    }
    flags.reject_unknown(&["repo"])?;
    let git = Git::open(&flags.path("repo", ".")).map_err(|e| e.to_string())?;
    let bundle = bundle(&git)?;
    let mut text = serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?;
    text.push('\n');
    std::fs::write(BUNDLE_FILE, text).map_err(|e| format!("{BUNDLE_FILE}: {e}"))?;
    // The file's name and not its path: the line goes to a terminal whose
    // current directory the person already knows, and printing the absolute
    // path here would put on the screen the one thing the file leaves out.
    Ok(format!(
        "  wrote {BUNDLE_FILE} — paste it into the false-positive issue. It names files and \
         symbols, never code."
    ))
}

/// The bundle for one checkout, composed and then scrubbed.
///
/// Returned as a JSON value rather than the typed [`Bundle`] because the scrub
/// runs over the serialized strings — the shape every channel of free text
/// ends up in — and the count it produces is written back into the document.
pub fn bundle(git: &Git) -> Result<Value, String> {
    // The policy in force now, through `fp-window`'s own reader: `resolve`
    // with the file read attached.
    let in_force =
        measure::load_policy(git, &measure::PolicySource::Worktree).map_err(|e| e.to_string())?;
    let diff = andon_core::verdict::policy_change::evaluate(&Policy::default(), &in_force, None);

    // Absent is an answer; unreadable is not. A record that exists and does
    // not read back — a tampered seal, a truncated file — must not become a
    // quiet `null`, because the person would then file an issue about a
    // measurement the bundle says never happened.
    let last = if store::last_record_path(git).exists() {
        Some(store::read_last(git)?)
    } else {
        None
    };

    let facts = git.facts();
    let typed = Bundle {
        schema_version: BUNDLE_SCHEMA_VERSION,
        bundle: "andon-doctor",
        redaction: REDACTION_RULE,
        redactions: 0,
        andon_version: env!("CARGO_PKG_VERSION"),
        rule_pack_version: andon_engine_tamper::syntax::RULE_PACK_VERSION,
        platform: Platform {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        },
        git_version: facts.version.clone(),
        repository: basename(&facts.toplevel),
        policy: PolicySection {
            hash: in_force.policy_hash().map_err(|e| e.to_string())?,
            diff_vs_defaults: diff.deltas.iter().map(|d| d.describe()).collect(),
            loosenings: diff.loosenings().count(),
        },
        regimes: last.as_ref().map(regimes_of).unwrap_or_default(),
        last_measurement: last.as_ref().map(|record| summarize(record, &in_force)),
    };

    let mut value = serde_json::to_value(&typed).map_err(|e| e.to_string())?;
    let roots = known_roots(git);
    let redactions = scrub(&mut value, &roots);
    value["redactions"] = Value::from(redactions);
    Ok(value)
}

/// The whole bundle. Every field is documented by what makes it safe to carry.
#[derive(Debug, Serialize)]
pub struct Bundle {
    /// [`BUNDLE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// What this document is, for a reader who finds it detached from the
    /// command that wrote it.
    pub bundle: &'static str,
    /// [`REDACTION_RULE`], so the reader of the issue can see the rule the file
    /// was built under without reading this module.
    pub redaction: &'static str,
    /// How many known-root path replacements the scrub made. Zero is the
    /// expected value; anything else says a channel carried a path and names
    /// the fact without naming the path.
    pub redactions: usize,
    /// This package's version — the one `andon --version` prints.
    pub andon_version: &'static str,
    /// The tamper engine's rule pack, from the constant the engine stamps into
    /// its own regime.
    pub rule_pack_version: &'static str,
    /// OS and architecture, from the standard library's constants.
    pub platform: Platform,
    /// `git --version` as [`Git::open`] probed it.
    pub git_version: String,
    /// The repository's basename — the last component of its root, never more.
    pub repository: String,
    /// The policy in force now, and how it differs from the defaults.
    pub policy: PolicySection,
    /// Every distinct measurement regime the last record's results carry, one
    /// per engine family that measured. Empty with no record.
    pub regimes: Vec<Regime>,
    /// The last measurement, or `null` when none has been taken here.
    pub last_measurement: Option<LastMeasurement>,
}

/// Where this ran.
#[derive(Debug, Serialize)]
pub struct Platform {
    /// `std::env::consts::OS`.
    pub os: &'static str,
    /// `std::env::consts::ARCH`.
    pub arch: &'static str,
}

/// The policy in force, as `fp-window` reports it.
#[derive(Debug, Serialize)]
pub struct PolicySection {
    /// Digest of the policy in force — what a fresh measurement would stamp.
    /// Compare with `last_measurement.policy_hash` to see whether the policy
    /// moved since the record was written.
    pub hash: String,
    /// Each field that differs from the conservative defaults, spelled as
    /// [`andon_core::verdict::policy_change::PolicyDelta::describe`] spells
    /// it. Empty means the defaults are in force.
    pub diff_vs_defaults: Vec<String>,
    /// How many of those deltas loosen a gate.
    pub loosenings: usize,
}

/// One measurement regime, labeled the way the ledger labels it.
#[derive(Debug, Serialize)]
pub struct Regime {
    /// The engine family, in its wire spelling — the regime's own answer,
    /// not a word parsed out of the label.
    pub family: String,
    /// [`regime_label`] of the regime: every field of its variant, one line.
    pub label: String,
}

/// The last measurement, reduced to what a triage reads and nothing the
/// working tree wrote.
#[derive(Debug, Serialize)]
pub struct LastMeasurement {
    /// The binary that wrote the record. May be older than this one.
    pub measured_by: MeasuredBy,
    /// What the head was: a commit, or an uncommitted snapshot.
    pub head_kind: HeadKind,
    /// How the base was chosen — a fixed vocabulary (`merge-base`,
    /// `explicit`, `worktree`, ...), never a ref the caller typed.
    pub base_resolution: String,
    /// Whether everything set out to be measured was.
    pub completeness: Completeness,
    /// What, if anything, has checked this record.
    pub attestation: Attestation,
    /// The policy that governed the record.
    pub policy_hash: String,
    /// The categorical outcome.
    pub verdict: Verdict,
    /// True when the stored verdict contradicts the record's own results.
    pub verdict_invalid: bool,
    /// Why, one entry per cause: the stable code, its severity, its message.
    pub reasons: Vec<Reason>,
    /// How many findings the record holds — the same count as `findings.len()`.
    pub finding_count: usize,
    /// The findings, worst first: metric, severity, value, and the location
    /// — the one deliberate inclusion, see the module docs.
    pub findings: Vec<Finding>,
    /// Changed paths nothing could read. A count: the paths are in `andon
    /// report`, and a number carries what the reader needs.
    pub unread_paths: usize,
    /// Changed paths withheld by `[self_measure] excluded_paths`. A count, for
    /// the same reason.
    pub withheld_paths: usize,
    /// Where the change sits against the iteration cap.
    pub iteration: IterationState,
    /// The view an agent would have been handed, under the `[agent]` budget in
    /// force now.
    pub agent_profile: AgentView,
}

/// The tool identity a record carries.
#[derive(Debug, Serialize)]
pub struct MeasuredBy {
    /// Release version.
    pub version: String,
    /// Commit the binary was built from.
    pub build_oid: String,
    /// Whether that binary was an attested release.
    pub attested_release: bool,
}

/// One verdict reason. `metric_ids` is not projected: the metrics it would
/// name are the findings below.
#[derive(Debug, Serialize)]
pub struct Reason {
    /// Stable machine code.
    pub code: String,
    /// How serious.
    pub severity: Severity,
    /// The explanation, as the record spells it.
    pub message: String,
}

/// One finding: what fired, how hard, on what, and where.
#[derive(Debug, Serialize)]
pub struct Finding {
    /// Stable metric id.
    pub metric_id: String,
    /// Post-policy severity — what actually fired at the operator.
    pub severity: Severity,
    /// The number itself. A `text` value in this build is an engine's own
    /// sentence — a fixed absence reason, or the suite outcome, which is a
    /// template over integers (`exited {code} in {duration_ms} ms`) — never
    /// content read from the tree; the scrub covers a producer that changes
    /// that.
    pub value: MetricValue,
    /// Granularity.
    pub scope: ScopeKind,
    /// Repository-relative path in git's spelling, when file- or
    /// function-scoped.
    pub path: Option<String>,
    /// Function or class name, when function-scoped.
    pub symbol: Option<String>,
    /// Line range, when line-scoped.
    pub line_span: Option<LineSpan>,
}

/// What the agent profile would have said about this record.
#[derive(Debug, Serialize)]
pub struct AgentView {
    /// True when anything was cut to fit the budget.
    pub truncated: bool,
    /// Reasons the full record holds.
    pub total_reasons: u32,
    /// Findings the full record holds.
    pub total_findings: u32,
    /// Reasons that survived the budget.
    pub reasons_shown: usize,
    /// Findings that survived the budget.
    pub findings_shown: usize,
}

/// The regimes a record was measured under — `fp-window`'s own loop: every
/// result, absences included, deduplicated per record.
fn regimes_of(record: &MeasurementRecord) -> Vec<Regime> {
    let seen: BTreeSet<(String, String)> = record
        .results
        .iter()
        .map(|r| {
            (
                regime_family(&r.measurement_regime),
                regime_label(&r.measurement_regime),
            )
        })
        .collect();
    seen.into_iter()
        .map(|(family, label)| Regime { family, label })
        .collect()
}

/// Reduce a record to the triage view.
fn summarize(record: &MeasurementRecord, in_force: &Policy) -> LastMeasurement {
    let bounds = AgentProfileBounds::from_token_budget(
        in_force.agent.profile_token_budget,
        in_force.agent.bytes_per_token,
    );
    let profile = build_agent_profile(record, &bounds);
    let findings: Vec<Finding> = render::findings(record)
        .into_iter()
        .map(|r| Finding {
            metric_id: r.metric_id.clone(),
            severity: r.severity,
            value: r.value.clone(),
            scope: r.scope.kind,
            path: r.scope.path.clone(),
            symbol: r.scope.symbol.clone(),
            line_span: r.scope.line_span,
        })
        .collect();
    LastMeasurement {
        measured_by: MeasuredBy {
            version: record.tool.version.clone(),
            build_oid: record.tool.build_oid.clone(),
            attested_release: record.tool.attested_release,
        },
        head_kind: record.compare_context.head_kind,
        base_resolution: record.compare_context.base_resolution.clone(),
        completeness: record.completeness,
        attestation: record.attestation.value,
        policy_hash: record.policy_hash.clone(),
        verdict: record.verdict.verdict,
        verdict_invalid: andon_core::verdict::stored_verdict_is_contradicted(record),
        reasons: record
            .verdict
            .reasons
            .iter()
            .map(|r| Reason {
                code: r.code.clone(),
                severity: r.severity,
                message: r.message.clone(),
            })
            .collect(),
        finding_count: findings.len(),
        findings,
        unread_paths: record.unreadable_paths.len(),
        withheld_paths: record
            .self_measure
            .as_ref()
            .map_or(0, |p| p.excluded_paths.len()),
        iteration: record.verdict.iteration,
        agent_profile: AgentView {
            truncated: profile.truncated,
            total_reasons: profile.total_reasons,
            total_findings: profile.total_findings,
            reasons_shown: profile.reasons.len(),
            findings_shown: profile.findings.len(),
        },
    }
}

/// The last path component, or the whole path when it has none.
fn basename(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// One absolute root this process knows, and the token that stands in for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    /// The path, as the source that knew it spelled it.
    pub path: String,
    /// What replaces it.
    pub token: &'static str,
}

/// The roots the scrub replaces: the repository and its git directory, the
/// current directory, the temporary directory, the home directory.
///
/// A filesystem root (`/`, `C:\`) is never a scrub root: replacing it would
/// eat the first character of every absolute path and leave the rest, which
/// is a redaction that redacts nothing and breaks the count's meaning.
fn known_roots(git: &Git) -> Vec<Root> {
    let facts = git.facts();
    let mut roots = vec![
        Root {
            path: facts.toplevel.display().to_string(),
            token: "<repo>",
        },
        Root {
            path: facts.git_dir.display().to_string(),
            token: "<git-dir>",
        },
    ];
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(Root {
            path: cwd.display().to_string(),
            token: "<cwd>",
        });
    }
    roots.push(Root {
        path: std::env::temp_dir().display().to_string(),
        token: "<temp>",
    });
    // Both, not one or the other: a Windows shell sets `USERPROFILE`, a POSIX
    // one sets `HOME`, and Git Bash on Windows sets both — sometimes in two
    // spellings. Whichever a policy value or an error message carries has to
    // be a root this scrub knows.
    for name in ["HOME", "USERPROFILE"] {
        if let Some(home) = std::env::var_os(name) {
            roots.push(Root {
                path: home.to_string_lossy().into_owned(),
                token: "<home>",
            });
        }
    }
    roots.retain(|root| is_scrub_root(&root.path));
    roots
}

/// Whether a path may be scrubbed: anything below a filesystem root.
fn is_scrub_root(path: &str) -> bool {
    Path::new(path)
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty())
}

/// Replace every occurrence of every root, in both separator forms, in every
/// string of `value`. Returns how many replacements were made.
///
/// Longest form first, so a root nested inside another (`<repo>` under
/// `<home>`) is replaced by its own token rather than by the outer one plus a
/// tail — `<home>/repo` would still say where the repository lives.
pub fn scrub(value: &mut Value, roots: &[Root]) -> usize {
    let mut forms: Vec<(String, &'static str)> = roots
        .iter()
        .flat_map(|root| {
            let trimmed = root.path.trim_end_matches(['/', '\\']).to_string();
            [
                (trimmed.clone(), root.token),
                (trimmed.replace('\\', "/"), root.token),
                (trimmed.replace('/', "\\"), root.token),
            ]
        })
        .filter(|(form, _)| !form.is_empty())
        .collect();
    forms.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
    forms.dedup();
    scrub_with(value, &forms)
}

fn scrub_with(value: &mut Value, forms: &[(String, &'static str)]) -> usize {
    match value {
        Value::String(text) => {
            let mut hits = 0;
            for (form, token) in forms {
                let count = text.matches(form.as_str()).count();
                if count > 0 {
                    *text = text.replace(form.as_str(), token);
                    hits += count;
                }
            }
            hits
        }
        Value::Array(items) => items.iter_mut().map(|v| scrub_with(v, forms)).sum(),
        Value::Object(map) => map.values_mut().map(|v| scrub_with(v, forms)).sum(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn roots() -> Vec<Root> {
        vec![
            Root {
                path: "C:\\Users\\someone\\work\\repo".to_string(),
                token: "<repo>",
            },
            Root {
                path: "C:\\Users\\someone".to_string(),
                token: "<home>",
            },
        ]
    }

    /// The guard, exercised against the failure it exists to catch: a path in
    /// either separator form, nested inside a string, anywhere in the tree.
    #[test]
    fn every_known_root_is_replaced_in_both_separator_forms_and_counted() {
        let mut value = json!({
            "policy": {
                "diff": ["sandbox.test_command: null -> C:/Users/someone/work/repo/run.sh (neither)"]
            },
            "reasons": [{ "message": "could not read C:\\Users\\someone\\work\\repo\\src\\a.ts" }],
            "count": 3,
        });
        let hits = scrub(&mut value, &roots());
        assert_eq!(hits, 2);
        assert_eq!(
            value["policy"]["diff"][0],
            "sandbox.test_command: null -> <repo>/run.sh (neither)"
        );
        assert_eq!(
            value["reasons"][0]["message"],
            "could not read <repo>\\src\\a.ts"
        );
    }

    /// A root nested in another is replaced by its own token, never by the
    /// outer token plus a tail that still says where it lives.
    #[test]
    fn the_longest_root_wins_over_the_one_it_sits_inside() {
        let mut value = json!("C:\\Users\\someone\\work\\repo and C:\\Users\\someone\\other");
        let hits = scrub(&mut value, &roots());
        assert_eq!(hits, 2);
        assert_eq!(value, "<repo> and <home>\\other");
    }

    /// A string with nothing to redact is left alone and counts nothing.
    #[test]
    fn a_clean_bundle_reports_zero_redactions() {
        let mut value = json!({ "path": "src/orders.ts", "symbol": "orderTotal" });
        assert_eq!(scrub(&mut value, &roots()), 0);
        assert_eq!(value["path"], "src/orders.ts");
    }

    /// A filesystem root never becomes a scrub root; anything below one does.
    #[test]
    fn a_filesystem_root_is_not_a_scrub_root() {
        assert!(!is_scrub_root("/"));
        assert!(!is_scrub_root(""));
        assert!(is_scrub_root("/tmp"));
        assert!(is_scrub_root("C:\\Users\\someone"));
        if cfg!(windows) {
            assert!(!is_scrub_root("C:\\"));
        }
    }
}
