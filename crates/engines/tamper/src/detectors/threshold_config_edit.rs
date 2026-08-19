//! Quality thresholds loosened inside the change being measured.
//!
//! # This one is conditional, and the condition is not the file it found
//!
//! PLAN round-1 B6: a tool that blocks on policy edits has made legitimate
//! policy evolution impossible, and a project that cannot change its own
//! thresholds will change tools instead. So this is the one of the seven whose
//! firing is not an unconditional stop, and P5a's verdict assembly is where the
//! "loosening without a ledgered justification" rule lives.
//!
//! **It is not, however, advisory.** That was the first version of the rule and
//! it was wrong in a way this detector is uniquely placed to cause: the
//! exemption was keyed on the signal's enum variant, so *every* firing was a
//! note rather than a stop — while the justification route it was nominally
//! handed to parses `.andon.toml` and nothing else. This detector reads ESLint,
//! tsconfig, mypy, ruff, coverage configuration and a dozen more, so a real
//! loosening in any of them took an exemption with nowhere behind it to be ruled
//! on. Since then a firing stops the line unless a **verified** ledgered
//! justification covers the change, wherever the threshold lived
//! (`andon_core::verdict::severity::signal_stops_the_line`).
//!
//! The reported severity stays `Low`, and that is not a contradiction: blocking
//! is keyed on the flag and never on the severity, for the muzzle reason
//! `andon_core::verdict::severity` sets out. `Low` says how strong this finding
//! is, not whether the line stops.
//!
//! What the detector still owes is an accurate *delta*: which threshold moved,
//! in which direction. A `policy-change` finding that cannot say what changed is
//! not worth reporting.
//!
//! # Only loosening counts
//!
//! Tightening a rule is the opposite of gaming it. `error` -> `warn` fires,
//! `warn` -> `error` does not; a coverage minimum falling fires, one rising does
//! not; `strict: true` -> `false` fires, the reverse does not.

use std::collections::BTreeMap;

use crate::change::ChangeView;
use crate::config;
use crate::detectors::{Detector, Finding, Outcome};
use andon_core::schema::enums::{Severity, TamperSignal};

/// The detector.
pub struct ThresholdConfigEdit;

/// The tools whose configuration carries quality thresholds.
///
/// Stems rather than file names, for the reason [`config::Tool`] sets out: the
/// exact list held `.eslintrc.js` and not `.eslintrc.cjs`, `.eslintrc.yml` and
/// not `.eslintrc.yaml`, three flat-config spellings and not `eslint.config.cjs`,
/// `.golangci.yml` and not `.golangci.toml` — and every one of those returned a
/// confident zero on byte-identical content that fired in its sibling spelling.
const THRESHOLD_TOOLS: &[config::Tool] = &[
    config::Tool::any(".andon"),
    config::Tool::family("tsconfig"),
    config::Tool::any(".eslintrc"),
    config::Tool::family("eslint.config"),
    config::Tool::any("biome"),
    config::Tool::any(".flake8"),
    config::Tool::any("pyproject"),
    config::Tool::any("mypy"),
    config::Tool::any(".mypy"),
    config::Tool::any("ruff"),
    config::Tool::any(".ruff"),
    config::Tool::any("clippy"),
    config::Tool::any(".golangci"),
    config::Tool::family("sonar-project"),
    config::Tool::family("jest.config"),
    config::Tool::family("vitest.config"),
    // Coverage configuration carries thresholds too, and they were reachable in
    // some of these files and not others: `.nycrc.json` dropping `lines` from
    // 90 to 10 is a floor lowered, in a file this detector was not opening.
    config::Tool::any(".coveragerc"),
    config::Tool::any(".nycrc"),
    config::Tool::any(".c8rc"),
    config::Tool::any("codecov"),
    config::Tool::any(".codecov"),
    config::Tool::any("tarpaulin"),
    config::Tool::only("setup", &["cfg"]),
    config::Tool::only("package", &["json"]),
    config::Tool::only("tox", &["ini"]),
];

/// Whether a path is threshold configuration.
pub fn is_threshold_config(path: &str) -> bool {
    config::names_one_of(path, THRESHOLD_TOOLS)
}

/// Severity words, weakest first. A move down this list is a loosening.
const SEVERITY_WORDS: &[&str] = &[
    "off", "none", "ignore", "info", "hint", "warn", "warning", "error", "deny", "forbid",
];

/// Keys whose numeric value is a floor: lowering one loosens.
const FLOOR_KEY_FRAGMENTS: &[&str] = &[
    "threshold",
    "minimum",
    "min_",
    "min-",
    "branches",
    "functions",
    "lines",
    "statements",
    "coverage",
    "fail_under",
    "fail-under",
    "max_severity",
    "budget",
];

/// Keys whose numeric value is a ceiling: raising one loosens.
///
/// `complexity` is here bare rather than as `max-complexity` and
/// `cognitive-complexity`, which it subsumes: ESLint spells the same setting
/// `complexity` with no prefix, and the two prefixed spellings were the whole
/// table, so a `.eslintrc.json` raising `complexity` from 10 to 100 matched
/// nothing and came back `{flag: false, magnitude: 0, completeness: "complete"}`.
/// Matching is `contains`, so one entry covers all three spellings.
///
/// The rest of the `max-*` family — `max-lines`, `max-lines-per-function`,
/// `max-depth`, `max-params`, `max-statements`, `max-nested-callbacks` — is not
/// enumerated here and does not need to be: [`is_ceiling`] reads the prefix,
/// which is the same rationale that put `complexity` in the table, applied to
/// every rule whose own name says the number is a ceiling.
const CEILING_KEY_FRAGMENTS: &[&str] = &[
    "complexity",
    "max_line_length",
    "max-line-length",
    "max_warnings",
    "max-warnings",
    "max_errors",
    "max-errors",
    "iteration_cap",
];

/// Keys spelled `max…` whose number is nonetheless a floor.
///
/// `severity.max_severity_for_c_tier` caps how loud a C-tier metric may be, so
/// lowering it lets *less* through — the opposite direction from every other
/// `max`, and `andon_core::verdict::policy_change::direction_of` is
/// authoritative for it. Named here so the prefix rule in [`is_ceiling`] cannot
/// quietly reverse a policy field's direction.
const MAX_THAT_IS_A_FLOOR: &[&str] = &["max_severity", "max-severity"];

/// Boolean keys where `true` is the strict setting.
const STRICT_WHEN_TRUE: &[&str] = &[
    "strict",
    "strictnullchecks",
    "noimplicitany",
    "noimplicitreturns",
    "nounusedlocals",
    "nounusedparameters",
    "strictfunctiontypes",
    "strictbindcallapply",
    "alwaysstrict",
    "usedefineforclassfields",
    "block_on_tamper",
    "block_on_test_failure",
    // `med_plus_requires_diff_actionable` is deliberately absent, and it used to
    // be here. Read as a key name it looks like a strictness flag; read against
    // what the field does it is the opposite — it *restricts* the MED+ band to
    // metrics the agent can act on, so turning it off lets MORE findings block.
    // Turning it off is an unwise tightening (PREMORTEM A4's uninstall loop),
    // not a gaming move, and firing here put a tamper signal in the payload for
    // an honest edit. `andon_core::verdict::policy_change::direction_of` is
    // authoritative for `.andon.toml`, and
    // `the_detector_and_the_direction_table_agree_about_every_policy_field`
    // fails if this list ever contradicts it again.
    "disallow_untyped_defs",
    "check_untyped_defs",
    "warn_unused_ignores",
    "exclusion_drift_signal",
];

/// Boolean keys where `false` is the strict setting, so turning one **on**
/// loosens.
///
/// The mirror of [`STRICT_WHEN_TRUE`], and it was missing: `skipLibCheck` going
/// `false -> true` stops the compiler checking every declaration file it is
/// handed, which is a real loosening of a real threshold, and it came back
/// `{flag: false, magnitude: 0, completeness: "complete"}` because the only
/// boolean model here read strictness one way round.
const STRICT_WHEN_FALSE: &[&str] = &[
    "skiplibcheck",
    "skipdefaultlibcheck",
    "suppressimplicitanyindexerrors",
    "suppressexcesspropertyerrors",
];

impl Detector for ThresholdConfigEdit {
    fn signal(&self) -> TamperSignal {
        TamperSignal::ThresholdConfigEdit
    }

    fn metric_id(&self) -> &'static str {
        "tamper.threshold-config-edit"
    }

    fn magnitude_metric_id(&self) -> &'static str {
        "tamper.threshold-config-edit.magnitude"
    }

    fn describes(&self) -> &'static str {
        "a quality threshold or strictness flag loosened inside the measured change"
    }

    fn severity_when_fired(&self) -> Severity {
        // The weakest of the seven, and it says how strong the finding is rather
        // than whether the line stops — blocking is keyed on the flag. B6's
        // exemption lives in `severity::signal_stops_the_line` and is
        // conditional on a verified justification, not on this number.
        Severity::Low
    }

    fn run(&self, change: &ChangeView) -> Outcome {
        let mut findings = Vec::new();
        let mut unassessed = Vec::new();
        for file in &change.files {
            if file.content_unchanged() || !is_threshold_config(&file.path) {
                continue;
            }
            let base = settings(file.base_bytes());
            let head = settings(file.head_bytes());
            // A setting that is gone has no value to compare, and the loop below
            // only ever sees keys present on both sides — so removing
            // `noImplicitAny` from a `tsconfig.json` was a change inside this
            // detector's own subject that it reported as nothing at all.
            for (key, (_, base_value)) in &base {
                if head.contains_key(key) {
                    continue;
                }
                if let Some(reason) = deletion(key, base_value) {
                    unassessed.push(Finding::in_file(
                        &file.path,
                        format!("{key}: {base_value} -> absent ({reason})"),
                    ));
                }
            }
            for (key, (line, head_value)) in &head {
                let Some((_, base_value)) = base.get(key) else {
                    continue;
                };
                if base_value == head_value {
                    continue;
                }
                if let Some(reason) = loosening(key, base_value, head_value) {
                    findings.push(Finding::at(
                        &file.path,
                        *line,
                        format!("{key}: {base_value} -> {head_value} ({reason})"),
                    ));
                } else if let Some(reason) = unrankable(key, base_value, head_value) {
                    unassessed.push(Finding::at(
                        &file.path,
                        *line,
                        format!("{key}: {base_value} -> {head_value} ({reason})"),
                    ));
                }
            }
        }
        let count = findings.len() as i64;
        if count > 0 {
            Outcome::fired(count, findings).with_unassessed(unassessed)
        } else {
            Outcome::quiet(0).with_unassessed(unassessed)
        }
    }
}

/// Why a value change is a loosening, or `None` when it is not one.
fn loosening(key: &str, before: &str, after: &str) -> Option<&'static str> {
    let key = key.to_ascii_lowercase();
    let leaf = key.rsplit('.').next().unwrap_or(&key).to_string();
    // Booleans are spelled `true` in TOML and JSON, `True` in an INI file that
    // Python wrote, and `yes` in some YAML. Comparing them as written meant
    // `disallow_untyped_defs = True -> False` in mypy.ini read as an ordinary
    // string edit; the corpus caught it.
    let before_bool = boolean(before);
    let after_bool = boolean(after);

    if let (Some(b), Some(a)) = (rank(before), rank(after)) {
        if a < b {
            return Some("severity lowered");
        }
        // The severity held. In `["error", 10] -> ["error", 100]` the rule is
        // as loud as it was and enforces a tenth as much, and reading only the
        // first element made that invisible — the most common shape of the
        // evasion in the ecosystem, since every rule that takes a threshold
        // takes it as an option. Only where the rule's own *name* says the
        // number is a ceiling: `indent: ["error", 2] -> ["error", 4]` is a
        // style choice and knowing that requires knowing the rule.
        if a == b && is_ceiling(&key) {
            if let (Some(b), Some(a)) = (rule_option_number(before), rule_option_number(after)) {
                return (a > b).then_some("rule allowance raised");
            }
        }
        return None;
    }
    if STRICT_WHEN_TRUE.iter().any(|k| leaf == *k)
        && before_bool == Some(true)
        && after_bool == Some(false)
    {
        return Some("strictness turned off");
    }
    if STRICT_WHEN_FALSE.iter().any(|k| leaf == *k)
        && before_bool == Some(false)
        && after_bool == Some(true)
    {
        return Some("checking skipped");
    }
    if let (Ok(b), Ok(a)) = (before.parse::<f64>(), after.parse::<f64>()) {
        if is_ceiling(&key) {
            return (a > b).then_some("allowance raised");
        }
        if FLOOR_KEY_FRAGMENTS.iter().any(|k| key.contains(k)) {
            return (a < b).then_some("floor lowered");
        }
    }
    None
}

/// Whether a key's number is a ceiling, so that raising it loosens.
///
/// The named fragments, and then the prefix: a leaf key beginning `max-` or
/// `max_` says of itself that its number is an allowance. That is the sentence
/// [`unrankable`] already used to justify the table — "compared where the rule's
/// own name says the number is a ceiling" — applied to every rule it is true of
/// rather than to the six somebody listed. The separator is required, so
/// `maxAge` is not a threshold and `max-depth` is.
fn is_ceiling(key: &str) -> bool {
    if MAX_THAT_IS_A_FLOOR.iter().any(|k| key.contains(k)) {
        return false;
    }
    if CEILING_KEY_FRAGMENTS.iter().any(|k| key.contains(k)) {
        return true;
    }
    let leaf = key.rsplit('.').next().unwrap_or(key);
    leaf.starts_with("max-") || leaf.starts_with("max_")
}

/// Why a changed value could not be ranked at all, or `None` when the detector
/// understood it.
///
/// # Narrow on purpose, and the narrowing is the design
///
/// Only lint rules — a value this detector reads as `<severity>` or
/// `[<severity>, ...options]` — count. Those are what it claims to model, and a
/// rule whose severity held while its options moved is a change inside that
/// claim which it has no answer for. `tsconfig`'s `target: es2020 -> es2022`,
/// a renamed path, a bumped port: all changes in a file this detector reads and
/// none of them thresholds, so marking them unassessable would put a caveat on
/// every config edit in every change and make `partial` the standing state.
/// A caveat that is always on is a caveat nobody reads.
///
/// The one it exists for: knowing which option of a rule is its threshold means
/// knowing the rule, and no per-linter rule table ships here. `is_ceiling`
/// covers the names that say so themselves; everything else lands here, loudly,
/// instead of arriving as a confident zero.
fn unrankable(key: &str, before: &str, after: &str) -> Option<&'static str> {
    let (Some(b), Some(a)) = (rank(before), rank(after)) else {
        return None;
    };
    if a != b {
        // The severity moved, and `loosening` has already ruled on which way.
        return None;
    }
    if loosening(key, before, after).is_some() {
        return None;
    }
    // The severity held and the option moved, but the rule's own name says the
    // number is a ceiling and both sides read as numbers — so the direction was
    // decided, and it was a tightening. Understood is understood whichever way
    // it went; only a firing is directional.
    let key = key.to_ascii_lowercase();
    if is_ceiling(&key)
        && rule_option_number(before).is_some()
        && rule_option_number(after).is_some()
    {
        return None;
    }
    Some(
        "a rule option moved while its severity held, and ranking it means knowing which \
         option of this rule is its threshold — no per-linter rule table ships here, so \
         whether this loosened the rule is not decidable from the text",
    )
}

/// Why a deleted setting cannot be ranked, or `None` when it was never this
/// detector's subject.
///
/// # Deleted is inside the subject, and the direction is outside the text
///
/// Deleting a rule loosens as surely as setting it to `off` — that is the
/// corpus's own note on `threshold-config-edit/eslint-rule-deleted` — but only
/// if the tool's default is looser than the value that was there, and nothing
/// in the file says what the default is. `strict: true` deleted from a
/// `tsconfig.json` that also sets `strict` in an extended base is no change at
/// all. So this reports rather than rules: the flag and the magnitude stay
/// about what could be decided, and the result stops claiming to be a complete
/// answer.
///
/// Narrow for the same reason [`unrankable`] is narrow. Only settings this
/// detector has a model for count — a severity word, a strictness boolean, a
/// number under a key whose name says floor or ceiling. A deleted `target` or a
/// renamed path is not a threshold, and marking every deleted config line
/// unassessed would make `partial` the standing state of every change that
/// tidies a config file.
fn deletion(key: &str, before: &str) -> Option<&'static str> {
    let key = key.to_ascii_lowercase();
    let leaf = key.rsplit('.').next().unwrap_or(&key).to_string();
    let modelled = rank(before).is_some()
        || (boolean(before).is_some()
            && (STRICT_WHEN_TRUE.iter().any(|k| leaf == *k)
                || STRICT_WHEN_FALSE.iter().any(|k| leaf == *k)))
        || (before.parse::<f64>().is_ok()
            && (is_ceiling(&key) || FLOOR_KEY_FRAGMENTS.iter().any(|k| key.contains(k))));
    modelled.then_some(
        "a setting this detector ranks was deleted rather than changed, and whether the \
         tool's default is looser than the value it had is not decidable from the text — \
         deleting a rule can loosen as surely as turning it off",
    )
}

/// The first number among a rule's options, in either form ESLint writes them.
///
/// `["error", 10]` and `["error", { "max": 10 }]` are the same rule at the same
/// threshold, and flat config uses the second for anything that takes more than
/// one option. The severity itself is skipped — it is the element before the
/// first comma, and `rank` has already read it.
fn rule_option_number(value: &str) -> Option<f64> {
    let (_, options) = value.trim().strip_prefix('[')?.split_once(',')?;
    let mut digits = String::new();
    for c in options.chars() {
        if c.is_ascii_digit() || (c == '.' && !digits.is_empty()) || (c == '-' && digits.is_empty())
        {
            digits.push(c);
        } else if !digits.is_empty() {
            break;
        }
    }
    digits.parse().ok()
}

/// A configuration boolean, however the file's syntax spells it.
fn boolean(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

/// Position in [`SEVERITY_WORDS`], for values that are severity words.
fn rank(value: &str) -> Option<usize> {
    let value = severity_token(value).to_ascii_lowercase();
    SEVERITY_WORDS.iter().position(|w| *w == value)
}

/// The severity out of a rule value, whichever of eslint's two forms it is in.
///
/// `"no-explicit-any": "error"` and
/// `"no-explicit-any": ["error", { "fixToUnknown": true }]` say the same thing,
/// and the second is the form every real configuration uses as soon as a rule
/// takes options. Reading the array as an opaque string meant the most common
/// downgrade in the ecosystem was invisible.
///
/// Only the severity is read *here*. The options beside it are read by
/// [`rule_option_number`], and the pair is compared in [`loosening`]:
/// `["error", 10] -> ["error", 100]` on a rule whose name says the number is a
/// ceiling now fires. It used not to, and the sentence that stood here said so
/// as a permanent limitation — a UAT run raising ESLint's `complexity` from 10
/// to 100 got `{flag: false, magnitude: 0, completeness: "complete"}` back.
///
/// What is still not caught is a threshold option on a rule whose name does not
/// say it is one, because that needs a per-linter rule table this detector does
/// not have. Those changes are no longer silent either: [`unrankable`] reports
/// them and the engine marks the result `partial`.
fn severity_token(value: &str) -> &str {
    let trimmed = value.trim();
    let Some(inner) = trimmed.strip_prefix('[') else {
        return trimmed;
    };
    inner
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches(['"', '\'', ']'])
        .trim()
}

/// Every `key = value` in a config file, as a flat map.
///
/// Keys are qualified by the enclosing bracketed section when there is one
/// (`[severity]` in TOML, `[run]` in INI), so `severity.max_severity_for_c_tier`
/// does not collide with a same-named key elsewhere. JSON and YAML nesting is
/// deliberately not tracked — see [`crate::config`] for why a leaf key is the
/// right granularity here.
fn settings(source: &[u8]) -> BTreeMap<String, (u32, String)> {
    let text = String::from_utf8_lossy(source);
    let mut out = BTreeMap::new();
    let mut section = String::new();
    for (index, raw) in text.lines().enumerate() {
        if config::is_noise(raw) {
            continue;
        }
        if let Some(found) = config::section(raw) {
            section = found;
            continue;
        }
        for pair in config::pairs(raw) {
            if pair.value.is_empty() {
                continue;
            }
            let qualified = if section.is_empty() {
                pair.key
            } else {
                format!("{section}.{}", pair.key)
            };
            out.insert(qualified, (index as u32 + 1, pair.value));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::FileChange;

    #[test]
    fn an_eslint_rule_downgraded_to_warn_fires() {
        let base = "{ \"rules\": { \"no-explicit-any\": \"error\" } }";
        let head = "{ \"rules\": { \"no-explicit-any\": \"warn\" } }";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("severity lowered"));
    }

    #[test]
    fn the_array_rule_form_is_read_too() {
        // The form every real eslint config uses once a rule takes options.
        let base =
            "{ \"rules\": { \"no-explicit-any\": [\"error\", { \"fixToUnknown\": true }] } }";
        let head = "{ \"rules\": { \"no-explicit-any\": [\"warn\", { \"fixToUnknown\": true }] } }";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("severity lowered"));
    }

    #[test]
    fn the_array_rule_form_is_directional_too() {
        let base = "{ \"rules\": { \"complexity\": [\"warn\", 10] } }";
        let head = "{ \"rules\": { \"complexity\": [\"error\", 10] } }";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn upgrading_a_rule_does_not_fire() {
        let base = "{ \"rules\": { \"no-explicit-any\": \"warn\" } }";
        let head = "{ \"rules\": { \"no-explicit-any\": \"error\" } }";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn turning_off_typescript_strictness_fires() {
        let base = "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2022\" } }";
        let head = "{ \"compilerOptions\": { \"strict\": false, \"target\": \"es2022\" } }";
        let view = ChangeView::new(vec![FileChange::modified("tsconfig.json", base, head)]);
        assert!(ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn lowering_a_coverage_floor_fires() {
        let base = "[tool.coverage.report]\nfail_under = 85\n";
        let head = "[tool.coverage.report]\nfail_under = 60\n";
        let view = ChangeView::new(vec![FileChange::modified("pyproject.toml", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("floor lowered"));
    }

    #[test]
    fn raising_a_complexity_allowance_fires() {
        let base = "[flake8]\nmax-complexity = 10\n";
        let head = "[flake8]\nmax-complexity = 40\n";
        let view = ChangeView::new(vec![FileChange::modified("setup.cfg", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("allowance raised"));
    }

    #[test]
    fn raising_a_coverage_floor_does_not_fire() {
        let base = "[tool.coverage.report]\nfail_under = 60\n";
        let head = "[tool.coverage.report]\nfail_under = 85\n";
        let view = ChangeView::new(vec![FileChange::modified("pyproject.toml", base, head)]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn an_unrelated_config_edit_does_not_fire() {
        let base = "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2020\" } }";
        let head = "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2022\" } }";
        let view = ChangeView::new(vec![FileChange::modified("tsconfig.json", base, head)]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn a_source_file_with_a_threshold_shaped_constant_does_not_fire() {
        let base = "export const maxComplexity = 10;\n";
        let head = "export const maxComplexity = 40;\n";
        let view = ChangeView::new(vec![FileChange::modified("src/limits.ts", base, head)]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn an_ini_written_boolean_is_still_a_boolean() {
        let base = "[mypy]
disallow_untyped_defs = True
";
        let head = "[mypy]
disallow_untyped_defs = False
";
        let view = ChangeView::new(vec![FileChange::modified("mypy.ini", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("strictness turned off"));
    }

    #[test]
    fn a_firing_is_the_weakest_of_the_seven_and_that_is_not_what_decides_the_line() {
        // Renamed from `firing_is_advisory_not_blocking`, which stopped being
        // true when the exemption was narrowed: an unjustified loosening stops
        // the line. What the severity says is how strong the finding is.
        assert_eq!(ThresholdConfigEdit.severity_when_fired(), Severity::Low);
        assert!(!ThresholdConfigEdit.severity_when_fired().is_med_plus());
    }

    #[test]
    fn an_eslint_threshold_raised_inside_a_rule_fires() {
        // The UAT case: the rule stays as loud as it was and enforces a tenth
        // as much. This came back `{flag: false, magnitude: 0,
        // completeness: "complete"}`, and the module doc recorded it as a
        // permanent limitation.
        let base = "{ \"rules\": { \"complexity\": [\"error\", 10] } }";
        let head = "{ \"rules\": { \"complexity\": [\"error\", 100] } }";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(
            outcome.findings[0].detail.contains("rule allowance raised"),
            "{:?}",
            outcome.findings
        );
    }

    #[test]
    fn the_same_threshold_raised_in_flat_config_fires() {
        // `eslint.config.js` writes the option as an object, which is the form
        // every flat config uses. Reported missed alongside `.eslintrc.json`.
        let base = "export default [{ rules: { complexity: [\"error\", { max: 10 }] } }];\n";
        let head = "export default [{ rules: { complexity: [\"error\", { max: 100 }] } }];\n";
        let view = ChangeView::new(vec![FileChange::modified("eslint.config.js", base, head)]);
        assert!(ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn the_unwrapped_spelling_of_the_same_setting_fires() {
        // ESLint spells it `complexity`; flake8 spells it `max-complexity`. The
        // table held only the prefixed spellings.
        let base = "{ \"rules\": { \"complexity\": 10 } }";
        let head = "{ \"rules\": { \"complexity\": 100 } }";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        assert!(ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn lowering_a_rule_threshold_is_a_tightening_and_stays_quiet() {
        let base = "{ \"rules\": { \"complexity\": [\"error\", 100] } }";
        let head = "{ \"rules\": { \"complexity\": [\"error\", 10] } }";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert!(outcome.unassessed.is_empty(), "{outcome:?}");
    }

    #[test]
    fn a_rule_option_that_is_not_a_threshold_does_not_fire() {
        // `indent: ["error", 2] -> ["error", 4]` is a style choice, and telling
        // it apart from a threshold means knowing the rule. It must not fire —
        // but it is a rule option this detector could not rank, so it must not
        // pass as a complete answer either.
        let base = "{ \"rules\": { \"indent\": [\"error\", 2] } }";
        let head = "{ \"rules\": { \"indent\": [\"error\", 4] } }";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert_eq!(outcome.unassessed.len(), 1, "{outcome:?}");
        assert!(outcome.unassessed[0].detail.contains("indent"));
    }

    #[test]
    fn a_config_edit_outside_this_detectors_subject_is_not_marked_unassessed() {
        // The narrowing that keeps the caveat worth reading. A bumped compiler
        // target is a change in a file this detector reads and is not a
        // threshold — if this became `partial`, so would every config edit in
        // every change.
        let base = "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2020\" } }";
        let head = "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2022\" } }";
        let view = ChangeView::new(vec![FileChange::modified("tsconfig.json", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(!outcome.fired);
        assert!(outcome.unassessed.is_empty(), "{outcome:?}");
    }

    #[test]
    fn a_severity_move_is_ranked_and_never_merely_unranked() {
        for (base, head) in [
            ("\"error\"", "\"warn\""),
            ("\"warn\"", "\"error\""),
            ("[\"error\", 10]", "[\"warn\", 10]"),
        ] {
            let before = format!("{{ \"rules\": {{ \"complexity\": {base} }} }}");
            let after = format!("{{ \"rules\": {{ \"complexity\": {head} }} }}");
            let view = ChangeView::new(vec![FileChange::modified(
                ".eslintrc.json",
                &before,
                &after,
            )]);
            let outcome = ThresholdConfigEdit.run(&view);
            assert!(
                outcome.unassessed.is_empty(),
                "{base} -> {head}: the severity moved, so the direction is known: {outcome:?}"
            );
        }
    }

    #[test]
    fn a_deleted_setting_is_reported_as_unranked_rather_than_as_nothing() {
        // The loop over head keys only ever sees settings present on both sides,
        // so a deleted one had no value to compare and produced nothing at all.
        // Deleting a rule can loosen as surely as turning it off — and it can
        // also be no change, if an extended base still sets it — so this is
        // reported rather than ruled on.
        let view = ChangeView::new(vec![FileChange::modified(
            "tsconfig.json",
            "{ \"compilerOptions\": { \"noImplicitAny\": true, \"target\": \"es2022\" } }",
            "{ \"compilerOptions\": { \"target\": \"es2022\" } }",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert_eq!(outcome.unassessed.len(), 1, "{outcome:?}");
        assert!(
            outcome.unassessed[0].detail.contains("noimplicitany"),
            "{:?}",
            outcome.unassessed
        );
        assert!(outcome.unassessed[0].detail.contains("-> absent"));
    }

    #[test]
    fn a_deleted_line_this_detector_never_modelled_spends_no_caveat() {
        // The narrowing that keeps the caveat readable. A compiler target and a
        // renamed path are deletions in a file this detector reads and are not
        // thresholds; if they were unassessed, every change that tidies a config
        // file would come back `partial`.
        let view = ChangeView::new(vec![FileChange::modified(
            "tsconfig.json",
            "{ \"compilerOptions\": { \"strict\": true, \"target\": \"es2020\" } }",
            "{ \"compilerOptions\": { \"strict\": true } }",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert!(outcome.unassessed.is_empty(), "{outcome:?}");
    }

    #[test]
    fn a_flag_whose_strict_value_is_false_fires_when_it_is_turned_on() {
        // The only boolean model here read strictness one way round, so
        // `skipLibCheck: false -> true` — the compiler told to stop checking
        // declaration files — came back as a complete zero.
        let view = ChangeView::new(vec![FileChange::modified(
            "tsconfig.json",
            "{ \"compilerOptions\": { \"skipLibCheck\": false } }",
            "{ \"compilerOptions\": { \"skipLibCheck\": true } }",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("checking skipped"));
        // And the reverse is a tightening.
        let view = ChangeView::new(vec![FileChange::modified(
            "tsconfig.json",
            "{ \"compilerOptions\": { \"skipLibCheck\": true } }",
            "{ \"compilerOptions\": { \"skipLibCheck\": false } }",
        )]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn a_rule_whose_name_says_ceiling_is_one_without_being_listed() {
        // The `complexity` rationale, applied to every rule it is true of. The
        // separator is required, so a `maxAge` is not a threshold.
        for key in [
            "max-lines",
            "max-lines-per-function",
            "max-depth",
            "max-params",
            "max-statements",
            "max-nested-callbacks",
            "rules.max_line_count",
        ] {
            assert!(is_ceiling(key), "{key}");
        }
        for key in ["maxage", "indent", "quotes", "lines", "branches"] {
            assert!(!is_ceiling(key), "{key}");
        }
    }

    #[test]
    fn the_one_max_that_is_a_floor_keeps_its_direction() {
        // `max_severity_for_c_tier` caps how loud a C-tier metric may be, so
        // lowering it lets less through — the opposite direction from every
        // other `max`, and the direction table in `andon_core` is authoritative
        // for it. A prefix rule that reversed a policy field would be a wrong
        // answer with a tamper signal attached.
        assert!(!is_ceiling("severity.max_severity_for_c_tier"));
        let view = ChangeView::new(vec![FileChange::modified(
            ".andon.toml",
            "[severity]\nmax_severity_for_c_tier = 3\n",
            "[severity]\nmax_severity_for_c_tier = 1\n",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(
            outcome.findings[0].detail.contains("floor lowered"),
            "{:?}",
            outcome.findings
        );
    }

    #[test]
    fn every_spelling_of_one_tools_configuration_is_that_tool_s_configuration() {
        for path in [
            ".eslintrc",
            ".eslintrc.json",
            ".eslintrc.js",
            ".eslintrc.cjs",
            ".eslintrc.yml",
            ".eslintrc.yaml",
            "eslint.config.js",
            "eslint.config.cjs",
            "eslint.config.mjs",
            "eslint.config.mts",
            ".golangci.yml",
            ".golangci.toml",
            ".golangci.json",
            "tsconfig.json",
            "tsconfig.base.json",
            ".nycrc.json",
            "packages/api/mypy.ini",
        ] {
            assert!(is_threshold_config(path), "{path}");
        }
        for path in [
            "src/limits.ts",
            "src/tsconfig-loader.ts",
            "src/setup.ts",
            "eslint-rules/index.js",
        ] {
            assert!(!is_threshold_config(path), "{path}");
        }
    }

    #[test]
    fn the_rule_option_reader_skips_the_severity_and_finds_the_number() {
        assert_eq!(rule_option_number("[\"error\", 10]"), Some(10.0));
        assert_eq!(
            rule_option_number("[\"error\", { \"max\": 40 }]"),
            Some(40.0)
        );
        assert_eq!(rule_option_number("[\"warn\", { max: 8 }]"), Some(8.0));
        // No options, or none numeric.
        assert_eq!(rule_option_number("\"error\""), None);
        assert_eq!(rule_option_number("[\"error\"]"), None);
        assert_eq!(
            rule_option_number("[\"error\", { \"allow\": [\"arrowFunctions\"] }]"),
            None
        );
    }
}
