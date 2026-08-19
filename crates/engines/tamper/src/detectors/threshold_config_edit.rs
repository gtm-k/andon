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

use std::collections::{BTreeMap, BTreeSet};

use crate::change::ChangeView;
use crate::config::{self, tools};
use crate::detectors::{Detector, Finding, Outcome};
use andon_core::schema::enums::{Severity, TamperSignal};

/// The detector.
pub struct ThresholdConfigEdit;

/// The tools whose configuration carries quality thresholds.
///
/// Which tools, not which file names: [`config::tools`] holds the names, for
/// the reason [`config::Tool`] sets out. The exact list this replaced held
/// `.eslintrc.js` and not `.eslintrc.cjs`, `.eslintrc.yml` and not
/// `.eslintrc.yaml`, three flat-config spellings and not `eslint.config.cjs`,
/// `.golangci.yml` and not `.golangci.toml` — and every one of those returned a
/// confident zero on byte-identical content that fired in its sibling spelling.
const THRESHOLD_TOOLS: &[config::Tool] = &[
    tools::ANDON,
    tools::TSCONFIG,
    tools::ESLINTRC,
    tools::ESLINT_FLAT,
    tools::BIOME,
    tools::FLAKE8,
    tools::PYPROJECT,
    tools::MYPY,
    tools::MYPY_DOT,
    tools::RUFF,
    tools::RUFF_DOT,
    tools::CLIPPY,
    tools::GOLANGCI,
    tools::SONAR,
    tools::JEST,
    tools::VITEST,
    // Coverage configuration carries thresholds too, and they were reachable in
    // some of these files and not others: `.nycrc.json` dropping `lines` from
    // 90 to 10 is a floor lowered, in a file this detector was not opening.
    tools::COVERAGERC,
    tools::NYCRC,
    tools::C8RC,
    tools::CODECOV,
    tools::CODECOV_DOT,
    tools::TARPAULIN,
    tools::SETUP_CFG,
    tools::PACKAGE_JSON,
    tools::TOX_INI,
];

/// Whether a path is threshold configuration.
pub fn is_threshold_config(path: &str) -> bool {
    config::names_one_of(path, THRESHOLD_TOOLS)
}

/// Whose vocabulary a file is written in.
///
/// # Two settings mean different things depending on who reads the file
///
/// Almost every key here means the same thing wherever it appears, which is
/// what lets one table of fragments serve fifteen tools. Two do not, and both
/// were confident zeros:
///
/// - ESLint writes a rule's severity as `0`, `1` or `2` as readily as `off`,
///   `warn` and `error`. `"no-explicit-any": 2 -> 0` turns a rule off, and the
///   severity ladder read words only. Nowhere else does a bare `2` mean
///   `error`, so ranking one everywhere would reverse the direction of every
///   honest numeric setting that happens to sit at 2.
/// - Codecov's `target` is the coverage percentage a project must hold. `80 ->
///   50` is a floor lowered as plainly as `fail_under`, and `target` is also
///   TypeScript's language level, where it is a string and nothing to do with
///   quality.
///
/// So the dialect is read off the file name, from the same tool table that
/// decides whether the file is opened at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    /// ESLint, in either config generation.
    Eslint,
    /// Codecov.
    Codecov,
    /// Everything else: the shared vocabulary and nothing more.
    Shared,
}

fn dialect_of(path: &str) -> Dialect {
    if config::names_one_of(path, &[tools::ESLINTRC, tools::ESLINT_FLAT]) {
        Dialect::Eslint
    } else if config::names_one_of(path, &[tools::CODECOV, tools::CODECOV_DOT]) {
        Dialect::Codecov
    } else {
        Dialect::Shared
    }
}

/// A configuration number, however its syntax spells it.
///
/// `parse::<f64>` was the whole reader, and three ordinary spellings fell
/// straight through it: TOML's digit separator (`iteration_cap = 10_000`),
/// Codecov's percentage (`target: 80%`), and a number written as a quoted
/// string, which YAML and JSON both allow. Each one arrived as "not a number",
/// which meant either a threshold that could not be compared or — once the axis
/// below existed — a caveat on an honest edit.
fn number(value: &str) -> Option<f64> {
    let trimmed = value.trim().trim_matches(['"', '\'']).trim();
    let trimmed = trimmed.strip_suffix('%').unwrap_or(trimmed);
    if trimmed.is_empty() || trimmed.starts_with('_') || trimmed.ends_with('_') {
        return None;
    }
    trimmed
        .chars()
        .filter(|c| *c != '_')
        .collect::<String>()
        .parse()
        .ok()
}

/// ESLint's numeric severity, as a position in [`SEVERITY_WORDS`].
///
/// Only in an ESLint file, and only for `0`, `1` and `2`: those are the three
/// values the vocabulary has, and a rule option that happens to be 2 is
/// therefore indistinguishable from `error` by the text alone. That ambiguity
/// is decided in ESLint's own favour — see
/// [`the_bare_number_corner_is_decided_in_eslint_s_favour`].
fn numeric_rank(dialect: Dialect, value: &str) -> Option<usize> {
    if dialect != Dialect::Eslint {
        return None;
    }
    let word = match value.trim().trim_matches(['"', '\'']).trim() {
        "0" => "off",
        "1" => "warn",
        "2" => "error",
        _ => return None,
    };
    SEVERITY_WORDS.iter().position(|w| *w == word)
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
            let dialect = dialect_of(&file.path);
            let base = settings(file.base_bytes());
            let head = settings(file.head_bytes());
            // A setting that is gone has no value to compare, and the loop below
            // only ever sees keys present on both sides — so removing
            // `noImplicitAny` from a `tsconfig.json` was a change inside this
            // detector's own subject that it reported as nothing at all.
            for (key, (_, base_value)) in &base.settings {
                if head.settings.contains_key(key) {
                    continue;
                }
                if let Some(reason) = deletion(dialect, key, base_value) {
                    unassessed.push(Finding::in_file(
                        &file.path,
                        format!("{key}: {base_value} -> absent ({reason})"),
                    ));
                }
            }
            for (key, (line, head_value)) in &head.settings {
                let Some((_, base_value)) = base.settings.get(key) else {
                    continue;
                };
                // A threshold written as a reference does not move when the
                // threshold does, so it is ruled on whether or not its own text
                // changed — that is the whole of the indirect case.
                if let Some(reason) = indirect(dialect, key, base_value, head_value, &base, &head) {
                    match reason {
                        Ok(fired) => findings.push(Finding::at(
                            &file.path,
                            *line,
                            format!("{key}: {base_value} -> {head_value} ({fired})"),
                        )),
                        Err(unranked) => unassessed.push(Finding::at(
                            &file.path,
                            *line,
                            format!("{key}: {base_value} -> {head_value} ({unranked})"),
                        )),
                    }
                    continue;
                }
                if base_value == head_value {
                    continue;
                }
                if let Some(reason) = loosening(dialect, key, base_value, head_value) {
                    findings.push(Finding::at(
                        &file.path,
                        *line,
                        format!("{key}: {base_value} -> {head_value} ({reason})"),
                    ));
                } else if let Some(reason) = unrankable(dialect, key, base_value, head_value) {
                    unassessed.push(Finding::at(
                        &file.path,
                        *line,
                        format!("{key}: {base_value} -> {head_value} ({reason})"),
                    ));
                }
            }
            unassessed.extend(unread_changes(&file.path, &base, &head));
        }
        let count = findings.len() as i64;
        if count > 0 {
            Outcome::fired(count, findings).with_unassessed(unassessed)
        } else {
            Outcome::quiet(0).with_unassessed(unassessed)
        }
    }
}

/// Changed lines this scanner read nothing out of, that carry a value of the
/// kind it ranks.
///
/// # The other axis, and the one two rounds of repair never added
///
/// Every rule above answers *which tool is this file, and what does this key
/// mean*. None of them answers *can the scanner read this shape at all* — and a
/// shape it cannot read produces no setting, so no rule ever runs and the file
/// comes back `{flag: false, magnitude: 0, completeness: "complete"}`. That is
/// the confident zero in its purest form: not a threshold the detector declined
/// to rank, but one it never saw.
///
/// [`config::pairs_continued`] closes the bracketed spellings by following a
/// value onto the lines after it. This is what answers for the seventh shape,
/// the one nobody has written down — a YAML block sequence, say, where
///
/// ```text
/// rules:
///   complexity:
///     - error
///     - 10
/// ```
///
/// has no brackets to follow and no separator on the line that carries the
/// number. The line changed, the scanner got nothing from it, and the token on
/// it is exactly the kind this detector's models are made of. It cannot say
/// which way that went, and saying so is the honest answer.
///
/// # Why the token test is this narrow
///
/// A caveat that is always on is a caveat nobody reads, and the standing state
/// is what makes `partial` mean something. Three narrowings hold it there:
///
/// - **trimmed lines**, so reindenting a config is not a change. The corpus has
///   that case (`config-reindented`) and it must stay `complete`.
/// - **read lines**, so a line the scanner consumed — including one a continued
///   value ran through — is never a blind spot even if its own text carries no
///   separator.
/// - **standalone tokens**, so a path is not a number. `src/legacy2/*` and
///   `*/__init__.py` are ordinary exclusion entries in files this detector also
///   reads, and every one of them carries digits. A token adjacent to a
///   separator or a glob is part of a path and says nothing about a threshold.
fn unread_changes(path: &str, base: &Scanned, head: &Scanned) -> Vec<Finding> {
    let mut out = Vec::new();
    for (side, other, label) in [(head, base, "now reads"), (base, head, "no longer reads")] {
        let mut available: BTreeMap<&str, usize> = BTreeMap::new();
        for line in &other.lines {
            *available.entry(line.as_str()).or_default() += 1;
        }
        for (index, line) in side.lines.iter().enumerate() {
            match available.get_mut(line.as_str()) {
                Some(count) if *count > 0 => {
                    *count -= 1;
                    continue;
                }
                _ => {}
            }
            if side.read.contains(&index) || !carries_a_ranked_token(line) {
                continue;
            }
            out.push(Finding::at(
                path,
                index as u32 + 1,
                format!(
                    "this file {label} `{line}`, and the scanner took no setting from it — \
                     the value on it is of the kind this detector ranks and it is written in \
                     a shape the scanner cannot reach, so whether a threshold moved here is \
                     not decidable from what was read"
                ),
            ));
        }
    }
    out
}

/// Whether a line carries a number, a severity word or a boolean standing on
/// its own rather than inside a path or an identifier.
fn carries_a_ranked_token(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut start: Option<usize> = None;
    for index in 0..=bytes.len() {
        let inside = index < bytes.len()
            && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'-' | b'.'));
        match (inside, start) {
            (true, None) => start = Some(index),
            (false, Some(from)) => {
                start = None;
                // A run touching a separator or a glob is part of a path.
                let hemmed = |at: usize| matches!(bytes[at], b'/' | b'*' | b'?' | b'\\');
                if from > 0 && hemmed(from - 1) {
                    continue;
                }
                if index < bytes.len() && hemmed(index) {
                    continue;
                }
                let token = &line[from..index];
                if number(token).is_some()
                    || SEVERITY_WORDS.contains(&token.to_ascii_lowercase().as_str())
                    || boolean(token).is_some()
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// A threshold whose value is a name rather than a number, resolved against the
/// same file — `Ok` when it moved and which way, `Err` when it cannot be read,
/// `None` when this key is not that shape.
///
/// # A limit behind a variable is still a limit
///
/// Flat config is JavaScript, and JavaScript configs bind their numbers:
///
/// ```text
/// const LIMIT = 10;
/// export default [{ rules: { complexity: ["error", LIMIT] } }];
/// ```
///
/// Raising that 10 to 100 loosens the rule and leaves the rule's own line
/// byte-identical, so every comparison above ran on values that had not
/// changed and the answer was a complete zero. The binding is in the same file
/// and this scanner already read it — `const LIMIT = 10` is a `key = value`
/// like any other — so one level of resolution is all it takes.
///
/// It is one level on purpose. A limit imported from another module is not in
/// this file and nothing here can evaluate it; that case is reported rather
/// than guessed, and only when the reference itself was written or edited in
/// this change. A rule that has always read `["error", LIMIT]` and still does
/// spends no caveat, or every edit to such a file would carry one forever.
fn indirect(
    dialect: Dialect,
    key: &str,
    before: &str,
    after: &str,
    base: &Scanned,
    head: &Scanned,
) -> Option<Result<String, &'static str>> {
    let key = key.to_ascii_lowercase();
    if !is_ceiling(dialect, &key) {
        return None;
    }
    // Only `[<severity>, ...options]`, on both sides, with the severity holding:
    // a bare severity has no allowance to be indirect about, and a severity that
    // moved is `loosening`'s to rule on.
    if rank(dialect, before)? != rank(dialect, after)? {
        return None;
    }
    if !before.trim_start().starts_with('[') || !after.trim_start().starts_with('[') {
        return None;
    }
    if rule_option_number(before).is_some() && rule_option_number(after).is_some() {
        return None;
    }
    if rule_option_name(before).is_none() && rule_option_name(after).is_none() {
        return None;
    }
    let resolved = |value: &str, side: &Scanned| -> Option<(String, f64)> {
        if let Some(literal) = rule_option_number(value) {
            return Some((literal.to_string(), literal));
        }
        let name = rule_option_name(value)?;
        let (_, bound) = side.settings.get(&name)?;
        number(bound).map(|found| (format!("{name} = {bound}"), found))
    };
    match (resolved(before, base), resolved(after, head)) {
        (Some((was, b)), Some((now, a))) => (a > b).then(|| {
            Ok(format!(
                "rule allowance raised behind a reference: {was} -> {now}"
            ))
        }),
        _ if before != after => Some(Err(
            "this rule's option is a name rather than a number and nothing in this file \
             binds it, so whether the allowance moved is not decidable from the text",
        )),
        _ => None,
    }
}

/// The first identifier among a rule's options, lower-cased.
///
/// The mirror of [`rule_option_number`] for the case that one cannot read: the
/// option is spelled as a name, and the name is a key this scanner may already
/// have a value for.
/// An identifier followed by `:` or `=` is the option's *name*, not its value —
/// `{ max: LIMIT }` binds `LIMIT` to `max` — so the scan steps over it. Quotes
/// are stepped over too, because JSON writes the same thing as `{"max": LIMIT}`.
fn rule_option_name(value: &str) -> Option<String> {
    let (_, options) = value.trim().strip_prefix('[')?.split_once(',')?;
    let bytes = options.as_bytes();
    let mut start: Option<usize> = None;
    for index in 0..=bytes.len() {
        let inside =
            index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_');
        match (inside, start) {
            (true, None) => start = Some(index),
            (false, Some(from)) => {
                start = None;
                let named = bytes[index..]
                    .iter()
                    .find(|c| !matches!(c, b' ' | b'\t' | b'"' | b'\''))
                    .is_some_and(|c| matches!(c, b':' | b'='));
                let token = &options[from..index];
                if !named && !token.chars().all(|c| c.is_ascii_digit()) {
                    return Some(token.to_ascii_lowercase());
                }
            }
            _ => {}
        }
    }
    None
}

/// Why a value change is a loosening, or `None` when it is not one.
fn loosening(dialect: Dialect, key: &str, before: &str, after: &str) -> Option<&'static str> {
    let key = key.to_ascii_lowercase();
    let leaf = key.rsplit('.').next().unwrap_or(&key).to_string();
    // Booleans are spelled `true` in TOML and JSON, `True` in an INI file that
    // Python wrote, and `yes` in some YAML. Comparing them as written meant
    // `disallow_untyped_defs = True -> False` in mypy.ini read as an ordinary
    // string edit; the corpus caught it.
    let before_bool = boolean(before);
    let after_bool = boolean(after);

    if let (Some(b), Some(a)) = (rank(dialect, before), rank(dialect, after)) {
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
        if a == b && is_ceiling(dialect, &key) {
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
    if let (Some(b), Some(a)) = (number(before), number(after)) {
        if is_ceiling(dialect, &key) {
            return (a > b).then_some("allowance raised");
        }
        if is_floor(dialect, &key) {
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
fn is_ceiling(_dialect: Dialect, key: &str) -> bool {
    if MAX_THAT_IS_A_FLOOR.iter().any(|k| key.contains(k)) {
        return false;
    }
    if CEILING_KEY_FRAGMENTS.iter().any(|k| key.contains(k)) {
        return true;
    }
    let leaf = key.rsplit('.').next().unwrap_or(key);
    leaf.starts_with("max-") || leaf.starts_with("max_")
}

/// Whether a key's number is a floor, so that lowering it loosens.
///
/// The shared fragments, and then the one key whose meaning is its tool's:
/// Codecov's `target` is the coverage percentage a project must hold, so
/// `80 -> 50` is `fail_under` under another name. It is not in the shared table
/// because `target` is also TypeScript's language level, where it is a string
/// and says nothing about quality — see [`Dialect`].
fn is_floor(dialect: Dialect, key: &str) -> bool {
    if FLOOR_KEY_FRAGMENTS.iter().any(|k| key.contains(k)) {
        return true;
    }
    let leaf = key.rsplit('.').next().unwrap_or(key);
    dialect == Dialect::Codecov && leaf == "target"
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
fn unrankable(dialect: Dialect, key: &str, before: &str, after: &str) -> Option<&'static str> {
    let (Some(b), Some(a)) = (rank(dialect, before), rank(dialect, after)) else {
        return None;
    };
    if a != b {
        // The severity moved, and `loosening` has already ruled on which way.
        return None;
    }
    if loosening(dialect, key, before, after).is_some() {
        return None;
    }
    // The severity held and the option moved, but the rule's own name says the
    // number is a ceiling and both sides read as numbers — so the direction was
    // decided, and it was a tightening. Understood is understood whichever way
    // it went; only a firing is directional.
    let key = key.to_ascii_lowercase();
    if is_ceiling(dialect, &key)
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
fn deletion(dialect: Dialect, key: &str, before: &str) -> Option<&'static str> {
    let key = key.to_ascii_lowercase();
    let leaf = key.rsplit('.').next().unwrap_or(&key).to_string();
    let modelled = rank(dialect, before).is_some()
        || (boolean(before).is_some()
            && (STRICT_WHEN_TRUE.iter().any(|k| leaf == *k)
                || STRICT_WHEN_FALSE.iter().any(|k| leaf == *k)))
        || (number(before).is_some() && (is_ceiling(dialect, &key) || is_floor(dialect, &key)));
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
///
/// ESLint's numbers rank here too, and they rank *first*: `"complexity": 2` is
/// a rule set to `error`, not a complexity allowance of two, and the ceiling
/// table would otherwise read `2 -> 0` as an allowance lowered and go quiet on
/// a rule being switched off. That precedence is the deliberate half of the
/// ambiguity — see [`numeric_rank`].
fn rank(dialect: Dialect, value: &str) -> Option<usize> {
    let token = severity_token(value);
    numeric_rank(dialect, token).or_else(|| {
        let token = token.to_ascii_lowercase();
        SEVERITY_WORDS.iter().position(|w| *w == token)
    })
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
fn settings(source: &[u8]) -> Scanned {
    let text = String::from_utf8_lossy(source);
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Scanned {
        lines: lines.iter().map(|line| line.trim().to_string()).collect(),
        ..Scanned::default()
    };
    let mut section = String::new();
    for index in 0..lines.len() {
        let raw = lines[index];
        if config::is_noise(raw) {
            out.read.insert(index);
            continue;
        }
        if let Some(found) = config::section(raw) {
            section = found;
            out.read.insert(index);
            continue;
        }
        let (pairs, spanned) = config::pairs_continued(&lines, index);
        for pair in pairs {
            if pair.value.is_empty() {
                continue;
            }
            let qualified = if section.is_empty() {
                pair.key
            } else {
                format!("{section}.{}", pair.key)
            };
            out.settings
                .insert(qualified, (index as u32 + 1, pair.value));
            // Every line the value ran over, not just the one the key is on: a
            // continuation line is a line this scanner read, and the axis below
            // asks exactly that question of every changed line.
            out.read.extend(index..(index + spanned).min(lines.len()));
        }
    }
    out
}

/// What the scanner got out of one side of one file.
#[derive(Debug, Default)]
struct Scanned {
    /// Every `key = value`, qualified by section, as `(1-based line, value)`.
    settings: BTreeMap<String, (u32, String)>,
    /// Every line, trimmed. Trimmed because reindentation is not a change and
    /// a caveat spent on one would be a caveat on `cargo fmt`.
    lines: Vec<String>,
    /// The 0-based lines the scanner read something out of — a comment, a
    /// section header, a setting, or a line a continued value ran through.
    read: BTreeSet<usize>,
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
            assert!(is_ceiling(Dialect::Shared, key), "{key}");
        }
        for key in ["maxage", "indent", "quotes", "lines", "branches"] {
            assert!(!is_ceiling(Dialect::Shared, key), "{key}");
        }
    }

    #[test]
    fn the_one_max_that_is_a_floor_keeps_its_direction() {
        // `max_severity_for_c_tier` caps how loud a C-tier metric may be, so
        // lowering it lets less through — the opposite direction from every
        // other `max`, and the direction table in `andon_core` is authoritative
        // for it. A prefix rule that reversed a policy field would be a wrong
        // answer with a tamper signal attached.
        assert!(!is_ceiling(
            Dialect::Shared,
            "severity.max_severity_for_c_tier"
        ));
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

    #[test]
    fn a_severity_eslint_wrote_as_a_number_is_a_severity() {
        // `2`, `1`, `0` are `error`, `warn`, `off`, and every real eslint config
        // in the wild uses them. Turning a rule off this way came back
        // `{flag: false, magnitude: 0, completeness: "complete"}`.
        let view = ChangeView::new(vec![FileChange::modified(
            ".eslintrc.json",
            "{ \"rules\": { \"no-explicit-any\": 2 } }",
            "{ \"rules\": { \"no-explicit-any\": 0 } }",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("severity lowered"));

        // And the reverse is a tightening, with nothing left unranked.
        let view = ChangeView::new(vec![FileChange::modified(
            ".eslintrc.json",
            "{ \"rules\": { \"no-explicit-any\": 0 } }",
            "{ \"rules\": { \"no-explicit-any\": 2 } }",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert!(outcome.unassessed.is_empty(), "{outcome:?}");
    }

    #[test]
    fn the_bare_number_corner_is_decided_in_eslint_s_favour() {
        // `"complexity": 2` is genuinely ambiguous in the text: eslint reads it
        // as the severity `error`, and this detector's own ceiling table would
        // read it as an allowance of two. The tie goes to eslint, because in an
        // eslint file that is what the file means — and the other reading makes
        // `2 -> 0` an allowance *lowered*, which is a confident silence on a
        // rule being switched off.
        let view = ChangeView::new(vec![FileChange::modified(
            ".eslintrc.json",
            "{ \"rules\": { \"complexity\": 2 } }",
            "{ \"rules\": { \"complexity\": 0 } }",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(
            outcome.findings[0].detail.contains("severity lowered"),
            "{:?}",
            outcome.findings
        );
    }

    #[test]
    fn a_numeric_severity_is_eslint_s_and_nobody_else_s() {
        // The bound on the rule above. Ranking a bare `2` as `error` everywhere
        // would turn every honest numeric setting that happens to sit at 2 into
        // a severity, and `precision: 2 -> 0` in a codecov file is a display
        // setting.
        let view = ChangeView::new(vec![FileChange::modified(
            "codecov.yml",
            "coverage:\n  precision: 2\n",
            "coverage:\n  precision: 0\n",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert!(outcome.unassessed.is_empty(), "{outcome:?}");
    }

    #[test]
    fn a_threshold_a_formatter_split_over_lines_is_still_a_threshold() {
        // The same rule as `an_eslint_threshold_raised_inside_a_rule_fires`,
        // written the way a formatter writes it. The opening line's value came
        // back empty and was dropped, the `10` line has no separator on it, and
        // the whole rule was invisible.
        let base =
            "{\n  \"rules\": {\n    \"complexity\": [\n      \"error\",\n      10\n    ]\n  }\n}\n";
        let head =
            "{\n  \"rules\": {\n    \"complexity\": [\n      \"error\",\n      100\n    ]\n  }\n}\n";
        let view = ChangeView::new(vec![FileChange::modified(".eslintrc.json", base, head)]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(
            outcome.findings[0].detail.contains("rule allowance raised"),
            "{:?}",
            outcome.findings
        );
        // Reported where the rule is, not where the number is: the key names
        // the setting and the continuation lines do not.
        assert_eq!(outcome.findings[0].line, Some(3));
    }

    #[test]
    fn a_limit_behind_a_name_is_resolved_in_the_file_that_binds_it() {
        // Flat config is JavaScript and JavaScript configs bind their numbers.
        // The rule's own line is byte-identical on both sides, so every
        // comparison ran on values that had not changed.
        let view = ChangeView::new(vec![FileChange::modified(
            "eslint.config.js",
            "const LIMIT = 10;\nexport default [{ rules: { complexity: [\"error\", LIMIT] } }];\n",
            "const LIMIT = 100;\nexport default [{ rules: { complexity: [\"error\", LIMIT] } }];\n",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(
            outcome.findings[0].detail.contains("10 -> limit = 100"),
            "the finding has to say which number moved: {:?}",
            outcome.findings
        );
        // Lowering the same binding is a tightening.
        let view = ChangeView::new(vec![FileChange::modified(
            "eslint.config.js",
            "const LIMIT = 100;\nexport default [{ rules: { complexity: [\"error\", LIMIT] } }];\n",
            "const LIMIT = 10;\nexport default [{ rules: { complexity: [\"error\", LIMIT] } }];\n",
        )]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn a_limit_moved_behind_an_import_is_reported_rather_than_guessed() {
        // One level of resolution, and this is past it: the binding is in
        // another module and nothing here can evaluate it. Hiding a number
        // behind an import is the shape an evasion would take once the
        // resolution above exists, so it must not answer with silence.
        let view = ChangeView::new(vec![FileChange::modified(
            "eslint.config.js",
            "export default [{ rules: { complexity: [\"error\", 10] } }];\n",
            "import { LIMIT } from './limits';\nexport default [{ rules: { complexity: [\"error\", LIMIT] } }];\n",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert_eq!(outcome.unassessed.len(), 1, "{outcome:?}");
        assert!(outcome.unassessed[0].detail.contains("complexity"));
    }

    #[test]
    fn a_reference_this_change_did_not_touch_spends_no_caveat() {
        // The standing-state half, and the reason the caveat above is gated on
        // the reference having moved. A config that has always read
        // `["error", LIMIT]` and still does would otherwise carry a caveat on
        // every edit it ever receives, which is what makes `partial` worthless.
        let view = ChangeView::new(vec![FileChange::modified(
            "eslint.config.js",
            "export default [{ rules: { complexity: [\"error\", LIMIT], \"no-explicit-any\": \"warn\" } }];\n",
            "export default [{ rules: { complexity: [\"error\", LIMIT], \"no-explicit-any\": \"error\" } }];\n",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert!(outcome.unassessed.is_empty(), "{outcome:?}");
    }

    #[test]
    fn a_codecov_target_is_the_coverage_floor_it_is() {
        for (base, head) in [("80", "50"), ("80%", "50%"), ("\"80\"", "\"50\"")] {
            let view = ChangeView::new(vec![FileChange::modified(
                "codecov.yml",
                &format!("coverage:\n  status:\n    project:\n      target: {base}\n"),
                &format!("coverage:\n  status:\n    project:\n      target: {head}\n"),
            )]);
            let outcome = ThresholdConfigEdit.run(&view);
            assert!(outcome.fired, "{base} -> {head}: {outcome:?}");
            assert!(outcome.findings[0].detail.contains("floor lowered"));
        }
        // Raising it is the opposite of gaming it.
        let view = ChangeView::new(vec![FileChange::modified(
            "codecov.yml",
            "coverage:\n  status:\n    project:\n      target: 50\n",
            "coverage:\n  status:\n    project:\n      target: 80\n",
        )]);
        assert!(!ThresholdConfigEdit.run(&view).fired);
        // And `target` is TypeScript's language level, which is not a floor and
        // is not a number.
        let view = ChangeView::new(vec![FileChange::modified(
            "tsconfig.json",
            "{ \"compilerOptions\": { \"target\": \"es2022\" } }",
            "{ \"compilerOptions\": { \"target\": \"es2020\" } }",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert!(outcome.unassessed.is_empty(), "{outcome:?}");
    }

    #[test]
    fn a_number_a_syntax_decorated_is_still_a_number() {
        assert_eq!(number("10_000"), Some(10_000.0));
        assert_eq!(number("80%"), Some(80.0));
        assert_eq!(number("\"85\""), Some(85.0));
        assert_eq!(number("es2022"), None);
        assert_eq!(number("auto"), None);
        assert_eq!(number(""), None);
        assert_eq!(number("_"), None);
        // The `.andon.toml` case: a cap written with TOML's separator was not a
        // number, so raising it was a confident zero on this tool's own policy.
        let view = ChangeView::new(vec![FileChange::modified(
            ".andon.toml",
            "[loop]\niteration_cap = 10_000\n",
            "[loop]\niteration_cap = 20_000\n",
        )]);
        assert!(ThresholdConfigEdit.run(&view).fired);
    }

    #[test]
    fn a_shape_the_scanner_cannot_reach_is_reported_rather_than_answered() {
        // The seventh shape — the one nobody listed. A YAML block sequence has
        // no brackets to follow and no separator on the line carrying the
        // number, so no setting is produced and no rule above ever runs.
        let view = ChangeView::new(vec![FileChange::modified(
            ".eslintrc.yml",
            "rules:\n  complexity:\n    - error\n    - 10\n",
            "rules:\n  complexity:\n    - error\n    - 100\n",
        )]);
        let outcome = ThresholdConfigEdit.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert!(!outcome.unassessed.is_empty(), "{outcome:?}");
        assert!(
            outcome
                .unassessed
                .iter()
                .any(|f| f.detail.contains("- 100")),
            "the caveat has to name what went unread: {:?}",
            outcome.unassessed
        );
    }

    #[test]
    fn an_edit_the_scanner_did_read_spends_no_caveat_on_the_lines_around_it() {
        // The counterweight, over every shape the axis could have swallowed:
        // reindentation, a reordered exclusion block, an entry with a digit in
        // its path, a comment. None of these is a threshold and none may
        // produce one word of caveat.
        for (path, base, head) in [
            (
                "tsconfig.json",
                "{\n  \"compilerOptions\": {\n    \"strict\": true\n  }\n}\n",
                "{\n    \"compilerOptions\": {\n        \"strict\": true\n    }\n}\n",
            ),
            (
                ".coveragerc",
                "[run]\nomit =\n    tests/*\n    src/vendor2/*\n",
                "[run]\nomit =\n    src/vendor2/*\n    tests/*\n",
            ),
            (
                ".coveragerc",
                "[run]\nomit =\n    tests/*\n",
                "[run]\nomit =\n    tests/*\n    src/legacy2/*\n",
            ),
            (
                "codecov.yml",
                "ignore:\n  - vendor/**\n",
                "ignore:\n  - vendor/**\n  - src/billing2/**\n",
            ),
            (
                ".coveragerc",
                "[run]\nomit =\n    tests/*\n",
                "[run]\nomit =\n    # upstream covers it\n    tests/*\n",
            ),
        ] {
            let view = ChangeView::new(vec![FileChange::modified(path, base, head)]);
            let outcome = ThresholdConfigEdit.run(&view);
            assert!(!outcome.fired, "{path}: {outcome:?}");
            assert!(
                outcome.unassessed.is_empty(),
                "{path}: an ordinary edit spent a caveat, which is how `partial` \
                 stops meaning anything: {outcome:?}"
            );
        }
    }

    #[test]
    fn a_path_is_not_a_threshold_however_many_digits_it_has() {
        // What holds the axis above off every exclusion list in every config
        // file these detectors also read.
        for line in [
            "src/legacy2/*",
            "*/__init__.py",
            "- vendor/**",
            "\"src/generated2/**\",",
            "}",
            "],",
            "- es2022",
        ] {
            assert!(!carries_a_ranked_token(line), "{line}");
        }
        for line in ["- 100", "10", "\"error\",", "- true", "  0,"] {
            assert!(carries_a_ranked_token(line), "{line}");
        }
    }
}
