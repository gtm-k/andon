//! Coverage configuration that excludes more than it did.
//!
//! Widening an exclusion list raises the coverage number without testing
//! anything. It is the quietest of the seven: the diff is one line in a config
//! file nobody reviews closely, and the effect is on a metric everybody reads.
//!
//! # Scanned, not parsed
//!
//! Coverage exclusions live in `.coveragerc` (INI), `pyproject.toml`,
//! `package.json`, `jest.config.js` (JavaScript), `codecov.yml`, `.nycrc`,
//! `tox.ini`, `tarpaulin.toml` and `vitest.config.ts` — a syntax per tool for
//! one idea. What the detector needs from all of them is the same: *which
//! patterns are excluded*, which is the list of entries under a key whose name
//! says it excludes. [`crate::config`] does the reading and explains why it is a
//! scanner rather than eight parsers.
//!
//! The bluntness is bounded by the file list: only files that are coverage
//! configuration are examined at all, so a `src/exclude.ts` cannot fire this.
//!
//! # Neither list is a list of names any more
//!
//! Both the files and the keys were arrays of exact spellings, and both had the
//! same hole in them. `.nycrc` and `.nycrc.json` were in the file list and
//! `.nycrc.yml` was not, though nyc reads all three; `exclude` was in the key
//! list and tarpaulin's own `exclude_files` was not, though this detector reads
//! `tarpaulin.toml`. Each gap returned `{flag: false, magnitude: 0,
//! completeness: "complete"}` on a format the detector says it recognises,
//! which is the confident missed detection the completeness vocabulary exists
//! to prevent. Files are now matched by the tool's stem, read against the
//! syntaxes that tool reads ([`config::Tool`]), and keys by what their name says
//! (`EXCLUSION_KEY_FRAGMENTS`), so the eighth spelling of each is covered
//! before it is written.
//!
//! # Only widening fires
//!
//! Removing an exclusion is reported as a negative magnitude and does not fire.
//! A project tightening its coverage configuration is doing the opposite of
//! gaming it.
//!
//! # Counting entries was not counting exclusion
//!
//! The first version of this detector answered "how many patterns are excluded",
//! and that is not the question. Changing `.nycrc.json` from excluding
//! `src/generated/**` to excluding `src/**` takes the whole source tree out of
//! coverage and leaves the count at one — and the detector returned
//! `{flag: false, magnitude: 0, completeness: "complete"}`, which is a confident
//! zero on the plainest form of the thing it exists to catch. The same edit in
//! `.coveragerc` did the same. Nothing was wrong with the reading: the identical
//! file fires correctly when an entry is *added*. The model was wrong — it
//! measured cardinality where the signal is breadth.
//!
//! So a replacement is now ranked as well as counted, by `covers`, and the
//! replacements `covers` cannot rank are reported as unassessed rather than as
//! nothing (see [`crate::detectors::Outcome::unassessed`]).

use crate::change::ChangeView;
use crate::config::{self, tools};
use crate::detectors::{Detector, Finding, Outcome};
use andon_core::schema::enums::TamperSignal;

/// The detector.
pub struct CoverageExclusionDrift;

/// Key-name fragments whose value is a list of exclusion patterns.
///
/// # Fragments, because the exact list had the same hole the file list did
///
/// `tarpaulin.toml` is coverage configuration this detector reads, and
/// tarpaulin's own file-exclusion key is `exclude_files`. That was not in the
/// exact list, so an edit widening it came back
/// `{flag: false, magnitude: 0, completeness: "complete"}` — a confident zero
/// inside a format the detector declares it recognises, which is worse than not
/// reading the file at all. `sonar.coverage.exclusions` was the same shape.
///
/// Matching is `contains`, so a key whose *own name* says it excludes is read
/// however the tool spells it: `exclude`, `excludes`, `exclude_files`,
/// `exclude-files`, `exclude_lines`, `exclude_also`, `exclude_dirs`,
/// `exclusions`, `coverage_exclusions`, `omit`, `ignore`, `ignores`,
/// `coveragePathIgnorePatterns`, `testPathIgnorePatterns`, `skip_covered` — and
/// the eighth spelling, which exists and has not been written down yet.
///
/// The bound is still the file list: a key called `ignore` reaches here only in
/// a file whose name says it is coverage configuration.
const EXCLUSION_KEY_FRAGMENTS: &[&str] = &["exclude", "exclusion", "omit", "ignore", "skip"];

/// Key-name fragments whose value is a list of the sources coverage is measured
/// *over*, where a leading `!` is what takes something out of it.
///
/// # An exclusion does not have to be spelled in an exclusion list
///
/// Jest's `collectCoverageFrom` names what coverage collects, and the way to
/// remove a directory from it is to add `"!src/payments/**"`. That is the same
/// move as adding the same path to `coveragePathIgnorePatterns` — the number on
/// the dashboard rises and nothing was tested — and it happened in a key this
/// detector had no name for, so it came back
/// `{flag: false, magnitude: 0, completeness: "complete"}`.
///
/// Reading the key as an ordinary exclusion list would have been worse than not
/// reading it: its entries are *inclusions*, so a project adding `src/api/**` to
/// what it measures would have fired as an exclusion added — a tamper signal on
/// a tightening. Only the negated entries are exclusions, and they are recorded
/// with the `!` taken off so [`covers`] can rank one against another.
///
/// The same rule runs the other way in an exclusion list, where `!` re-includes:
/// `!src/api/**` inside `exclude` is not an exclusion and is dropped.
const INCLUSION_KEY_FRAGMENTS: &[&str] = &["include", "inclusion", "collectcoveragefrom", "source"];

/// What a key's entries are: patterns taken out of coverage, or patterns
/// coverage is taken over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sense {
    /// The entries are exclusions; a `!` entry is a re-inclusion.
    Exclusion,
    /// The entries are inclusions; only a `!` entry is an exclusion.
    Inclusion,
}

const EXCLUSION: Sense = Sense::Exclusion;

/// Which sense a key's list is in, or `None` when its name says neither.
///
/// Exclusion first: a key that reads both ways is an exclusion list, which is
/// this detector's own subject and the stricter reading of the two.
fn sense_of(key: &str) -> Option<Sense> {
    if EXCLUSION_KEY_FRAGMENTS.iter().any(|f| key.contains(f)) {
        return Some(Sense::Exclusion);
    }
    INCLUSION_KEY_FRAGMENTS
        .iter()
        .any(|f| key.contains(f))
        .then_some(Sense::Inclusion)
}

/// The exclusion patterns in a value, given which sense its key is in.
fn entries_under(sense: Sense, value: &str) -> impl Iterator<Item = String> + use<> {
    config::entries(value).into_iter().filter_map(move |entry| {
        match (sense, entry.strip_prefix('!')) {
            // `!` in an exclusion list puts something back; it excludes nothing.
            (Sense::Exclusion, Some(_)) => None,
            (Sense::Exclusion, None) => Some(entry),
            // `!` in an inclusion list is the only thing that excludes.
            (Sense::Inclusion, Some(negated)) => Some(negated.to_string()),
            (Sense::Inclusion, None) => None,
        }
    })
}

/// The tools whose configuration carries coverage exclusions.
///
/// Which tools, not which file names: [`config::tools`] holds the names, and
/// [`config::Tool`] says why one place holds them for both detectors.
const COVERAGE_TOOLS: &[config::Tool] = &[
    tools::COVERAGERC,
    tools::CODECOV,
    tools::CODECOV_DOT,
    tools::NYCRC,
    tools::C8RC,
    tools::TARPAULIN,
    tools::PYPROJECT,
    // Sonar's `sonar.coverage.exclusions` takes whole directories out of the
    // number the dashboard shows, which is the same move in a file this
    // detector was not reading at all.
    tools::SONAR,
    tools::JEST,
    tools::VITEST,
    tools::NYC_CONFIG,
    tools::SETUP_CFG,
    tools::PACKAGE_JSON,
    // coverage.py reads `[coverage:run]` out of `tox.ini` exactly as it reads
    // `[run]` out of `.coveragerc`; the identical block in `setup.cfg` fired
    // and this one was silent.
    tools::TOX_INI,
];

/// Whether a path is a coverage configuration file.
pub fn is_coverage_config(path: &str) -> bool {
    config::names_one_of(path, COVERAGE_TOOLS)
}

impl Detector for CoverageExclusionDrift {
    fn signal(&self) -> TamperSignal {
        TamperSignal::CoverageExclusionDrift
    }

    fn metric_id(&self) -> &'static str {
        "tamper.coverage-exclusion-drift"
    }

    fn magnitude_metric_id(&self) -> &'static str {
        "tamper.coverage-exclusion-drift.magnitude"
    }

    fn describes(&self) -> &'static str {
        "coverage configuration excluding more paths or lines than it did"
    }

    fn run(&self, change: &ChangeView) -> Outcome {
        let mut delta = 0i64;
        let mut broadened = 0i64;
        let mut findings = Vec::new();
        let mut unassessed = Vec::new();
        for file in &change.files {
            if file.content_unchanged() || !is_coverage_config(&file.path) {
                continue;
            }
            let base = exclusions(file.base_bytes());
            let head = exclusions(file.head_bytes());
            let file_delta = head.len() as i64 - base.len() as i64;
            delta += file_delta;

            // Multiset difference both ways, so a reordered list is no
            // difference at all and a replacement leaves one entry on each
            // side to be compared against the other.
            let mut removed = base.clone();
            let mut added = Vec::new();
            for (line, entry) in &head {
                match removed.iter().position(|(_, e)| e == entry) {
                    Some(pos) => {
                        removed.remove(pos);
                    }
                    None => added.push((*line, entry.clone())),
                }
            }

            // Each added entry is classified once, in this order: a pattern
            // that swallows one the change dropped is a widening whatever the
            // count did; otherwise a net rise in the count is an addition;
            // otherwise the list was rewritten in a way this detector cannot
            // rank, and saying so is the whole point.
            for (line, entry) in &added {
                if let Some((_, swallowed)) = removed.iter().find(|(_, gone)| covers(entry, gone)) {
                    broadened += 1;
                    findings.push(Finding::at(
                        &file.path,
                        *line,
                        format!("coverage exclusion broadened: {swallowed} -> {entry}"),
                    ));
                } else if file_delta > 0 {
                    findings.push(Finding::at(
                        &file.path,
                        *line,
                        format!("coverage exclusion added: {entry}"),
                    ));
                } else {
                    unassessed.push(Finding::at(
                        &file.path,
                        *line,
                        format!(
                            "coverage exclusion replaced by {entry} and this detector cannot \
                             rank the two: neither pattern is anchored above the other, so \
                             whether the new one excludes more code is not decidable from \
                             the text"
                        ),
                    ));
                }
            }
        }
        // Magnitude counts both routes to the same thing. They cannot
        // double-count: a broadening consumes an entry the change removed, and
        // a net rise is measured over entries that replaced nothing.
        let magnitude = delta + broadened;
        if delta > 0 || broadened > 0 {
            Outcome::fired(magnitude, findings).with_unassessed(unassessed)
        } else {
            Outcome::quiet(magnitude).with_unassessed(unassessed)
        }
    }
}

/// Whether the exclusion pattern `added` takes out everything `removed` did,
/// and more.
///
/// # A prefix test, not a glob engine
///
/// The six syntaxes this detector reads are consumed by six tools whose glob
/// semantics disagree — coverage.py's `*` crosses directory separators and
/// minimatch's does not — so a general subsumption decision would have to know
/// which tool reads the file, and would be wrong for one of them anyway. What is
/// true in all of them is narrower and enough: a pattern **anchored at a
/// strictly shallower directory** that then reaches downward with a
/// directory-spanning wildcard covers everything the deeper one did.
/// `src/**` against `src/generated/**` is that shape, and it is the shape the
/// evasion takes, because widening an exclusion means moving its anchor up.
///
/// Deliberately conservative in both directions:
///
/// - `src/*.ts` does not qualify as reaching downward — its tail is `*.ts`, and
///   whether that crosses a directory depends on the tool. It becomes an
///   unranked replacement instead of a firing.
/// - `*/__init__.py` -> `*/conftest.py` is not a widening: neither is anchored
///   at all, so neither contains the other. This is a real should-pass case in
///   the frozen corpus, and a rule keyed on "the text changed" would fire on it.
///
/// The one unanchored pattern that *is* ranked is a pattern that is nothing but
/// wildcards and separators — `*`, `**`, `**/*` — which excludes the repository
/// and cannot be narrower than anything.
fn covers(added: &str, removed: &str) -> bool {
    if added == removed {
        return false;
    }
    let (anchor, tail) = split_at_first_wildcard(added);
    // The tail has to reach down into whatever the anchor names: `**` at any
    // depth, or a `*` that is the whole of the rest.
    if !(tail.starts_with("**") || tail == "*") {
        return false;
    }
    if anchor.is_empty() {
        return all_wildcard(added) && !all_wildcard(removed);
    }
    let (removed_anchor, _) = split_at_first_wildcard(removed);
    removed_anchor.starts_with(anchor) && removed_anchor.len() > anchor.len()
}

/// A pattern split into the literal part before its first wildcard and the rest.
fn split_at_first_wildcard(pattern: &str) -> (&str, &str) {
    match pattern.find(['*', '?']) {
        Some(at) => pattern.split_at(at),
        None => (pattern, ""),
    }
}

/// Whether a pattern is nothing but wildcards and separators.
fn all_wildcard(pattern: &str) -> bool {
    !pattern.is_empty() && pattern.chars().all(|c| matches!(c, '*' | '?' | '/'))
}

/// `(1-based line, entry text)` for every exclusion pattern in a config file.
///
/// Four shapes, one reader: an inline list (`exclude = ["a", "b"]`, including
/// the single-line JSON these files are often written as), a continued block
/// (`omit =` followed by indented lines), a YAML sequence (`ignore:` followed
/// by `- a`), and a bracketed list the file breaks over several lines. See
/// [`crate::config`] for why this is a scanner and not five parsers.
///
/// # The block rule was an indentation rule, and JSON has no indentation rule
///
/// A list continued a block while the following lines were indented deeper
/// than the key's, which is how INI and YAML write one and is not a rule JSON
/// has to obey. So
///
/// ```text
/// {
/// "exclude": [
/// "src/generated/**"
/// ]
/// }
/// ```
///
/// — valid JSON, and what a machine-written `.nycrc` looks like — read as a key
/// that opened a block and no entries at all, and widening that exclusion to
/// `src/**` came back `{flag: false, magnitude: 0, completeness: "complete"}`.
/// The unfinished sibling did the same for a different reason: `"exclude": ["a",`
/// leaves a *non-empty* truncated value, so no block opened either.
///
/// A bracket is its own continuation rule, and a stronger one than indentation:
/// the list ends where it closes. Both are read — the bracket where there is
/// one, the indentation where there is not — because `omit =` in a `.coveragerc`
/// has no brackets to close and never will.
fn exclusions(source: &[u8]) -> Vec<(u32, String)> {
    let text = String::from_utf8_lossy(source);
    let mut out = Vec::new();
    // `(the key's indentation, brackets it left open)`.
    let mut block: Option<(usize, i32)> = None;

    for (index, raw) in text.lines().enumerate() {
        let line_no = index as u32 + 1;
        let indent = raw.len() - raw.trim_start().len();
        if config::is_noise(raw) {
            continue;
        }

        // A block continues while its brackets are open, or — where it opened
        // none — while the indentation stays deeper than the key's.
        if let Some((key_indent, depth)) = block {
            if depth > 0 {
                let still_open = depth + config::bracket_delta(raw);
                block = (still_open > 0).then_some((key_indent, still_open));
                // The closing line is read too. A pattern can share it —
                // `"src/**"]` — and `config::entries` drops the bracket.
                out.extend(entries_under(EXCLUSION, raw.trim()).map(|e| (line_no, e)));
                continue;
            }
            if indent > key_indent {
                out.extend(entries_under(EXCLUSION, raw.trim()).map(|e| (line_no, e)));
                continue;
            }
            block = None;
        }

        let mut opened_block: Option<i32> = None;
        for pair in config::pairs(raw) {
            let Some(sense) = sense_of(&pair.key) else {
                continue;
            };
            // A key opens a block when it has nothing after it, and also when
            // what it has does not close. The first is keyed on the value being
            // empty rather than on it yielding no entries: `ignore_errors =
            // True` yields none — `config::entries` drops booleans — and
            // reading that as an opened block swallowed every indented line
            // after it as an exclusion pattern.
            let unfinished = config::bracket_delta(&pair.value) > 0;
            if pair.value.is_empty() || unfinished {
                opened_block = Some(if unfinished {
                    config::bracket_delta(&pair.value)
                } else {
                    config::bracket_delta(raw).max(0)
                });
            }
            if !pair.value.is_empty() {
                out.extend(entries_under(sense, &pair.value).map(|e| (line_no, e)));
            }
        }
        if let Some(depth) = opened_block {
            block = Some((indent, depth));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::FileChange;

    #[test]
    fn an_added_omit_pattern_fires() {
        let base = "[run]\nomit =\n    tests/*\n";
        let head = "[run]\nomit =\n    tests/*\n    src/payments/*\n";
        let view = ChangeView::new(vec![FileChange::modified(".coveragerc", base, head)]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 1);
        assert!(outcome.findings[0].detail.contains("src/payments/*"));
    }

    #[test]
    fn an_inline_list_is_read_too() {
        let base = "{ \"jest\": { \"coveragePathIgnorePatterns\": [\"/node_modules/\"] } }";
        let head =
            "{ \"jest\": { \"coveragePathIgnorePatterns\": [\"/node_modules/\", \"/src/legacy/\"] } }";
        let view = ChangeView::new(vec![FileChange::modified("package.json", base, head)]);
        assert!(CoverageExclusionDrift.run(&view).fired);
    }

    #[test]
    fn a_yaml_sequence_is_read_too() {
        let base = "coverage:\n  status: project\nignore:\n  - vendor/**\n";
        let head = "coverage:\n  status: project\nignore:\n  - vendor/**\n  - src/billing/**\n";
        let view = ChangeView::new(vec![FileChange::modified("codecov.yml", base, head)]);
        assert!(CoverageExclusionDrift.run(&view).fired);
    }

    #[test]
    fn removing_an_exclusion_is_quiet_and_negative() {
        let base = "[run]\nomit =\n    tests/*\n    src/legacy/*\n";
        let head = "[run]\nomit =\n    tests/*\n";
        let view = ChangeView::new(vec![FileChange::modified(".coveragerc", base, head)]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(!outcome.fired);
        assert_eq!(outcome.magnitude, -1);
    }

    #[test]
    fn a_non_coverage_file_named_exclude_does_not_fire() {
        let base = "export const exclude = ['a'];\n";
        let head = "export const exclude = ['a', 'b', 'c'];\n";
        let view = ChangeView::new(vec![FileChange::modified("src/exclude.ts", base, head)]);
        assert!(!CoverageExclusionDrift.run(&view).fired);
    }

    #[test]
    fn editing_a_non_exclusion_key_does_not_fire() {
        let base = "[run]\nbranch = true\nomit =\n    tests/*\n";
        let head = "[run]\nbranch = false\nsource = src\nomit =\n    tests/*\n";
        let view = ChangeView::new(vec![FileChange::modified(".coveragerc", base, head)]);
        assert!(!CoverageExclusionDrift.run(&view).fired);
    }

    #[test]
    fn a_new_config_with_no_exclusions_does_not_fire() {
        let view = ChangeView::new(vec![FileChange::added(
            ".coveragerc",
            "[run]\nbranch = true\nsource = src\n",
        )]);
        assert!(!CoverageExclusionDrift.run(&view).fired);
    }

    #[test]
    fn an_exclusion_widened_in_place_fires_although_the_count_did_not_move() {
        // The UAT case, verbatim: `.nycrc.json` goes from excluding one
        // generated directory to excluding the whole source tree, and the entry
        // count stays at one. This returned `{false, 0, complete}` — a confident
        // zero on the plainest form of the evasion.
        let base = "{\n  \"exclude\": [\"src/generated/**\"]\n}\n";
        let head = "{\n  \"exclude\": [\"src/**\"]\n}\n";
        let view = ChangeView::new(vec![FileChange::modified(".nycrc.json", base, head)]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 1);
        assert!(
            outcome.findings[0]
                .detail
                .contains("src/generated/** -> src/**"),
            "the finding must name both sides, or it cannot be acted on: {:?}",
            outcome.findings
        );
        assert!(
            outcome.unassessed.is_empty(),
            "a ranked widening is not an unranked one"
        );
    }

    #[test]
    fn the_same_widening_in_the_ini_syntax_fires_too() {
        // Reported for `.coveragerc` alongside the `.nycrc.json` case. Same
        // model gap, different syntax — which is what proves the gap was the
        // model and not the reading.
        let base = "[run]\nomit =\n    src/generated/*\n";
        let head = "[run]\nomit =\n    src/*\n";
        let view = ChangeView::new(vec![FileChange::modified(".coveragerc", base, head)]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 1);
    }

    #[test]
    fn narrowing_an_exclusion_stays_quiet() {
        // The direction gate. A project taking generated code back out of its
        // exclusions is doing the opposite of gaming, and a rule that only
        // noticed "the anchor moved" would fire on both.
        let base = "{\n  \"exclude\": [\"src/**\"]\n}\n";
        let head = "{\n  \"exclude\": [\"src/generated/**\"]\n}\n";
        let view = ChangeView::new(vec![FileChange::modified(".nycrc.json", base, head)]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
    }

    #[test]
    fn a_bare_wildcard_is_the_widest_exclusion_there_is() {
        let base = "{\n  \"exclude\": [\"src/generated/**\"]\n}\n";
        let head = "{\n  \"exclude\": [\"**\"]\n}\n";
        let view = ChangeView::new(vec![FileChange::modified(".nycrc.json", base, head)]);
        assert!(CoverageExclusionDrift.run(&view).fired);
    }

    #[test]
    fn a_replacement_that_cannot_be_ranked_is_reported_as_unranked_not_as_nothing() {
        // Neither pattern is anchored, so neither contains the other and no
        // honest answer exists in the text. This is a should-pass case in the
        // frozen corpus and it must stay quiet — but quiet and `complete` are
        // different claims, and only one of them is true here.
        let base = "[run]\nomit =\n    tests/*\n    */__init__.py\n";
        let head = "[run]\nomit =\n    tests/*\n    */conftest.py\n";
        let view = ChangeView::new(vec![FileChange::modified(".coveragerc", base, head)]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 0);
        assert_eq!(outcome.unassessed.len(), 1, "{outcome:?}");
        assert!(outcome.unassessed[0].detail.contains("*/conftest.py"));
    }

    #[test]
    fn a_reordered_list_is_neither_a_finding_nor_an_unranked_one() {
        // The entries are a multiset, so moving them changes nothing and must
        // not spend a caveat either.
        let base = "[run]\nomit =\n    tests/*\n    */__init__.py\n    src/vendor/*\n";
        let head = "[run]\nomit =\n    src/vendor/*\n    tests/*\n    */__init__.py\n";
        let view = ChangeView::new(vec![FileChange::modified(".coveragerc", base, head)]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(!outcome.fired);
        assert!(outcome.unassessed.is_empty(), "{outcome:?}");
    }

    #[test]
    fn tightening_the_list_is_understood_and_not_merely_unranked() {
        // Entries removed and none added: nothing to rank, so no caveat. A
        // detector that marked every edit unassessed would make `partial` the
        // standing state and the caveat worthless.
        let base = "[run]\nomit =\n    tests/*\n    src/legacy/*\n";
        let head = "[run]\nomit =\n    tests/*\n";
        let outcome = CoverageExclusionDrift.run(&ChangeView::new(vec![FileChange::modified(
            ".coveragerc",
            base,
            head,
        )]));
        assert!(!outcome.fired);
        assert_eq!(outcome.magnitude, -1);
        assert!(outcome.unassessed.is_empty(), "{outcome:?}");
    }

    #[test]
    fn a_tools_own_exclusion_key_is_read_however_it_spells_it() {
        // `tarpaulin.toml` was in the file list and read; `exclude_files` is
        // tarpaulin's actual file-exclusion setting and was not in the key list,
        // so widening it came back `{flag: false, magnitude: 0, completeness:
        // "complete"}` — a confident zero inside a format this detector says it
        // recognises, which is worse than not opening the file.
        for key in ["exclude_files", "exclude-files"] {
            let base = format!("[report]\n{key} = [\"src/generated/*\"]\n");
            let head = format!("[report]\n{key} = [\"src/*\"]\n");
            let view = ChangeView::new(vec![FileChange::modified("tarpaulin.toml", &base, &head)]);
            let outcome = CoverageExclusionDrift.run(&view);
            assert!(outcome.fired, "{key}: {outcome:?}");
            assert_eq!(outcome.magnitude, 1, "{key}");
        }
        // And the key nobody has written down yet, which is the point of
        // matching what the name says rather than a list of names.
        let view = ChangeView::new(vec![FileChange::modified(
            ".nycrc.json",
            "{ \"coverageExcludePatterns\": [\"src/generated/**\"] }",
            "{ \"coverageExcludePatterns\": [\"src/**\"] }",
        )]);
        assert!(CoverageExclusionDrift.run(&view).fired);
    }

    #[test]
    fn every_spelling_of_one_tools_configuration_is_that_tool_s_configuration() {
        // nyc reads its rc file in four syntaxes and c8 in three; the list held
        // some of each. The stem is the tool, and the extension is how the
        // repository chose to write it.
        for path in [
            ".nycrc",
            ".nycrc.json",
            ".nycrc.yml",
            ".nycrc.yaml",
            ".c8rc",
            ".c8rc.json",
            "packages/api/.nycrc.json5",
        ] {
            assert!(is_coverage_config(path), "{path}");
        }
        assert!(is_coverage_config("tox.ini"), "coverage.py reads it");
        assert!(is_coverage_config("sonar-project.properties"));
        // The bound that keeps the scanner off source files.
        for path in ["src/exclude.ts", "src/setup.ts", "src/nycrc.ts"] {
            assert!(!is_coverage_config(path), "{path}");
        }
    }

    #[test]
    fn a_boolean_under_an_exclusion_shaped_key_does_not_swallow_what_follows() {
        // `config::entries` drops booleans, so `ignore_errors = True` yielded no
        // entries — and a key with no entries was read as one that opens an
        // indented block, which then ate every following line as an exclusion
        // pattern. Latent while the key list was exact; live the moment keys are
        // matched by what their name says.
        let base = "[report]\nignore_errors = True\nprecision = 2\nshow_missing = True\n";
        let head = "[report]\nignore_errors = True\nprecision = 2\nshow_missing = False\n";
        let view = ChangeView::new(vec![FileChange::modified(".coveragerc", base, head)]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 0);
        assert!(outcome.unassessed.is_empty(), "{outcome:?}");
    }

    #[test]
    fn covers_ranks_only_what_it_can_defend() {
        // The rule in isolation, because it is the one piece of judgement in
        // this detector and the corpus exercises only some of its arms.
        assert!(covers("src/**", "src/generated/**"));
        assert!(covers("src/*", "src/generated/*"));
        assert!(covers("**", "src/generated/**"));
        assert!(covers("src/vendor/**", "src/vendor/lib/**"));
        // Narrower, or unrelated, or unanchored on both sides.
        assert!(!covers("src/generated/**", "src/**"));
        assert!(!covers("src/a/**", "src/b/**"));
        assert!(!covers("*/conftest.py", "*/__init__.py"));
        assert!(!covers("src/**", "src/**"));
        // Anchored above, but the tail does not reach downward in every glob
        // dialect these files are read by, so it is not ranked either way.
        assert!(!covers("src/*.ts", "src/generated/*.ts"));
    }

    #[test]
    fn a_list_json_wrote_without_indentation_is_still_a_list() {
        // The block rule was an indentation rule, and JSON has no indentation
        // rule. This is valid JSON and what a machine writes; it read as a key
        // that opened a block and no entries at all.
        let view = ChangeView::new(vec![FileChange::modified(
            ".nycrc.json",
            "{\n\"exclude\": [\n\"src/generated/**\"\n]\n}\n",
            "{\n\"exclude\": [\n\"src/**\"\n]\n}\n",
        )]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("broadened"));
    }

    #[test]
    fn a_list_that_does_not_finish_on_its_own_line_is_still_a_list() {
        // The unfinished sibling: the value is non-empty and truncated, so no
        // block opened either, and the entry after the break was never read.
        let view = ChangeView::new(vec![FileChange::modified(
            ".nycrc.json",
            "{\n  \"exclude\": [\"vendor/**\",\n    \"src/generated/**\"]\n}\n",
            "{\n  \"exclude\": [\"vendor/**\",\n    \"src/**\"]\n}\n",
        )]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("broadened"));
    }

    #[test]
    fn an_indented_list_still_reports_its_entry_where_the_entry_is() {
        // The bracket rule runs beside the indentation rule and must not move
        // the location: a reader opens the file at the pattern, not at the key.
        let view = ChangeView::new(vec![FileChange::modified(
            ".coveragerc",
            "[run]\nomit =\n    tests/*\n",
            "[run]\nomit =\n    tests/*\n    src/payments/*\n",
        )]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert_eq!(outcome.findings[0].line, Some(4));
    }

    #[test]
    fn an_inclusion_list_narrowed_by_a_negation_fires() {
        // Jest's `collectCoverageFrom` names what coverage collects, and `!` is
        // how a directory leaves it. Same move as widening an ignore list, in a
        // key this detector had no name for.
        let view = ChangeView::new(vec![FileChange::modified(
            "jest.config.js",
            "module.exports = { collectCoverageFrom: [\"src/**/*.ts\", \"!src/generated/**\"] };\n",
            "module.exports = { collectCoverageFrom: [\"src/**/*.ts\", \"!src/**\"] };\n",
        )]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert!(outcome.findings[0].detail.contains("broadened"));

        // And a negation that was not there before is an exclusion added.
        let view = ChangeView::new(vec![FileChange::modified(
            "jest.config.js",
            "module.exports = { collectCoverageFrom: [\"src/**/*.ts\"] };\n",
            "module.exports = { collectCoverageFrom: [\"src/**/*.ts\", \"!src/payments/**\"] };\n",
        )]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 1);
    }

    #[test]
    fn an_inclusion_list_that_grows_is_measuring_more_and_not_less() {
        // The half that reading `collectCoverageFrom` as an ordinary exclusion
        // list would have failed: its entries are inclusions, so a project
        // adding a directory to what it measures would have fired as an
        // exclusion added — a tamper signal on a tightening.
        let view = ChangeView::new(vec![FileChange::modified(
            "jest.config.js",
            "module.exports = { collectCoverageFrom: [\"src/api/**\"] };\n",
            "module.exports = { collectCoverageFrom: [\"src/api/**\", \"src/web/**\"] };\n",
        )]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 0);
    }

    #[test]
    fn a_negation_inside_an_exclusion_list_excludes_nothing() {
        // The same rule the other way round. In `exclude` a `!` puts something
        // back, so adding one is a tightening and counting it as an exclusion
        // would fire on it.
        let view = ChangeView::new(vec![FileChange::modified(
            ".nycrc.json",
            "{ \"exclude\": [\"src/generated/**\"] }",
            "{ \"exclude\": [\"src/generated/**\", \"!src/generated/keep.ts\"] }",
        )]);
        let outcome = CoverageExclusionDrift.run(&view);
        assert!(!outcome.fired, "{outcome:?}");
        assert_eq!(outcome.magnitude, 0);
    }
}
