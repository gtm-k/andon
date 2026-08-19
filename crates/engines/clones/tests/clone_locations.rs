//! A duplication finding says where the duplication is.
//!
//! # What shipped, and why it made the headline metric the least useful one
//!
//! One duplication event produced five results. Four carried `path: null` and
//! all five carried `line_span: null`, so an agent reading the payload learned
//! that duplication happened and not where — and could do nothing about it. The
//! static engine, measured beside it in the same run, returns
//! `{"kind":"function","path":"src/inventory.ts","symbol":"allocate",
//! "line_span":{"start":17,"end":42}}` and was called the only fully actionable
//! output in the tool. Duplication is the signal the VISION leads with.
//!
//! # Which results get a location, and which must not
//!
//! | metric | scope | location |
//! |---|---|---|
//! | `clones.file-duplicated-tokens` | file | path, blob, and the longest unbroken duplicated stretch in that file |
//! | `clones.largest-clone-tokens` | change | path, blob, and the span of one side of the longest clone |
//! | `clones.duplicated-tokens` | change | none |
//! | `clones.duplicated-token-ratio` | change | none |
//! | `clones.clone-groups` | change | none |
//!
//! The last three are aggregates over the whole measured set. A total is about
//! every file at once, and naming one of them would be picking a scapegoat out
//! of a number that is not about it — the same fabrication the engine refuses
//! when it declines to emit a location for a change with no duplication at all.
//! `largest-clone-tokens` is different in kind: it reports a specific fragment,
//! and it was the one number here an agent could have acted on.
//!
//! # What is still missing, named rather than quietly half-shipped
//!
//! A clone has at least two sides and `ResultScope` has room for one path.
//! "Duplicated with `src/b.ts:12-40`" is what makes a duplication fixable. Both
//! sides are computed and reachable on `ClonesEngine::report()`; what is absent
//! is a field on the wire to carry the twin. That is P0-owned schema, so it is
//! routed rather than crammed into `symbol` — which is typed as a function or
//! class name and rendered as one by `agent_profile::render_scope`, so a
//! location there would be a lie in the shape of a field.

use andon_core::engine::{run_engine, MeasureContext};
use andon_core::policy::Policy;
use andon_core::schema::payload::{CompareContext, MeasurementResult, ScopeKind};
use andon_engine_clones::index::FileInput;
use andon_engine_clones::{syntax, ClonesEngine};

fn context() -> MeasureContext {
    MeasureContext {
        compare_context: CompareContext {
            base_oid: "0".repeat(40),
            head_oid: "1".repeat(40),
            git_version: "git version 2.51.0".to_string(),
            base_resolution: "explicit".to_string(),
        },
        policy: Policy::default(),
        changed_paths: Vec::new(),
        sandbox_available: false,
    }
}

fn input(path: &str, source: &str) -> FileInput {
    FileInput {
        path: path.to_string(),
        blob_oid: format!("{:040x}", syntax::fnv1a(source.as_bytes())),
        source: source.as_bytes().to_vec(),
    }
}

/// A block comfortably over the 50-token floor, eight lines long.
fn block(name: &str) -> String {
    format!(
        "export function {name}(items: number[], factor: number): number {{\n\
         \x20 let total = 0;\n\
         \x20 for (const item of items) {{\n\
         \x20   if (item > factor) {{ total += item * factor; }}\n\
         \x20   else {{ total -= item; }}\n\
         \x20 }}\n\
         \x20 return total;\n\
         }}\n"
    )
}

fn measure(inputs: Vec<FileInput>) -> Vec<MeasurementResult> {
    let engine = ClonesEngine::for_files(inputs, None).expect("measures");
    run_engine(&engine, &context()).expect("seals")
}

fn one<'a>(results: &'a [MeasurementResult], metric_id: &str) -> &'a MeasurementResult {
    results
        .iter()
        .find(|r| r.metric_id == metric_id)
        .unwrap_or_else(|| panic!("{metric_id} is emitted"))
}

#[test]
fn a_duplicated_file_says_which_lines_are_duplicated() {
    // The helper sits after a two-line header, so a span that merely defaulted
    // to the top of the file would pass by accident.
    let source = format!("// header\n// and another\n{}", block("shared"));
    let results = measure(vec![
        input("a.ts", &source),
        input("b.ts", &block("renamedEntirely")),
    ]);
    let file = results
        .iter()
        .find(|r| {
            r.metric_id == "clones.file-duplicated-tokens"
                && r.scope.path.as_deref() == Some("a.ts")
        })
        .expect("a.ts has a per-file result");

    let span = file
        .scope
        .line_span
        .expect("a file credited with duplicated tokens says where it is");
    assert!(
        span.start >= 3,
        "the duplicated helper starts after the two header lines, not at line \
         {} — a span anchored at the top of the file is not a location",
        span.start
    );
    assert!(span.end >= span.start, "{span:?}");
    assert!(
        span.end <= 10,
        "the file is ten lines long and the span must not run past it: {span:?}"
    );
    assert!(
        file.scope.blob_oid.is_some(),
        "the bytes the span indexes into are named alongside it"
    );
}

#[test]
fn the_longest_clone_says_where_it_is() {
    let results = measure(vec![
        input("a.ts", &block("one")),
        input("b.ts", &block("two")),
    ]);
    let largest = one(&results, "clones.largest-clone-tokens");
    assert_eq!(
        largest.scope.kind,
        ScopeKind::Change,
        "the question is still 'what is the longest clone in this change'"
    );
    let path = largest
        .scope
        .path
        .as_deref()
        .expect("the longest clone is a specific fragment and now names its file");
    assert!(path == "a.ts" || path == "b.ts", "{path}");
    let span = largest.scope.line_span.expect("and the lines it spans");
    assert_eq!(span.start, 1, "the block starts at line 1 in both files");
    assert_eq!(span.end, 8, "and ends at line 8");
    assert!(largest.scope.blob_oid.is_some());
}

#[test]
fn a_change_with_no_duplication_points_at_nothing() {
    // The location must be absent rather than a fabricated `1-1`. This is the
    // same rule as the counts': never a value for something that was not
    // measured.
    let results = measure(vec![
        input("a.ts", "export const config = { retries: 3, timeout: 1000 };\n"),
        input(
            "b.ts",
            "class Widget { constructor(private id: string) {} render(): string { return this.id; } }\n",
        ),
    ]);
    let largest = one(&results, "clones.largest-clone-tokens");
    assert_eq!(largest.scope.path, None, "{:?}", largest.scope);
    assert_eq!(largest.scope.line_span, None, "{:?}", largest.scope);
    for file in results
        .iter()
        .filter(|r| r.metric_id == "clones.file-duplicated-tokens")
    {
        assert_eq!(
            file.scope.line_span, None,
            "{:?} holds no duplication and must not claim a duplicated region",
            file.scope.path
        );
    }
}

#[test]
fn the_set_wide_totals_stay_locationless() {
    let results = measure(vec![
        input("a.ts", &block("one")),
        input("b.ts", &block("two")),
    ]);
    for metric in [
        "clones.duplicated-tokens",
        "clones.duplicated-token-ratio",
        "clones.clone-groups",
    ] {
        let scope = &one(&results, metric).scope;
        assert_eq!(scope.kind, ScopeKind::Change);
        assert_eq!(
            scope.path, None,
            "{metric} is a total over the measured set; naming one file would \
             point a number at a file it is not about"
        );
        assert_eq!(scope.line_span, None, "{metric}");
    }
}

#[test]
fn a_file_that_holds_a_copy_but_wins_no_group_still_gets_a_location() {
    // The case `groups` alone cannot answer, and the reason the span comes off
    // the coverage set. Five modules share a helper; two of them also share a
    // suffix, so the longer two-member group wins the region and the
    // five-member group is dropped from the report entirely. The other three
    // modules are still nothing but duplicated code.
    let helper = block("shared");
    let suffix = "\nexport function extra(x: number): number {\n  const y = x * 2;\n  const z = y + 3;\n  return z - 1;\n}\n";
    let inputs: Vec<FileInput> = (0..5)
        .map(|n| {
            let source = if n < 2 {
                format!("{helper}{suffix}")
            } else {
                helper.clone()
            };
            input(&format!("m{n}.ts"), &source)
        })
        .collect();
    let results = measure(inputs);
    for n in 0..5 {
        let path = format!("m{n}.ts");
        let file = results
            .iter()
            .find(|r| {
                r.metric_id == "clones.file-duplicated-tokens"
                    && r.scope.path.as_deref() == Some(path.as_str())
            })
            .expect("every measured file has a per-file result");
        assert!(
            file.scope.line_span.is_some(),
            "{path} is credited with duplicated tokens and must say where: \
             {:?}",
            file.scope
        );
    }
}

#[test]
fn two_machines_name_the_same_side_of_the_same_clone() {
    // `scope` is inside the per-result digest and is the pairing key in
    // `compare::classify`, so a location that depended on iteration order would
    // turn an honest recompute into an unpaired result or a divergence.
    let forward = measure(vec![
        input("z.ts", &block("one")),
        input("a.ts", &block("two")),
        input("m.ts", &block("three")),
    ]);
    let backward = measure(vec![
        input("m.ts", &block("three")),
        input("a.ts", &block("two")),
        input("z.ts", &block("one")),
    ]);
    let scopes = |results: &[MeasurementResult]| -> Vec<String> {
        results
            .iter()
            .map(|r| format!("{}::{:?}", r.metric_id, r.scope))
            .collect()
    };
    assert_eq!(scopes(&forward), scopes(&backward));
}
