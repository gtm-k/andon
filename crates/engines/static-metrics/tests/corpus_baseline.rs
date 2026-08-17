//! "Re-run the corpus per grammar bump", enforced at zero CI cost.
//!
//! PLAN P2 requires the parse-health corpus job to re-run whenever a grammar
//! moves. The obvious mechanism — a `push` path filter on the workflow — is both
//! too weak and too expensive: it fires on every commit that touches the engine
//! crate, which during this phase is every commit, and it does not fire at all
//! when a *transitive* change moves the grammar. It also cannot tell whether
//! anybody looked at the result.
//!
//! So the enforcement is here instead. `fixtures/parse-corpus/baseline.toml`
//! records the regime the last green corpus run was taken under, and this test
//! fails when that stamp and the engine's current regime disagree. Bumping a
//! grammar, or the tree-sitter runtime, or `SPEC_REVISION`, turns the ordinary
//! `cargo test` red on every push until the corpus job has been dispatched and
//! its fresh baseline committed. The expensive job itself stays on
//! `workflow_dispatch`, which is user decision D2.

use andon_static_metrics::{corpus, engine, Language};

#[test]
fn the_recorded_baseline_was_taken_under_the_regime_in_force() {
    let baseline = corpus::load_baseline(&corpus::baseline_path())
        .expect("fixtures/parse-corpus/baseline.toml must exist and parse");
    assert_eq!(
        baseline.regime,
        engine::regime_stamp(),
        "\nThe parse-health baseline was recorded under a different regime from \
         the one this build reports.\n\
         \n\
         A grammar, the tree-sitter runtime, or SPEC_REVISION has moved. Parse \
         health is a property of the grammar, so the recorded ERROR-node rates \
         no longer describe this build and the corpus has to be re-run:\n\
         \n\
         1. dispatch .github/workflows/parse-corpus.yml\n\
         2. commit the baseline.toml it uploads as an artifact\n\
         \n\
         This is PLAN P2's \"re-run per grammar bump\", enforced where it costs \
         nothing rather than in a workflow trigger nobody reads."
    );
}

#[test]
fn the_baseline_covers_every_language_the_corpus_declares() {
    let manifest = corpus::load(&corpus::manifest_path()).expect("the corpus manifest loads");
    let baseline = corpus::load_baseline(&corpus::baseline_path()).expect("the baseline loads");
    for repo in &manifest.repos {
        for language in &repo.languages {
            assert!(
                baseline.languages.iter().any(|row| &row.name == language),
                "the corpus covers {language} and the baseline has no row for it; \
                 the recorded run did not measure what the manifest declares"
            );
        }
    }
}

#[test]
fn the_recorded_baseline_is_inside_the_ex_ante_budgets() {
    // The dispatched corpus job scores its own run against the budgets, but it
    // runs at phase-review gates. Nothing stopped an over-budget baseline being
    // committed and sitting green until the next dispatch — the numbers are in
    // the file, so the check costs a file read and no network.
    //
    // This is the arithmetic the gate performs, performed on what is committed.
    let manifest = corpus::load(&corpus::manifest_path()).expect("the corpus manifest loads");
    let baseline = corpus::load_baseline(&corpus::baseline_path()).expect("the baseline loads");

    for budget in &manifest.budgets {
        let row = baseline
            .languages
            .iter()
            .find(|row| row.name == budget.language)
            .unwrap_or_else(|| panic!("the baseline has no row for {}", budget.language));

        assert!(
            row.degraded_file_ratio() <= budget.max_degraded_file_ratio,
            "{}: the committed baseline records {}/{} files degraded ({:.5}), \
             above the ex ante budget of {:.5}",
            row.name,
            row.degraded_files,
            row.files,
            row.degraded_file_ratio(),
            budget.max_degraded_file_ratio
        );
        assert!(
            row.error_node_ratio() <= budget.max_error_node_ratio,
            "{}: the committed baseline records an error-node rate of {:.7}, \
             above the ex ante budget of {:.7}",
            row.name,
            row.error_node_ratio(),
            budget.max_error_node_ratio
        );
    }
}

#[test]
fn every_baseline_row_has_a_budget_to_be_judged_against() {
    // The other direction: a language recorded with no budget behind it is a
    // language the test above silently skips.
    let manifest = corpus::load(&corpus::manifest_path()).expect("loads");
    let baseline = corpus::load_baseline(&corpus::baseline_path()).expect("loads");
    for row in &baseline.languages {
        assert!(
            manifest.budgets.iter().any(|b| b.language == row.name),
            "the baseline records {} and no budget covers it",
            row.name
        );
    }
}

#[test]
fn the_baseline_records_real_files_rather_than_an_empty_run() {
    // A baseline of zeros would satisfy every comparison above and prove
    // nothing. The corpus exists to have measured something.
    let baseline = corpus::load_baseline(&corpus::baseline_path()).expect("loads");
    assert!(!baseline.languages.is_empty());
    for row in &baseline.languages {
        assert!(row.files > 0, "{} measured no files", row.name);
        if row.name != Language::Rust.name() {
            assert!(
                row.total_nodes > 0,
                "{} parsed no nodes, so its ERROR rate has no denominator",
                row.name
            );
        }
    }
}
