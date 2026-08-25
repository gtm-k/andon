//! `fp_window::landing_times` against a real notes history (PLAN P9b).
//!
//! The unit tests beside the computation inject landing maps; what needs a real
//! repository is the map's own derivation — that a record line is dated by the
//! **earliest** notes commit whose tree contains it, that re-landings do not
//! re-date it, and that a repository with no ledger yields an empty map rather
//! than an error.

mod common;

use andon_core::canonical::to_canonical_string;
use andon_core::git::Git;
use andon_ledger::fp_window::landing_times;
use andon_ledger_min::notes::MEASURE_REF;

/// A scratch repository with one commit to hang notes on.
fn scratch(name: &str) -> (Git, String) {
    let root = common::root(name);
    common::bootstrap()
        .cmd(["init", "--quiet", "--initial-branch", "main"])
        .arg(&root)
        .output()
        .expect("git init");
    let git = Git::open(&root).expect("a repository");
    let head = common::write_and_commit(&git, "a.txt", "a\n", "base");
    (git, head)
}

/// Append `line` as a note on `commit`, with the notes commit's clock pinned.
fn append_note_at(git: &Git, commit: &str, line: &str, date: &str) {
    common::identified(git.cmd([
        "notes",
        &format!("--ref={MEASURE_REF}"),
        "append",
        "-m",
        line,
        commit,
    ]))
    .env("GIT_COMMITTER_DATE", date)
    .output()
    .expect("notes append");
}

#[test]
fn a_repository_with_no_ledger_yields_an_empty_map() {
    let (git, _) = scratch("fp-landing-empty");
    let map = landing_times(&git, MEASURE_REF).expect("landing times");
    assert!(map.is_empty(), "{map:?}");
}

#[test]
fn a_line_is_dated_by_the_earliest_tree_that_contains_it() {
    let (git, first) = scratch("fp-landing-earliest");
    let second = common::write_and_commit(&git, "b.txt", "b\n", "second");
    let line = to_canonical_string(&andon_core::testing::sample_record()).expect("serializes");

    // The same record line lands twice — on two commits, a day apart. Notes
    // history only ever unions, so the line's landing time is the first tree
    // that held it, not the last append that mentioned it.
    append_note_at(&git, &first, &line, "1767225600 +0000"); // 2026-01-01
    append_note_at(&git, &second, &line, "1767312000 +0000"); // 2026-01-02

    let map = landing_times(&git, MEASURE_REF).expect("landing times");
    assert_eq!(map.get(&line).copied(), Some(1_767_225_600), "{map:?}");
}

#[test]
fn the_map_keys_are_the_guarded_readers_records_reserialized() {
    // The whole lookup leans on canonical round-trip stability: what the
    // notes hold, read back through the guarded reader and re-serialized,
    // must reproduce the stored line byte for byte. Pinned here through a
    // real append + read rather than trusted from the P0 property test alone.
    let (git, head) = scratch("fp-landing-roundtrip");
    let record = andon_core::testing::sample_record();
    andon_ledger_min::notes::Notes::new(&git, MEASURE_REF)
        .append(&head, &record)
        .expect("append");

    let map = landing_times(&git, MEASURE_REF).expect("landing times");
    let read_back = andon_ledger_min::notes::Notes::new(&git, MEASURE_REF)
        .read(&head)
        .expect("read");
    assert_eq!(read_back.len(), 1);
    let line = to_canonical_string(&read_back[0]).expect("serializes");
    assert!(
        map.contains_key(&line),
        "the re-serialized record must be a key of {map:?}"
    );
}
