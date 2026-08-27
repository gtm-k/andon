//! Every metric id the MCP surface *documents* must be one the registry ships.
//!
//! This exists because the drift it catches already happened once. P6's F2
//! (E61, HIGH) was: `lib.rs` and the tool descriptions cited
//! `static.cognitive-complexity-ts` while the registry declared
//! `static.cognitive-complexity.typescript`. An agent following the tool's own
//! documentation got a hard error on its first `explain_finding` call — the
//! primary consumer, broken by the primary consumer's instructions.
//!
//! The strings were corrected. Nothing held them together, which is the gap
//! this file closes (D40). The ids live in prose — one doc comment and one
//! `description =` string — so the compiler never sees them, and
//! `conformance.rs` exercises `explain_finding` with an id taken from a *live
//! measurement's findings* rather than with the documented example. A registry
//! rename would redden `shipped_severity_band.rs` and the payload fixtures, so
//! the rename itself is caught; but whoever fixed those got no signal pointing
//! at this prose. That asymmetry is exactly how the original bug arose.
//!
//! Derivation, not a hardcoded list: the id prefixes come from the shipped
//! registry, so an engine added tomorrow is scanned for the day its file lands.
//! Writing the prefixes down here would reproduce the failure this test exists
//! to prevent — a constant nobody updates.

/// Characters an id may contain after its prefix. Anything else ends the token,
/// which is what stops a trailing backtick, quote, or paren being swallowed.
fn is_id_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-'
}

/// Every `<prefix>.<...>` token in `text`, for the given prefixes.
fn documented_ids(text: &str, prefixes: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    for prefix in prefixes {
        let needle = format!("{prefix}.");
        let mut from = 0;
        while let Some(rel) = text[from..].find(&needle) {
            let start = from + rel;
            // A prefix must start the token, or `mytamper.foo` would match
            // `tamper.`. Guard on the preceding character.
            let preceded_by_id_char = start > 0
                && text[..start]
                    .chars()
                    .next_back()
                    .is_some_and(|c| is_id_char(c) || c == '_');
            let end = start
                + text[start..]
                    .find(|c| !is_id_char(c))
                    .unwrap_or(text.len() - start);
            if !preceded_by_id_char {
                found.push(text[start..end].trim_end_matches('.').to_string());
            }
            from = end.max(start + 1);
        }
    }
    found.sort();
    found.dedup();
    found
}

/// The source files this test scans. `include_str!` needs literal paths, so the
/// set cannot be discovered at compile time — which makes it exactly the kind of
/// hand-maintained list that goes stale. `no_source_file_escapes_the_scan` below
/// is the watcher for it.
const SCANNED: &[(&str, &str)] = &[
    ("lib.rs", include_str!("../src/lib.rs")),
    ("main.rs", include_str!("../src/main.rs")),
];

/// Every `.rs` file under `dir`, **recursively**, relative to it with `/` separators.
///
/// Recursive because `read_dir` is not, and the first version of this guard used
/// the flat form: a nested `src/tools/mod.rs` escaped the scan *and* escaped the
/// check meant to catch exactly that, with both tests staying green. Demonstrated
/// rather than reasoned about — the Codex gate on `be2b423` created that file and
/// watched nothing notice.
///
/// A coverage check that under-covers in the same shape as the thing it guards is
/// worse than no check, because it reports success while doing it.
/// Deeper than any real module tree in this crate, shallower than a stack
/// overflow. A self-referential symlink under `src/` recurses forever: the Codex
/// gate on `2e90c03` created one and watched the walk go 14 levels deep before a
/// Windows path-length wall stopped it — a wall CI's Linux runners do not have,
/// so the same loop there would keep going until the stack gave out. Sixteen is
/// a bound, not a target; the crate is two files deep today.
const MAX_DEPTH: usize = 16;

fn rs_files_under(dir: &std::path::Path, prefix: &str, depth: usize, out: &mut Vec<String>) {
    // Loud, not silent. A walk that quietly stopped at the cap would under-cover
    // in exactly the shape this guard exists to catch, and report success while
    // doing it. Either the crate grew a module tree sixteen deep (raise the cap,
    // on purpose) or something under `src/` points back at itself (remove it).
    assert!(
        depth <= MAX_DEPTH,
        "`src/` is more than {MAX_DEPTH} directories deep at `{prefix}` — a symlink \
         loop, or a module tree nobody expected. This is a hard stop rather than a \
         truncated scan, because a scan that silently under-covers is the failure \
         this file exists to prevent."
    );
    let entries = std::fs::read_dir(dir).expect("a readable directory");
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if path.is_dir() {
            rs_files_under(&path, &rel, depth + 1, out);
        } else if name.ends_with(".rs") {
            out.push(rel);
        }
    }
}

#[test]
fn no_source_file_escapes_the_scan() {
    // A coverage list with nothing checking it is the failure this whole file is
    // about: a condition recorded once and never observed again. Today `lib.rs`
    // holds every documented id and `main.rs` holds none, but a new module
    // carrying tool descriptions would slip past a scan that trusts this list.
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut on_disk = Vec::new();
    rs_files_under(&src, "", 0, &mut on_disk);
    on_disk.sort();

    let mut scanned: Vec<String> = SCANNED.iter().map(|(n, _)| (*n).to_string()).collect();
    scanned.sort();

    assert_eq!(
        on_disk, scanned,
        "a source file was added or removed without updating SCANNED in this \
         test. Add it to SCANNED (and its ids get checked) or remove it — do not \
         relax this assertion, because the scan silently under-covering is the \
         way the id drift comes back."
    );
}

#[test]
fn every_metric_id_the_mcp_documents_is_one_the_registry_ships() {
    let source: String = SCANNED
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n");
    let source = source.as_str();
    let shipped = andon_cli::shipped::all_metric_ids();
    assert!(
        !shipped.is_empty(),
        "the shipped metric set is empty; this test would pass vacuously"
    );

    // Prefixes derived from what ships, never written down here.
    let mut prefixes: Vec<String> = shipped
        .iter()
        .filter_map(|id| id.split('.').next().map(str::to_string))
        .collect();
    prefixes.sort();
    prefixes.dedup();

    let documented = documented_ids(source, &prefixes);
    assert!(
        !documented.is_empty(),
        "no ids found in the MCP source, so this test proves nothing — either \
         the documentation stopped citing examples (fine, delete this test) or \
         the scan broke (not fine). Prefixes searched: {prefixes:?}"
    );

    let unresolvable: Vec<&String> = documented
        .iter()
        .filter(|id| !shipped.contains(id))
        .collect();

    assert!(
        unresolvable.is_empty(),
        "the MCP documents metric id(s) the registry does not ship: {unresolvable:?}\n\
         An agent following these instructions gets a hard error on `explain_finding`.\n\
         This is P6's F2 recurring. Fix the prose in `andon-mcp/src/lib.rs` to match \
         the registry, or the registry to match the prose — but do not delete this \
         assertion.\nIds documented: {documented:?}"
    );
}
