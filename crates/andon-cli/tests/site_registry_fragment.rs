//! The registry section of `site/index.html` is spliced from `registry/*.toml`
//! by `site/tools/registry-section.py`, and nothing re-runs that tool when the
//! registry changes. This reads the numbers the page shows and asserts them
//! against the registry files as the crate's own schema parses them, so the
//! page cannot say something the registry does not. RED means the fragment is
//! stale: `python site/tools/registry-section.py --splice`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use andon_core::registry::EngineRegistryFile;

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// The text between the first `start` and the next `end` after it.
fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let from = text
        .find(start)
        .unwrap_or_else(|| panic!("{start:?} not found"))
        + start.len();
    let to = text[from..]
        .find(end)
        .unwrap_or_else(|| panic!("{end:?} not found"));
    &text[from..from + to]
}

fn count(text: &str, start: &str, end: &str) -> usize {
    let raw = between(text, start, end).trim();
    raw.parse()
        .unwrap_or_else(|_| panic!("{raw:?} after {start:?} is not a count"))
}

#[test]
fn the_spliced_registry_fragment_says_what_the_registry_says() {
    let html = std::fs::read_to_string(workspace().join("site/index.html")).expect("the site");
    let page = between(&html, "<!-- registry:begin -->", "<!-- registry:end -->");

    let mut files: Vec<EngineRegistryFile> = Vec::new();
    for entry in std::fs::read_dir(workspace().join("registry")).expect("registry/") {
        let path = entry.expect("a directory entry").path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            let text = std::fs::read_to_string(&path).expect("a readable registry file");
            files.push(toml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display())));
        }
    }
    let metrics: Vec<_> = files.iter().flat_map(|f| &f.metrics).collect();
    let claims: Vec<_> = files.iter().flat_map(|f| &f.claims).collect();
    let mut by_tier = BTreeMap::new();
    for claim in &claims {
        *by_tier.entry(format!("{:?}", claim.tier)).or_insert(0usize) += 1;
    }

    assert_eq!(
        count(page, "<strong>", " metrics</strong>"),
        metrics.len(),
        "metric total"
    );
    assert_eq!(
        count(page, "in <strong>", " families</strong>"),
        files.len(),
        "families"
    );
    assert_eq!(
        count(page, "standing on <strong>", " claims</strong>"),
        claims.len(),
        "claims"
    );
    let deterministic = metrics.iter().filter(|m| m.deterministic).count();
    assert_eq!(
        count(page, "claims</strong>. ", " of the "),
        deterministic,
        "deterministic"
    );
    for part in between(page, "Claims by evidence tier: ", ".\"").split(", ") {
        let (n, tier) = part.split_once(" at tier ").expect("`<n> at tier <T>`");
        let shown: usize = n.parse().expect("a count");
        assert_eq!(
            shown,
            by_tier.get(tier).copied().unwrap_or(0),
            "tier {tier}"
        );
    }
}
