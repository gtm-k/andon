//! The crate doc's "## The modules" list names every public module.
//!
//! The list is prose and drifted once: `doctor` shipped without an entry. The
//! guard reads `lib.rs` itself, so a `pub mod` added without a line in the list
//! reddens here rather than waiting for a reader to notice.

const LIB: &str = include_str!("../src/lib.rs");

#[test]
fn the_module_list_names_every_public_module() {
    let after_heading = LIB
        .split("## The modules")
        .nth(1)
        .expect("lib.rs has a '## The modules' section");
    // The first line is the rest of the heading's own line; the list runs
    // until the doc comment ends.
    let section: String = after_heading
        .lines()
        .skip(1)
        .take_while(|line| line.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    let declared: Vec<&str> = LIB
        .lines()
        .filter_map(|line| line.strip_prefix("pub mod "))
        .map(|rest| rest.trim_end_matches(';').trim())
        .collect();
    assert!(!declared.is_empty(), "lib.rs declares public modules");
    for name in declared {
        assert!(
            section.contains(&format!("[`{name}`]")),
            "lib.rs declares `pub mod {name};` and its '## The modules' list does not name [`{name}`]"
        );
    }
}
