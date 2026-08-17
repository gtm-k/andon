//! Reading `key = value` out of configuration, whatever syntax it is written in.
//!
//! # Why not four parsers
//!
//! Two detectors — [`crate::detectors::coverage_exclusion_drift`] and
//! [`crate::detectors::threshold_config_edit`] — need to know which settings
//! moved in files written as JSON, TOML, INI, YAML, and JavaScript. Parsing each
//! properly would be five dependencies and five ways to be wrong about a
//! comment, for an answer that is always the same shape: *this key had that
//! value and now has this one*.
//!
//! So this is a scanner, not a parser. It finds every `key` followed by `:` or
//! `=` on a line and takes what follows, whether the line is
//! `strict = true`, `"strict": true,`, or
//! `{ "compilerOptions": { "strict": false } }` all on one line — which is the
//! case that matters, because minified and hand-written single-line JSON is
//! common in exactly these files and a line-splitting reader sees nothing in it.
//!
//! # What it deliberately does not do
//!
//! Track nesting. A leaf key is enough to say which threshold moved, and a
//! detector that reported `compilerOptions.strict` in one file and `strict` in
//! another — because one was nested and one was not — would be comparing
//! different names for the same setting. Bracketed sections (`[tool.mypy]`,
//! `[run]`) *are* tracked, because in INI and TOML the section is the only thing
//! distinguishing two same-named keys.
//!
//! The looseness is bounded by the caller: both detectors examine only files
//! whose names say they are configuration, so a `:` in a source file never
//! reaches here.

/// One `key = value` found on a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pair {
    /// The key, lower-cased, quotes stripped.
    pub key: String,
    /// The value as written, with surrounding quotes stripped. Empty when the
    /// key opened a block rather than naming a value.
    pub value: String,
}

/// Characters that may appear in a key.
fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '*')
}

/// Every `key = value` on one line.
///
/// Scans right-to-left from each separator, which is what makes single-line
/// nested JSON work: the key is whatever identifier sits immediately before the
/// colon, regardless of how many braces opened before it.
pub fn pairs(line: &str) -> Vec<Pair> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < chars.len() {
        let c = chars[index];
        if c != ':' && c != '=' {
            index += 1;
            continue;
        }
        // `=>`, `==`, `!=`, `<=`, `>=` are operators, not assignments.
        if chars.get(index + 1) == Some(&'>') || chars.get(index + 1) == Some(&'=') {
            index += 2;
            continue;
        }
        if index > 0 && matches!(chars[index - 1], '=' | '!' | '<' | '>' | ':') {
            index += 1;
            continue;
        }

        let Some(key) = key_before(&chars, index) else {
            index += 1;
            continue;
        };
        let (value, _) = value_after(&chars, index + 1);
        out.push(Pair {
            key: key.to_ascii_lowercase(),
            value,
        });
        // Deliberately *not* skipping past the value. A nested object is a
        // value and also a place more keys live: in
        // `{ "compilerOptions": { "strict": false } }` the outer key's value is
        // the whole object, and `strict` is the setting anyone cares about.
        // Resuming inside it is what makes single-line JSON readable at all.
        index += 1;
    }
    out
}

/// The identifier immediately left of `separator`.
fn key_before(chars: &[char], separator: usize) -> Option<String> {
    let mut end = separator;
    while end > 0 && chars[end - 1].is_whitespace() {
        end -= 1;
    }
    if end > 0 && matches!(chars[end - 1], '"' | '\'') {
        end -= 1;
    }
    let mut start = end;
    while start > 0 && is_key_char(chars[start - 1]) {
        start -= 1;
    }
    if start == end {
        return None;
    }
    let key: String = chars[start..end].iter().collect();
    // A bare number before a colon is a time, a version, or a port — not a key.
    if key.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(key)
}

/// The value right of `from`, and the index just past it.
fn value_after(chars: &[char], from: usize) -> (String, usize) {
    let mut index = from;
    while index < chars.len() && chars[index].is_whitespace() {
        index += 1;
    }
    if index >= chars.len() {
        return (String::new(), index);
    }

    // A bracketed value runs to its matching close, so a list stays one value.
    if matches!(chars[index], '[' | '{') {
        let open = chars[index];
        let close = if open == '[' { ']' } else { '}' };
        let start = index;
        let mut depth = 0usize;
        while index < chars.len() {
            if chars[index] == open {
                depth += 1;
            } else if chars[index] == close {
                depth -= 1;
                if depth == 0 {
                    index += 1;
                    break;
                }
            }
            index += 1;
        }
        let raw: String = chars[start..index.min(chars.len())].iter().collect();
        // An unclosed bracket is a block opening on the next line, and an empty
        // value is what tells the caller so.
        if depth != 0 && raw.trim_end() == open.to_string() {
            return (String::new(), chars.len());
        }
        return (raw, index);
    }

    let start = index;
    while index < chars.len() && !matches!(chars[index], ',' | '}' | ']') {
        index += 1;
    }
    let raw: String = chars[start..index].iter().collect();
    let value = raw
        .trim()
        .trim_end_matches(';')
        .trim()
        .trim_matches(['"', '\''])
        .to_string();
    (value, index)
}

/// The bracketed section a line opens, if it opens one.
///
/// `[tool.coverage.report]` -> `coverage.report`: the `tool.` prefix is TOML's
/// namespace for third-party configuration and says nothing about which setting
/// this is.
pub fn section(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') || trimmed.contains('=') {
        return None;
    }
    Some(
        trimmed
            .trim_matches(['[', ']'])
            .trim()
            .to_ascii_lowercase()
            .trim_start_matches("tool.")
            .to_string(),
    )
}

/// Whether a line is a comment or blank.
pub fn is_noise(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//")
}

/// The individual entries in a value that is a list.
///
/// Handles `["a", "b"]`, `a, b`, and the YAML `- a` form, so one function reads
/// an exclusion list in every syntax these files use.
pub fn entries(value: &str) -> Vec<String> {
    value
        .split([',', '[', ']', '{', '}'])
        .flat_map(|part| part.split_whitespace())
        .map(|part| {
            part.trim_matches(['"', '\'', '-', ',', ':'])
                .trim()
                .to_string()
        })
        .filter(|part| !part.is_empty() && part != "true" && part != "false")
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(line: &str, key: &str) -> Option<String> {
        pairs(line)
            .into_iter()
            .find(|p| p.key == key)
            .map(|p| p.value)
    }

    #[test]
    fn toml_and_ini_read() {
        assert_eq!(find("fail_under = 85", "fail_under").as_deref(), Some("85"));
        assert_eq!(
            find("max-complexity = 10", "max-complexity").as_deref(),
            Some("10")
        );
    }

    #[test]
    fn single_line_nested_json_reads() {
        let line = "{ \"compilerOptions\": { \"strict\": false, \"target\": \"es2022\" } }";
        assert_eq!(find(line, "strict").as_deref(), Some("false"));
        assert_eq!(find(line, "target").as_deref(), Some("es2022"));
    }

    #[test]
    fn a_list_stays_one_value() {
        let line = "{ \"jest\": { \"coveragePathIgnorePatterns\": [\"/node_modules/\", \"/src/legacy/\"] } }";
        let value = find(line, "coveragepathignorepatterns").expect("found");
        assert_eq!(entries(&value), vec!["/node_modules/", "/src/legacy/"]);
    }

    #[test]
    fn a_key_with_nothing_after_it_opens_a_block() {
        assert_eq!(find("omit =", "omit").as_deref(), Some(""));
        assert_eq!(find("ignore:", "ignore").as_deref(), Some(""));
    }

    #[test]
    fn operators_are_not_assignments() {
        assert!(pairs("if (a == b) { return; }").is_empty());
        assert!(pairs("const f = (x) => x + 1;")
            .iter()
            .all(|p| p.key != "x"));
        assert!(pairs("if (a !== b) return;").is_empty());
    }

    #[test]
    fn a_url_does_not_become_a_setting() {
        // `https` is a key by this scanner's rules; no detector knows it, which
        // is the layer that makes the looseness safe.
        let found = pairs("homepage = \"https://example.com\"");
        assert!(found.iter().any(|p| p.key == "homepage"));
    }

    #[test]
    fn eslint_rule_severities_read() {
        let line = "{ \"rules\": { \"no-explicit-any\": \"warn\" } }";
        assert_eq!(find(line, "no-explicit-any").as_deref(), Some("warn"));
    }

    #[test]
    fn sections_drop_the_toml_tool_namespace() {
        assert_eq!(
            section("[tool.coverage.report]").as_deref(),
            Some("coverage.report")
        );
        assert_eq!(section("[run]").as_deref(), Some("run"));
        assert_eq!(section("omit = [1]"), None);
    }

    #[test]
    fn yaml_sequences_read_as_entries() {
        assert_eq!(entries("- vendor/**"), vec!["vendor/**"]);
    }
}
