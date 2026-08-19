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

/// A tool whose configuration a detector reads, named by its stem rather than
/// by a spelling of its file name.
///
/// # The list was the bug, so the list stopped being the answer
///
/// Both detectors used to hold an array of exact file names. `.nycrc` and
/// `.nycrc.json` were in it and `.nycrc.yml` was not, so the identical edit
/// fired in two spellings of one file and came back
/// `{flag: false, magnitude: 0, completeness: "complete"}` in a third — nyc
/// reads all of them. The same hole held `.eslintrc.cjs` beside `.eslintrc.js`,
/// `.eslintrc.yaml` beside `.eslintrc.yml`, `eslint.config.cjs` beside three
/// other flat-config spellings, `.golangci.toml` beside `.golangci.yml`, and
/// `.c8rc` beside `.c8rc.json`. Every one of them was a confident zero on a
/// format the detector would say it recognises.
///
/// A name can always be added, and there will always be another one. So what is
/// matched is the *stem* — the file name with its syntax extension taken off —
/// and the extension is then read against the syntaxes that tool actually
/// reads. That is what closes the class rather than the cases: `.nycrc.json5`
/// is nyc configuration before anybody writes one.
///
/// # And then the stem was the bug
///
/// Taking *any* extension off *any* stem is one step too wide, and the step
/// lands on ordinary source. `pyproject` is configuration as `.toml` and a
/// perfectly ordinary Python module as `.py`, so `src/pyproject.py` raising
/// `max_warnings` from 10 to 100 came back as a tamper firing on somebody's
/// honest code. `tarpaulin.rs`, `clippy.rs`, `mypy.py`, `ruff.py`, `biome.ts`
/// and `codecov.py` are the same shape, and a tool that accuses honest work
/// gets uninstalled (PREMORTEM A4) — which is a worse outcome than the missed
/// detection the stem rule was widened to fix.
///
/// The line is drawn where it can be drawn without another list: a **dotfile
/// stem cannot be ordinary source**, because nothing in these ecosystems
/// compiles `.nycrc.ts` as a module. So [`Match::AnySyntax`] — the open class,
/// the one that covers the syntax nobody has written yet — is reserved for
/// stems beginning with a dot, and [`Tool::any`] refuses to construct anything
/// else. Every other stem names the syntaxes its own tool reads.
#[derive(Debug, Clone, Copy)]
pub struct Tool {
    /// The stem, lower-cased and without its syntax extension.
    pub stem: &'static str,
    /// How the stem is matched.
    pub how: Match,
}

/// How a [`Tool`]'s stem is matched against a file name.
#[derive(Debug, Clone, Copy)]
pub enum Match {
    /// This exact stem, in any syntax — including one nobody has written yet.
    ///
    /// Legal only for a dotfile stem, which is the condition under which "any
    /// syntax" cannot reach ordinary source: `.nycrc`, `.golangci`, `.eslintrc`.
    /// [`Tool::any`] enforces it.
    AnySyntax,
    /// This stem, or one that extends it with a further `.` segment, in these
    /// syntaxes — for the families that spell a variant into the name itself:
    /// `tsconfig.base.json`, `jest.config.ci.js`.
    Family(&'static [&'static str]),
    /// This exact stem, and only in these syntaxes. For every stem an ordinary
    /// file could carry: `setup.cfg` is configuration and `setup.ts` is code,
    /// `pyproject.toml` is configuration and `pyproject.py` is code.
    Syntaxes(&'static [&'static str]),
}

impl Tool {
    /// A dotfile stem, in any syntax.
    ///
    /// # Why this asserts rather than documenting a rule
    ///
    /// The tool tables are `const`, so the assertion runs at compile time and a
    /// non-dotfile stem is a build failure rather than a false positive
    /// somebody's CI discovers. The alternative — a sentence in a doc comment
    /// saying "only for stems nobody else could carry" — is exactly what stood
    /// here when `pyproject` was declared with this constructor. A rule the
    /// constructor does not enforce is a rule the next tool breaks.
    pub const fn any(stem: &'static str) -> Tool {
        assert!(
            !stem.is_empty() && stem.as_bytes()[0] == b'.',
            "Tool::any is the open class, and only a dotfile stem is safe in it: any \
             other stem answers for every extension, including the one an ordinary \
             source file carries. Use Tool::only with the syntaxes this tool reads."
        );
        Tool {
            stem,
            how: Match::AnySyntax,
        }
    }

    /// A family of stems, matched by prefix, in these syntaxes.
    pub const fn family(stem: &'static str, syntaxes: &'static [&'static str]) -> Tool {
        Tool {
            stem,
            how: Match::Family(syntaxes),
        }
    }

    /// One stem, in these syntaxes only.
    pub const fn only(stem: &'static str, syntaxes: &'static [&'static str]) -> Tool {
        Tool {
            stem,
            how: Match::Syntaxes(syntaxes),
        }
    }
}

/// The file names each tool writes its configuration under.
///
/// # Declared once, because the drift between two lists was the original defect
///
/// Nine of these are read by both [`crate::detectors::coverage_exclusion_drift`]
/// and [`crate::detectors::threshold_config_edit`], and the defect that started
/// all of this — `.nycrc.yml` answering a widening with silence while
/// `.nycrc.json` fired — was one list holding a spelling the other did not. Two
/// tables that each named their own syntaxes would have the same failure mode
/// one level up: `codecov.yaml` added to one detector and forgotten in the
/// other. So a tool's file names are a fact about the tool, stated here once,
/// and a detector's table says only *which* tools it reads.
pub mod tools {
    use super::Tool;

    /// The syntaxes a JavaScript-ecosystem config file is written in. A loader
    /// that takes `.js` takes `.mjs`, and the TypeScript spellings are what
    /// `eslint.config.mts` is.
    const JS: &[&str] = &["js", "cjs", "mjs", "ts", "mts", "cts"];
    /// The same, plus JSON, for the loaders that also accept a data file.
    const JS_OR_JSON: &[&str] = &["js", "cjs", "mjs", "ts", "mts", "cts", "json"];
    /// JSON, with comments allowed — TypeScript's and Biome's own spelling.
    const JSONC: &[&str] = &["json", "jsonc"];

    /// This tool's own policy file.
    pub const ANDON: Tool = Tool::any(".andon");
    /// TypeScript. `tsconfig.base.json` is the same file with a variant spelled
    /// into the name; `src/tsconfig.ts` is a module that reads one.
    pub const TSCONFIG: Tool = Tool::family("tsconfig", JSONC);
    /// ESLint's legacy rc file, in all six spellings and the next one.
    pub const ESLINTRC: Tool = Tool::any(".eslintrc");
    /// ESLint's flat config.
    pub const ESLINT_FLAT: Tool = Tool::family("eslint.config", JS);
    /// Biome. `biome.ts` is a module.
    pub const BIOME: Tool = Tool::only("biome", JSONC);
    /// flake8's dotfile.
    pub const FLAKE8: Tool = Tool::any(".flake8");
    /// Python's standard project file. `pyproject.py` is a Python module.
    pub const PYPROJECT: Tool = Tool::only("pyproject", &["toml"]);
    /// mypy. `mypy.py` is a Python module.
    pub const MYPY: Tool = Tool::only("mypy", &["ini"]);
    /// mypy's dotfile form.
    pub const MYPY_DOT: Tool = Tool::any(".mypy");
    /// Ruff. `ruff.py` is a Python module.
    pub const RUFF: Tool = Tool::only("ruff", &["toml"]);
    /// Ruff's dotfile form.
    pub const RUFF_DOT: Tool = Tool::any(".ruff");
    /// Clippy. `clippy.rs` is a Rust module.
    pub const CLIPPY: Tool = Tool::only("clippy", &["toml"]);
    /// golangci-lint.
    pub const GOLANGCI: Tool = Tool::any(".golangci");
    /// SonarQube's project descriptor.
    pub const SONAR: Tool = Tool::family("sonar-project", &["properties"]);
    /// Jest. Its loader also accepts a JSON file.
    pub const JEST: Tool = Tool::family("jest.config", JS_OR_JSON);
    /// Vitest.
    pub const VITEST: Tool = Tool::family("vitest.config", JS);
    /// nyc's JavaScript config form.
    pub const NYC_CONFIG: Tool = Tool::family("nyc.config", JS);
    /// coverage.py's dotfile.
    pub const COVERAGERC: Tool = Tool::any(".coveragerc");
    /// nyc's rc file.
    pub const NYCRC: Tool = Tool::any(".nycrc");
    /// c8's rc file.
    pub const C8RC: Tool = Tool::any(".c8rc");
    /// Codecov. `codecov.py` is the uploader's Python client.
    pub const CODECOV: Tool = Tool::only("codecov", &["yml", "yaml"]);
    /// Codecov's dotfile form.
    pub const CODECOV_DOT: Tool = Tool::any(".codecov");
    /// cargo-tarpaulin. `tarpaulin.rs` is a Rust module.
    pub const TARPAULIN: Tool = Tool::only("tarpaulin", &["toml"]);
    /// setuptools' config, which flake8 and coverage.py also read.
    pub const SETUP_CFG: Tool = Tool::only("setup", &["cfg"]);
    /// npm's manifest, which carries a `jest` block.
    pub const PACKAGE_JSON: Tool = Tool::only("package", &["json"]);
    /// tox, which coverage.py reads `[coverage:run]` out of.
    pub const TOX_INI: Tool = Tool::only("tox", &["ini"]);
}

/// Whether `path` names one of `tools`.
pub fn names_one_of(path: &str, tools: &[Tool]) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let (stem, syntax) = stem_and_syntax(name);
    tools.iter().any(|tool| match tool.how {
        Match::AnySyntax => stem == tool.stem,
        // The remainder has to start at a dot, or `tsconfig` claims
        // `tsconfig-loader.ts` and a source file becomes threshold
        // configuration. A family spells its variant as a further name segment
        // — `tsconfig.base`, `jest.config.ci` — and never as a suffix.
        Match::Family(syntaxes) => {
            let named = stem == tool.stem
                || stem
                    .strip_prefix(tool.stem)
                    .is_some_and(|rest| rest.starts_with('.'));
            named && syntaxes.contains(&syntax)
        }
        Match::Syntaxes(syntaxes) => stem == tool.stem && syntaxes.contains(&syntax),
    })
}

/// A file name split into its stem and its syntax extension.
///
/// The extension is what follows the *last* dot, so `eslint.config.cjs` is the
/// flat-config stem in the CommonJS syntax rather than an `eslint` file with two
/// extensions. A leading dot is part of the stem and never a separator:
/// `.coveragerc` has no extension, and `.nycrc.yml` has one.
pub fn stem_and_syntax(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(0) | None => (name, ""),
        Some(at) => (&name[..at], &name[at + 1..]),
    }
}

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

    #[test]
    fn a_name_splits_into_the_tool_and_the_syntax() {
        assert_eq!(stem_and_syntax(".coveragerc"), (".coveragerc", ""));
        assert_eq!(stem_and_syntax(".nycrc.yml"), (".nycrc", "yml"));
        assert_eq!(stem_and_syntax("tox.ini"), ("tox", "ini"));
        assert_eq!(
            stem_and_syntax("eslint.config.cjs"),
            ("eslint.config", "cjs")
        );
        assert_eq!(stem_and_syntax("Makefile"), ("Makefile", ""));
    }

    #[test]
    fn a_dotfile_stem_answers_for_every_syntax() {
        // Including one nobody has written yet, which is the whole point: the
        // list of names was the defect, so the list is not the answer. Safe
        // here and only here, because nothing compiles a dotfile as a module.
        const TOOLS: &[Tool] = &[Tool::any(".nycrc")];
        for name in [
            ".nycrc",
            ".nycrc.json",
            ".nycrc.yml",
            ".nycrc.yaml",
            ".nycrc.json5",
            "packages/app/.nycrc.toml",
        ] {
            assert!(names_one_of(name, TOOLS), "{name}");
        }
        assert!(!names_one_of("src/nycrc.ts", TOOLS));
    }

    #[test]
    fn a_stem_an_ordinary_file_could_carry_answers_only_for_its_own_syntax() {
        const TOOLS: &[Tool] = &[
            Tool::only("setup", &["cfg"]),
            Tool::only("pyproject", &["toml"]),
        ];
        assert!(names_one_of("setup.cfg", TOOLS));
        assert!(!names_one_of("src/setup.ts", TOOLS));
        assert!(!names_one_of("setup.py", TOOLS));
        // The reported false positive: one stem, configuration in one syntax
        // and a Python module in another.
        assert!(names_one_of("pyproject.toml", TOOLS));
        assert!(!names_one_of("src/pyproject.py", TOOLS));
    }

    #[test]
    fn a_family_matches_the_variants_spelled_into_the_name() {
        const TOOLS: &[Tool] = &[
            Tool::family("tsconfig", &["json"]),
            Tool::family("jest.config", &["mjs"]),
        ];
        assert!(names_one_of("tsconfig.json", TOOLS));
        assert!(names_one_of("tsconfig.base.json", TOOLS));
        assert!(names_one_of("jest.config.ci.mjs", TOOLS));
        assert!(!names_one_of("src/config.ts", TOOLS));
        // A family names its variants as further segments, so a stem that
        // merely begins with the same letters is not one of them.
        assert!(!names_one_of("src/tsconfig-loader.ts", TOOLS));
        assert!(!names_one_of("tsconfiguration.json", TOOLS));
        // And a family is a stem an ordinary file can carry too, so it answers
        // only for the syntaxes its own loader reads.
        assert!(!names_one_of("src/tsconfig.ts", TOOLS));
    }

    #[test]
    fn the_open_class_is_reserved_for_stems_nothing_compiles() {
        // `Tool::any` asserts this in a `const fn`, so the tables below cannot
        // be built wrong — but a table is data and this is the property that
        // data has to have, stated where a reader looking for it will find it.
        for tool in ALL_TOOLS {
            if matches!(tool.how, Match::AnySyntax) {
                assert!(
                    tool.stem.starts_with('.'),
                    "{} answers for every extension and is a name an ordinary \
                     source file can carry",
                    tool.stem
                );
            }
        }
    }

    #[test]
    fn no_declared_tool_claims_a_source_extension() {
        // The other half, over the real tables rather than over a rule: every
        // syntax any tool answers for, checked against the extensions these
        // ecosystems compile. `.eslintrc.ts` reaching this list would be
        // harmless — nothing imports it — and `pyproject.py` reaching it is the
        // uninstall.
        const COMPILED: &[&str] = &["py", "rs", "go", "rb", "java", "kt", "php"];
        for tool in ALL_TOOLS {
            let syntaxes = match tool.how {
                Match::AnySyntax => continue,
                Match::Family(s) | Match::Syntaxes(s) => s,
            };
            for syntax in syntaxes {
                assert!(
                    !COMPILED.contains(syntax),
                    "{}.{syntax} is a source file in a language this repository \
                     measures, and naming it configuration accuses honest code",
                    tool.stem
                );
            }
        }
    }

    /// Every tool either detector declares, so the properties above are stated
    /// over what ships rather than over an example.
    const ALL_TOOLS: &[Tool] = &[
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
        tools::NYC_CONFIG,
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
}
