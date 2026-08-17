//! Deeply nested input is tokenized and compared, quickly, without unwinding
//! the stack.
//!
//! The sibling of `andon-engine-tamper`'s test of the same name, and it exists
//! for the same reason: a file anyone who can open a pull request may write must
//! not be able to hang or abort a measurement. A stack overflow is not catchable
//! in Rust — it aborts the process — so a recursive walker over PR-controlled
//! input is an availability bug no `Result` can express.
//!
//! This crate came through the audit clean: `syntax::tokens_of` walks with an
//! explicit stack, and nothing here calls `Node::parent()`, which is the
//! O(depth) accessor that made the tamper suite quadratic. The test is here so
//! that staying clean is checked rather than remembered.

use std::time::{Duration, Instant};

use andon_engine_clones::index::{FileInput, Index};
use andon_engine_clones::{detect, syntax};

fn nested(depth: usize, open: char, close: char) -> String {
    let mut source = String::from("export function f(x: number): number {\n  const v = ");
    source.extend(std::iter::repeat_n(open, depth));
    source.push('1');
    source.extend(std::iter::repeat_n(close, depth));
    source.push_str(";\n  return v as unknown as number;\n}\n");
    source
}

fn input(path: &str, source: &str) -> FileInput {
    FileInput {
        path: path.to_string(),
        blob_oid: format!("{:040x}", syntax::fnv1a(source.as_bytes())),
        source: source.as_bytes().to_vec(),
    }
}

#[test]
fn tokenizing_and_detecting_survive_hostile_nesting() {
    for depth in [1_000usize, 5_000] {
        let source = nested(depth, '[', ']');
        let started = Instant::now();
        let tokens = syntax::tokenize("src/deep.ts", source.as_bytes()).expect("tokenizes");
        let inputs = vec![input("a.ts", &source), input("b.ts", &source)];
        let paths: Vec<String> = inputs.iter().map(|i| i.path.clone()).collect();
        let (index, _) = Index::empty().update(&inputs);
        let report = detect::detect(&index, &paths);
        let elapsed = started.elapsed();
        println!(
            "depth {depth:>5}: {} tokens, {} group(s), {elapsed:?}",
            tokens.len(),
            report.groups.len()
        );
        assert!(tokens.len() > depth, "the nesting reached the token stream");
        assert!(
            elapsed < Duration::from_secs(20),
            "detection took {elapsed:?} at depth {depth}"
        );
        // Two identical files are a clone of each other however deep they nest.
        assert!(!report.groups.is_empty());
    }
}

#[test]
fn a_deeply_nested_python_file_tokenizes() {
    let mut source = String::from("def f():\n    v = ");
    source.extend(std::iter::repeat_n('[', 5_000));
    source.push('1');
    source.extend(std::iter::repeat_n(']', 5_000));
    source.push_str("\n    return v\n");
    let tokens = syntax::tokenize("src/deep.py", source.as_bytes()).expect("tokenizes");
    assert!(tokens.len() > 5_000);
}
