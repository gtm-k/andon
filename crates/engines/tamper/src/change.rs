//! What a detector is given: the change, as byte pairs.
//!
//! # Why the detectors do not take a repository
//!
//! Every detector is a pure function of `(path, base bytes, head bytes)`. That
//! is a design decision with two consequences worth the trade:
//!
//! - **The corpus needs no git.** A precision/recall case is two directories of
//!   plain files, so the fixture corpus is readable in a diff and a reviewer can
//!   see exactly what a detector is being asked to catch. A corpus of git
//!   repositories would be the same content behind a wall.
//! - **Nothing can reach the working tree.** A detector cannot read a file it
//!   was not handed, so it cannot accidentally measure checkout-dependent bytes.
//!   The adapter that builds a [`ChangeView`] from a resolved change reads blobs
//!   only, and that is the one place the rule has to hold (PREMORTEM T1).

/// What happened to a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// New in this change.
    Added,
    /// Present on both sides, edited.
    Modified,
    /// Gone in this change.
    Deleted,
    /// Moved, with or without an edit.
    Renamed,
}

/// One changed path, with the bytes on both sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    /// Head-side path. For a deletion, the path that was deleted.
    pub path: String,
    /// Base-side path, when the file moved.
    pub old_path: Option<String>,
    /// What happened.
    pub kind: ChangeKind,
    /// Base-side bytes. `None` when the file is new.
    pub base: Option<Vec<u8>>,
    /// Head-side bytes. `None` when the file was deleted.
    pub head: Option<Vec<u8>>,
    /// Head-side blob OID, for naming the bytes a finding is about.
    pub head_blob_oid: Option<String>,
}

impl FileChange {
    /// An added file.
    pub fn added(path: &str, head: &str) -> FileChange {
        FileChange {
            path: path.to_string(),
            old_path: None,
            kind: ChangeKind::Added,
            base: None,
            head: Some(head.as_bytes().to_vec()),
            head_blob_oid: None,
        }
    }

    /// An edited file.
    pub fn modified(path: &str, base: &str, head: &str) -> FileChange {
        FileChange {
            path: path.to_string(),
            old_path: None,
            kind: ChangeKind::Modified,
            base: Some(base.as_bytes().to_vec()),
            head: Some(head.as_bytes().to_vec()),
            head_blob_oid: None,
        }
    }

    /// A deleted file.
    pub fn deleted(path: &str, base: &str) -> FileChange {
        FileChange {
            path: path.to_string(),
            old_path: None,
            kind: ChangeKind::Deleted,
            base: Some(base.as_bytes().to_vec()),
            head: None,
            head_blob_oid: None,
        }
    }

    /// A moved file, content on both sides.
    pub fn renamed(old_path: &str, path: &str, base: &str, head: &str) -> FileChange {
        FileChange {
            path: path.to_string(),
            old_path: Some(old_path.to_string()),
            kind: ChangeKind::Renamed,
            base: Some(base.as_bytes().to_vec()),
            head: Some(head.as_bytes().to_vec()),
            head_blob_oid: None,
        }
    }

    /// Head bytes, or empty when the file was deleted.
    pub fn head_bytes(&self) -> &[u8] {
        self.head.as_deref().unwrap_or_default()
    }

    /// Base bytes, or empty when the file is new.
    pub fn base_bytes(&self) -> &[u8] {
        self.base.as_deref().unwrap_or_default()
    }

    /// The path the base side was at.
    pub fn base_path(&self) -> &str {
        self.old_path.as_deref().unwrap_or(&self.path)
    }

    /// Whether the bytes are unchanged — a pure rename, or a mode-only edit.
    ///
    /// Load-bearing for the test-removal detector: moving a test file must not
    /// read as deleting the tests in it.
    pub fn content_unchanged(&self) -> bool {
        match (&self.base, &self.head) {
            (Some(base), Some(head)) => base == head,
            _ => false,
        }
    }
}

/// The whole change.
///
/// Detectors read the set, not individual files, because the honest answers are
/// net answers: tests moved from one file to another are not tests removed, and
/// a suppression added in one file while two are removed in another is not a
/// rising suppression density.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeView {
    /// Every changed path, in the order the caller supplied. Detectors that care
    /// about order sort for themselves.
    pub files: Vec<FileChange>,
}

impl ChangeView {
    /// Build from a list of file changes, sorted by head path so that a
    /// detector's findings come out in one order on every machine.
    pub fn new(mut files: Vec<FileChange>) -> ChangeView {
        files.sort_by(|a, b| a.path.cmp(&b.path));
        ChangeView { files }
    }

    /// Whether the change touches anything at all.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Whether a path looks like a test file.
///
/// Path-shaped and deliberately generous: a detector that missed
/// `src/__tests__/user.ts` because it wanted `.test.ts` would be one rename away
/// from blind. The false-positive cost is bounded — a non-test file matching
/// these patterns still only fires a detector if its *contents* look like tests
/// being removed.
pub fn is_test_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower).to_string();
    let in_test_dir = lower.split('/').any(|segment| {
        matches!(
            segment,
            "test" | "tests" | "__tests__" | "spec" | "specs" | "e2e" | "testing"
        )
    });
    let named_as_test = name.starts_with("test_")
        || name.contains(".test.")
        || name.contains(".spec.")
        || name.contains("_test.")
        || name.contains("-test.")
        || name.contains(".steps.");
    in_test_dir || named_as_test
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paths_are_recognized_by_name_and_by_directory() {
        for path in [
            "src/user.test.ts",
            "src/user.spec.js",
            "tests/test_user.py",
            "src/__tests__/user.ts",
            "app/tests/helpers.py",
            "pkg/user_test.py",
        ] {
            assert!(is_test_path(path), "{path} should read as a test path");
        }
        for path in [
            "src/user.ts",
            "src/latest.ts",
            "src/contest.py",
            "docs/testing.md",
        ] {
            assert!(!is_test_path(path), "{path} should not read as a test path");
        }
    }

    #[test]
    fn a_pure_rename_is_visible_as_one() {
        let moved = FileChange::renamed("a/x.ts", "b/x.ts", "const a = 1;", "const a = 1;");
        assert!(moved.content_unchanged());
        assert_eq!(moved.base_path(), "a/x.ts");
        let edited = FileChange::renamed("a/x.ts", "b/x.ts", "const a = 1;", "const a = 2;");
        assert!(!edited.content_unchanged());
    }

    #[test]
    fn the_view_sorts_so_findings_come_out_in_one_order() {
        let view = ChangeView::new(vec![
            FileChange::added("z.ts", ""),
            FileChange::added("a.ts", ""),
        ]);
        assert_eq!(view.files[0].path, "a.ts");
    }
}
