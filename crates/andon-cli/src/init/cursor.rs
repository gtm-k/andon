//! `andon init --cursor` — a git pre-commit gate, MCP registration, and a
//! rules file that is discoverability only.
//!
//! # The gate is the git hook, not the rules file
//!
//! Cursor reads `.cursor/rules/*.mdc` as guidance an agent *may* follow, and
//! guidance is menu-shaped: PREMORTEM A2's failure is precisely a tool whose
//! invocation depends on an agent choosing to. So the gate here is a **git
//! pre-commit hook** — a change that measures `block` does not become a
//! commit, whoever or whatever ran `git commit`. The rules file exists so the
//! agent knows the tool is there and what the hook will hold it to; it gates
//! nothing (PLAN round-1 A2-coherence).

use std::path::Path;

use super::{hook_command, install_mcp_server, remove_mcp_server, report, Step};

/// The marker naming this installer in every file it owns, so installs are
/// idempotent and removal never deletes what somebody else wrote.
const MARKER: &str = "installed by `andon init --cursor`";

fn pre_commit_script(self_measure: bool) -> String {
    format!(
        "#!/bin/sh\n\
         # Andon pre-commit gate — {MARKER}.\n\
         # A change that measures `block` (exit 2) or has escalated to a human\n\
         # (exit 3) does not become a commit. Remove with\n\
         # `andon init --cursor --remove`, or delete this file.\n\
         exec {}\n",
        hook_command("pre-commit", self_measure)
    )
}

fn rules_file() -> String {
    format!(
        "---\n\
         description: Andon measures every change and gates commits on the evidence\n\
         alwaysApply: true\n\
         ---\n\
         \n\
         <!-- {MARKER}; discoverability only — the gate is the git pre-commit hook -->\n\
         \n\
         This repository measures code changes with Andon.\n\
         \n\
         - A git pre-commit hook runs `andon hook pre-commit` on what you are about to\n\
         \x20 commit. A `block` verdict refuses the commit and prints the findings, each\n\
         \x20 located as `path:span:symbol`.\n\
         - To see the verdict before committing, call the `measure_change` MCP tool\n\
         \x20 (server `andon`), or run `andon measure` in the shell.\n\
         - Act on findings whose `diff_actionable` is true; a false there means the\n\
         \x20 finding is context, not something to fix inside this change — do not grind\n\
         \x20 on it.\n\
         - Every number carries evidence: `explain_finding` (or `andon explain\n\
         \x20 <metric-id>`) shows the claim behind it and what it does NOT predict.\n\
         - After the loop cap, the verdict becomes `escalate_to_human`: stop and hand\n\
         \x20 the change to a person.\n"
    )
}

/// Install or remove the Cursor integration at the repository root.
pub fn run(repo: &Path, self_measure: bool, remove: bool) -> Result<String, String> {
    let git = andon_core::git::Git::open(repo).map_err(|e| e.to_string())?;
    let root = git.facts().toplevel.clone();
    let hook_path = super::git_hook_path(repo, "pre-commit")?;
    let rules_path = root.join(".cursor").join("rules").join("andon.mdc");
    let mcp_path = root.join(".cursor").join("mcp.json");

    let steps = if remove {
        vec![
            remove_owned_file(&hook_path, "the andon pre-commit gate")?,
            remove_owned_file(&rules_path, "the andon rules file")?,
            remove_mcp_server(&mcp_path)?,
        ]
    } else {
        vec![
            install_pre_commit(&hook_path, self_measure)?,
            install_rules(&rules_path)?,
            install_mcp_server(&mcp_path)?,
        ]
    };

    let closing = if remove {
        "Nothing of Andon's remains in this repository's Cursor configuration or git hooks."
    } else {
        "The gate is the pre-commit hook; the rules file only tells the agent it exists. \
         `andon` and `andon-mcp` must be on PATH for whatever runs `git commit`. Undo \
         everything with `andon init --cursor --remove`."
    };
    Ok(report(
        if remove {
            "Cursor integration removed."
        } else {
            "Cursor integration installed."
        },
        &steps,
        closing,
    ))
}

fn install_pre_commit(path: &Path, self_measure: bool) -> Result<Step, String> {
    let wanted = pre_commit_script(self_measure);
    if path.exists() {
        let existing =
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if existing == wanted {
            return Ok(Step::Already(format!(
                "{} is already the andon gate",
                path.display()
            )));
        }
        if existing.contains(MARKER) {
            // Ours, from an earlier install (e.g. the flag changed): rewrite.
            write_script(path, &wanted)?;
            return Ok(Step::Wrote(format!(
                "{} — rewrote the andon gate",
                path.display()
            )));
        }
        return Err(format!(
            "{} already exists and was not written by this installer. Not touching it. To add \
             the gate yourself, make it run:\n\n    {}\n\n(exit 2 or 3 refuses the commit)",
            path.display(),
            hook_command("pre-commit", self_measure)
        ));
    }
    write_script(path, &wanted)?;
    Ok(Step::Wrote(format!(
        "{} — refuses a commit whose change measures `block`, whoever runs `git commit`",
        path.display()
    )))
}

fn write_script(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(path, content).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
}

fn install_rules(path: &Path) -> Result<Step, String> {
    let wanted = rules_file();
    if path.exists() {
        let existing =
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if existing == wanted {
            return Ok(Step::Already(format!(
                "{} is already current",
                path.display()
            )));
        }
        if !existing.contains(MARKER) {
            return Err(format!(
                "{} already exists and was not written by this installer. Not touching it.",
                path.display()
            ));
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(path, wanted).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Step::Wrote(format!(
        "{} — tells the agent the tool and the gate exist; gates nothing itself",
        path.display()
    )))
}

/// Delete a file this installer owns; refuse to delete anything else.
fn remove_owned_file(path: &Path, what: &str) -> Result<Step, String> {
    if !path.exists() {
        return Ok(Step::Absent(format!("{}", path.display())));
    }
    let existing = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !existing.contains(MARKER) {
        return Err(format!(
            "{} was not written by this installer; not removing it.",
            path.display()
        ));
    }
    std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Step::Removed(format!("{what} ({})", path.display())))
}
