//! `andon init` — gate-shaped integration, installed and removable.
//!
//! # Gate-shaped, not menu-shaped
//!
//! PREMORTEM A2's tool is installed and never invoked: a menu of capabilities
//! an agent may consult and does not. What this module installs is the other
//! shape — hooks that *fire on their own* at the moments a gate belongs:
//!
//! - `--claude` installs a **Stop hook** for Claude Code (the gate at the end
//!   of every response) and registers the MCP server in `.mcp.json` so
//!   agent-initiated calls have a surface to land on.
//! - `--cursor` installs a **git pre-commit hook** (the gate at commit time)
//!   and registers the MCP server for Cursor. The rules file it writes is
//!   discoverability only — the *gate* is the hook, per the plan's A2
//!   coherence rule: a rules file suggests, a hook fires.
//! - `--ci` prints the generic CI recipe from `docs/ci-recipe.md`, compiled in
//!   so the printed recipe is the committed one.
//!
//! # Everything is additive, said aloud, and removable
//!
//! Every write merges into what is already there and refuses — with the exact
//! content to add by hand — rather than editing a file it does not own. Every
//! `--<harness> --remove` undoes exactly what the install wrote and nothing
//! else. And every run ends by saying what it wrote and where, because an
//! installer whose effects are invisible is one nobody can trust to undo.

use std::path::{Path, PathBuf};

use crate::args::Flags;

mod claude;
mod cursor;
pub mod hook;

/// The generic CI recipe, compiled in so `andon init --ci` prints exactly the
/// committed document.
const CI_RECIPE: &str = include_str!("../../../../docs/ci-recipe.md");

const INIT_USAGE: &str = "\
andon init --claude [--self-measure] [--remove] [--repo <PATH>]
andon init --cursor [--self-measure] [--remove] [--repo <PATH>]
andon init --ci

  --claude        install the Claude Code Stop hook (.claude/settings.json)
                  and register the MCP server (.mcp.json)
  --cursor        install the git pre-commit hook and register the MCP server
                  and rules file for Cursor (.cursor/)
  --ci            print the generic CI recipe (docs/ci-recipe.md)
  --self-measure  bake --self-measure into the installed hook, for a checkout
                  of Andon itself (applies [self_measure] excluded_paths)
  --remove        undo exactly what the matching install wrote
  --repo <PATH>   any path inside the repository (default: .)

Hooks call `andon hook <kind>`, so `andon` (and for MCP, `andon-mcp`) must be
on PATH for the account the harness runs as.";

/// `andon init`.
pub fn cmd_init(flags: &Flags) -> Result<String, String> {
    if flags.on("help") {
        return Ok(INIT_USAGE.to_string());
    }
    flags.reject_unknown(&["repo"])?;
    let repo = flags.path("repo", ".");
    let remove = flags.on("remove");
    let self_measure = flags.on("self-measure");

    match (flags.on("claude"), flags.on("cursor"), flags.on("ci")) {
        (true, false, false) => claude::run(&repo, self_measure, remove),
        (false, true, false) => cursor::run(&repo, self_measure, remove),
        (false, false, true) => Ok(CI_RECIPE.to_string()),
        (false, false, false) => Ok(INIT_USAGE.to_string()),
        _ => Err("one harness at a time: --claude, --cursor, or --ci".to_string()),
    }
}

/// What one install step did, for the closing report.
enum Step {
    /// A file was written or extended; the string says which and what for.
    Wrote(String),
    /// Nothing to do; the string says what was already in place.
    Already(String),
    /// A removal happened.
    Removed(String),
    /// Nothing to remove.
    Absent(String),
}

impl Step {
    fn line(&self) -> String {
        match self {
            Step::Wrote(s) => format!("  wrote      {s}"),
            Step::Already(s) => format!("  unchanged  {s}"),
            Step::Removed(s) => format!("  removed    {s}"),
            Step::Absent(s) => format!("  absent     {s}"),
        }
    }
}

fn report(title: &str, steps: &[Step], closing: &str) -> String {
    let mut out = format!("\n{title}\n\n");
    for step in steps {
        out.push_str(&step.line());
        out.push('\n');
    }
    if !closing.is_empty() {
        out.push('\n');
        out.push_str(closing);
        out.push('\n');
    }
    out
}

/// Read a JSON object from `path`, or an empty one where no file exists.
///
/// A file that exists and cannot be parsed is a refusal, never a clobber: the
/// installer does not own it, and "fix or move the broken file" is something
/// only its owner can decide.
fn read_json_object(path: &Path) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    if !path.exists() {
        return Ok(serde_json::Map::new());
    }
    let bytes = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&bytes).map_err(|e| {
        format!(
            "{} exists but is not valid JSON ({e}). Fix it first — this installer merges into \
             existing files and never overwrites one it cannot read.",
            path.display()
        )
    })?;
    match value {
        serde_json::Value::Object(map) => Ok(map),
        _ => Err(format!(
            "{} exists but its top level is not a JSON object, so there is nothing to merge \
             into. Fix it first.",
            path.display()
        )),
    }
}

/// Write a JSON object back, pretty, with a trailing newline.
fn write_json_object(
    path: &Path,
    map: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let mut text = serde_json::to_string_pretty(&serde_json::Value::Object(map.clone()))
        .map_err(|e| e.to_string())?;
    text.push('\n');
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The MCP server entry both harnesses register: the `andon-mcp` binary on
/// PATH, stdio transport.
fn mcp_server_entry() -> serde_json::Value {
    serde_json::json!({ "command": "andon-mcp" })
}

/// Merge the `andon` MCP server into a `mcpServers` file, additively.
fn install_mcp_server(path: &Path) -> Result<Step, String> {
    let mut root = read_json_object(path)?;
    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    let Some(servers) = servers.as_object_mut() else {
        return Err(format!(
            "{}: `mcpServers` is not an object; fix it first",
            path.display()
        ));
    };
    match servers.get("andon") {
        Some(existing) if *existing == mcp_server_entry() => {
            return Ok(Step::Already(format!(
                "{} already registers the andon MCP server",
                path.display()
            )));
        }
        Some(_) => {
            return Err(format!(
                "{} already has an `andon` MCP server configured differently. Not touching it. \
                 To use this build, set mcpServers.andon to {} yourself.",
                path.display(),
                mcp_server_entry()
            ));
        }
        None => {
            servers.insert("andon".to_string(), mcp_server_entry());
        }
    }
    write_json_object(path, &root)?;
    Ok(Step::Wrote(format!(
        "{} — registers the andon MCP server (measure_change, get_results, await_results, \
         explain_finding, get_ledger)",
        path.display()
    )))
}

/// Remove the `andon` MCP server entry this installer wrote.
fn remove_mcp_server(path: &Path) -> Result<Step, String> {
    if !path.exists() {
        return Ok(Step::Absent(format!("{}", path.display())));
    }
    let mut root = read_json_object(path)?;
    let Some(servers) = root.get_mut("mcpServers").and_then(|v| v.as_object_mut()) else {
        return Ok(Step::Absent(format!(
            "{} has no mcpServers entry",
            path.display()
        )));
    };
    match servers.get("andon") {
        None => {
            return Ok(Step::Absent(format!(
                "{} does not register andon",
                path.display()
            )))
        }
        Some(existing) if *existing != mcp_server_entry() => {
            return Err(format!(
                "{} has an `andon` MCP server this installer did not write; not removing it.",
                path.display()
            ));
        }
        Some(_) => {
            servers.remove("andon");
        }
    }
    if servers.is_empty() {
        root.remove("mcpServers");
    }
    write_json_object(path, &root)?;
    Ok(Step::Removed(format!(
        "the andon MCP server from {}",
        path.display()
    )))
}

/// The `andon hook <kind>` command line an installed hook runs, with
/// `--self-measure` baked in when the install asked for it.
fn hook_command(kind: &str, self_measure: bool) -> String {
    if self_measure {
        format!("andon hook {kind} --self-measure")
    } else {
        format!("andon hook {kind}")
    }
}

/// Where a git hook lives, asked of a **plain** git — deliberately not the
/// measurement wrapper.
///
/// The wrapper pins `core.hooksPath` to a decoy directory so that no hook can
/// fire inside a measurement, which is exactly right for measuring and
/// exactly wrong here: asked through the wrapper, this function would install
/// the gate into the decoy (it did — the smoke test found the hook in
/// `andon-hooks-disabled-by-design/`). The installer's job is the user's
/// repository as the user's own git sees it, worktrees and their real
/// `core.hooksPath` included, so it asks an unpinned subprocess.
fn git_hook_path(repo: &Path, name: &str) -> Result<PathBuf, String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--git-path"])
        .arg(format!("hooks/{name}"))
        .current_dir(repo)
        .output()
        .map_err(|e| format!("git could not be run: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse --git-path failed in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let answer = String::from_utf8_lossy(&output.stdout);
    let path = Path::new(answer.trim());
    Ok(if path.is_absolute() {
        path.to_path_buf()
    } else {
        // `--git-path` answers relative to the directory git ran in.
        repo.join(path)
    })
}
