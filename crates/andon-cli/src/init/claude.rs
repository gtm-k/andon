//! `andon init --claude` — the Stop-hook gate and MCP registration for
//! Claude Code.
//!
//! # Why the Stop hook is the gate
//!
//! Claude Code's Stop hook fires when the agent finishes responding — the
//! moment "the change is done" is claimed. A hook that exits 2 there blocks
//! the stop and feeds its stderr back to the agent, which makes it exactly
//! gate-shaped: the agent cannot declare done past a `block` without reading
//! the findings. `andon hook claude-stop` (see [`super::hook`]) maps verdicts
//! onto that contract and stays silent when nothing is in flight, so a
//! chat-only session never hears from it.

use std::path::Path;

use super::{hook_command, install_mcp_server, remove_mcp_server, report, Step};

/// The one command the installed Stop hook runs.
fn stop_hook_entry(self_measure: bool) -> serde_json::Value {
    serde_json::json!({
        "hooks": [
            { "type": "command", "command": hook_command("claude-stop", self_measure) }
        ]
    })
}

/// Whether one configured hook command is ours, with or without the
/// `--self-measure` variant, so removal and idempotence survive a re-install
/// that changed the flag.
fn is_our_command(command: &serde_json::Value) -> bool {
    command.as_str().is_some_and(|c| {
        c == hook_command("claude-stop", false) || c == hook_command("claude-stop", true)
    })
}

/// Install or remove the Claude Code integration at the repository root.
pub fn run(repo: &Path, self_measure: bool, remove: bool) -> Result<String, String> {
    let git = andon_core::git::Git::open(repo).map_err(|e| e.to_string())?;
    let root = git.facts().toplevel.clone();
    let settings = root.join(".claude").join("settings.json");
    let mcp = root.join(".mcp.json");

    let steps = if remove {
        vec![remove_stop_hook(&settings)?, remove_mcp_server(&mcp)?]
    } else {
        vec![
            install_stop_hook(&settings, self_measure)?,
            install_mcp_server(&mcp)?,
        ]
    };

    let closing = if remove {
        "Nothing of Andon's remains in this repository's Claude Code configuration."
    } else {
        "Both entries need `andon` and `andon-mcp` on PATH for the account Claude Code runs \
         as. The Stop hook blocks only on a `block` verdict and says nothing when no change \
         is in flight. Undo everything with `andon init --claude --remove`."
    };
    Ok(report(
        if remove {
            "Claude Code integration removed."
        } else {
            "Claude Code integration installed."
        },
        &steps,
        closing,
    ))
}

fn install_stop_hook(path: &Path, self_measure: bool) -> Result<Step, String> {
    let mut root = super::read_json_object(path)?;
    let hooks = root.entry("hooks").or_insert_with(|| serde_json::json!({}));
    let Some(hooks) = hooks.as_object_mut() else {
        return Err(format!(
            "{}: `hooks` is not an object; fix it first",
            path.display()
        ));
    };
    let stop = hooks.entry("Stop").or_insert_with(|| serde_json::json!([]));
    let Some(stop) = stop.as_array_mut() else {
        return Err(format!(
            "{}: `hooks.Stop` is not an array; fix it first",
            path.display()
        ));
    };

    let already = stop.iter().any(|entry| {
        entry["hooks"]
            .as_array()
            .is_some_and(|list| list.iter().any(|h| is_our_command(&h["command"])))
    });
    if already {
        return Ok(Step::Already(format!(
            "{} already runs the andon Stop hook",
            path.display()
        )));
    }
    stop.push(stop_hook_entry(self_measure));
    super::write_json_object(path, &root)?;
    Ok(Step::Wrote(format!(
        "{} — a Stop hook running `{}`: blocks the agent's stop on a `block` verdict and \
         feeds it the findings",
        path.display(),
        hook_command("claude-stop", self_measure)
    )))
}

fn remove_stop_hook(path: &Path) -> Result<Step, String> {
    if !path.exists() {
        return Ok(Step::Absent(format!("{}", path.display())));
    }
    let mut root = super::read_json_object(path)?;
    let Some(hooks) = root.get_mut("hooks").and_then(|v| v.as_object_mut()) else {
        return Ok(Step::Absent(format!(
            "{} has no hooks entry",
            path.display()
        )));
    };
    let Some(stop) = hooks.get_mut("Stop").and_then(|v| v.as_array_mut()) else {
        return Ok(Step::Absent(format!(
            "{} has no Stop hooks",
            path.display()
        )));
    };

    let had_ours = stop.iter().any(|entry| {
        entry["hooks"]
            .as_array()
            .is_some_and(|list| list.iter().any(|h| is_our_command(&h["command"])))
    });
    if !had_ours {
        return Ok(Step::Absent(format!(
            "{} did not run the andon Stop hook",
            path.display()
        )));
    }
    for entry in stop.iter_mut() {
        if let Some(list) = entry.get_mut("hooks").and_then(|v| v.as_array_mut()) {
            list.retain(|h| !is_our_command(&h["command"]));
        }
    }
    // An entry whose only hook was ours is now an empty shell this installer
    // created; a still-populated entry belongs to somebody else and stays.
    stop.retain(|entry| {
        entry["hooks"]
            .as_array()
            .is_none_or(|list| !list.is_empty())
    });
    if stop.is_empty() {
        hooks.remove("Stop");
    }
    if hooks.is_empty() {
        root.remove("hooks");
    }
    super::write_json_object(path, &root)?;
    Ok(Step::Removed(format!(
        "the andon Stop hook from {}",
        path.display()
    )))
}
