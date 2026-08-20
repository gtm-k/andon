//! Shared machinery for driving the real `andon-mcp` binary over stdio.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use andon_core::git::Git;
use serde_json::{json, Value};

/// Fixture identity, matching `andon-cli/tests/common`.
pub const FIXTURE_NAME: &str = "Andon Golden";
/// See [`FIXTURE_NAME`].
pub const FIXTURE_EMAIL: &str = "golden@andon.invalid";
/// See [`FIXTURE_NAME`].
pub const FIXTURE_DATE: &str = "1767225600 +0000";

/// How long one JSON-RPC response may take before the test declares the
/// server hung. Generous, because a cold measure loads five engines.
const RESPONSE_WAIT: Duration = Duration::from_secs(120);

/// A running `andon-mcp` process and the reader thread draining its stdout.
pub struct Server {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
}

impl Server {
    /// Start the real binary with `repo` as its working directory.
    pub fn start(repo: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_andon-mcp"))
            .current_dir(repo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Inherited so a crash's message lands in the test output instead
            // of a closed pipe, and a full buffer can never deadlock the child.
            .stderr(Stdio::inherit())
            .spawn()
            .expect("andon-mcp starts");
        let stdin = child.stdin.take().expect("stdin is piped");
        let stdout = child.stdout.take().expect("stdout is piped");

        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });

        Server {
            child,
            stdin,
            lines,
            next_id: 0,
        }
    }

    /// Send `initialize` with the given protocol version, complete the
    /// handshake, and return the initialize result.
    pub fn initialize(&mut self, protocol_version: &str) -> Value {
        let result = self.request(
            "initialize",
            json!({
                "protocolVersion": protocol_version,
                "capabilities": {},
                "clientInfo": { "name": "conformance", "version": "0" },
            }),
        );
        self.notify("notifications/initialized", json!({}));
        result
    }

    /// Call one tool and return the `CallToolResult` value.
    pub fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )
    }

    /// One JSON-RPC request, answered or the test dies telling you which.
    pub fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }));

        loop {
            let line = self
                .lines
                .recv_timeout(RESPONSE_WAIT)
                .unwrap_or_else(|_| panic!("no response to {method} within {RESPONSE_WAIT:?}"));
            let message: Value = serde_json::from_str(line.trim_end_matches('\r'))
                .unwrap_or_else(|e| panic!("the server wrote a non-JSON line: {e}\n{line}"));
            // Anything that is not the answer to this id — a notification, a
            // server-initiated request — is not what conformance is asking
            // about here; skip rather than fail so the tests do not pin
            // incidental traffic.
            if message.get("id") != Some(&json!(id)) {
                continue;
            }
            if let Some(error) = message.get("error") {
                panic!("{method} answered with a protocol error: {error}");
            }
            return message["result"].clone();
        }
    }

    /// One JSON-RPC notification; nothing comes back.
    pub fn notify(&mut self, method: &str, params: Value) {
        self.send(&json!({ "jsonrpc": "2.0", "method": method, "params": params }));
    }

    fn send(&mut self, message: &Value) {
        let mut line = message.to_string();
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .expect("the server is reading its stdin");
        self.stdin.flush().expect("flush");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A repository with history, no remote, and a change in flight heavy enough
/// to carry MED+ findings: the state the agent surface exists for.
pub fn scratch_repo() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("a temporary directory");
    let bootstrap = Git::open(Path::new(env!("CARGO_MANIFEST_DIR"))).expect("a repository");
    bootstrap
        .cmd([
            "init",
            "--quiet",
            "--initial-branch=main",
            "--object-format=sha1",
        ])
        .arg(temp.path())
        .output()
        .expect("git init");
    let git = Git::open(temp.path()).expect("the fixture is a repository");
    for (key, value) in [
        ("user.name", FIXTURE_NAME),
        ("user.email", FIXTURE_EMAIL),
        ("core.autocrlf", "false"),
        ("core.eol", "lf"),
    ] {
        git.cmd(["config", key, value]).output().expect("config");
    }
    std::fs::write(temp.path().join("src.ts"), simple_source()).expect("write");
    git.cmd(["add", "--all", "."]).output().expect("add");
    commit_fixture(&git, "root");
    std::fs::write(temp.path().join("src.ts"), tangled_source()).expect("write");
    temp
}

/// Commit whatever is staged at the fixture identity.
pub fn commit_fixture(git: &Git, message: &str) {
    git.cmd(["commit", "--quiet", "--all", "-m", message])
        .env("GIT_AUTHOR_NAME", FIXTURE_NAME)
        .env("GIT_AUTHOR_EMAIL", FIXTURE_EMAIL)
        .env("GIT_AUTHOR_DATE", FIXTURE_DATE)
        .env("GIT_COMMITTER_NAME", FIXTURE_NAME)
        .env("GIT_COMMITTER_EMAIL", FIXTURE_EMAIL)
        .env("GIT_COMMITTER_DATE", FIXTURE_DATE)
        .output()
        .expect("git commit");
}

/// The base: a function nothing fires on.
pub fn simple_source() -> &'static str {
    "export function classify(x: number): number {\n  return x > 0 ? 1 : 0;\n}\n"
}

/// The change in flight: `classify` rewritten with nesting deep enough that
/// cognitive complexity crosses its declared Medium rung (15), so the
/// measurement carries a MED+ finding with a function-scoped location.
pub fn tangled_source() -> &'static str {
    concat!(
        "export function classify(x: number): number {\n",
        "  let out = 0;\n",
        "  if (x > 0) {\n",
        "    if (x > 1) {\n",
        "      if (x > 2) {\n",
        "        if (x > 3) {\n",
        "          if (x > 4) {\n",
        "            if (x > 5) {\n",
        "              out = 6;\n",
        "            } else {\n",
        "              out = 5;\n",
        "            }\n",
        "          }\n",
        "        }\n",
        "      }\n",
        "    }\n",
        "  }\n",
        "  if (x < 0 && x > -10) {\n",
        "    out = -1;\n",
        "  }\n",
        "  return out;\n",
        "}\n",
    )
}
