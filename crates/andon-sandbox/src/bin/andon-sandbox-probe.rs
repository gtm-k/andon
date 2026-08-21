//! Probe for the sandbox behaviour tests — a real process the sandbox can
//! spawn, contain, and kill, portable across the three OS legs.
//!
//! Subcommands, one behaviour each:
//!
//! - `env-dump <file>` — write every environment variable NAME, one per line.
//! - `heartbeat <file>` — append one byte every 50ms, forever. The liveness
//!   signal: a stopped heartbeat is a dead process, observable without any
//!   process-inspection API.
//! - `spawn-orphan <file>` — spawn `heartbeat <file>` as a child, then sleep
//!   forever. The timeout-kill case: both this process and its child must die.
//! - `orphan-and-exit <file>` — spawn `heartbeat <file>`, exit 0 immediately.
//!   The sweep case: a passing command's stragglers must die too.
//! - `exit <code>` — exit with the code.
//! - `say <text>` — print the text to stdout and `err:<text>` to stderr.

use std::process::{Command, Stdio};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("env-dump") => {
            let names: Vec<String> = std::env::vars_os()
                .map(|(k, _)| k.to_string_lossy().into_owned())
                .collect();
            std::fs::write(&args[1], names.join("\n")).expect("env-dump write");
        }
        Some("heartbeat") => loop {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&args[1])
                .expect("heartbeat open");
            let _ = file.write_all(b".");
            drop(file);
            std::thread::sleep(std::time::Duration::from_millis(50));
        },
        Some("spawn-orphan") => {
            spawn_heartbeat(&args[1]);
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        Some("orphan-and-exit") => {
            spawn_heartbeat(&args[1]);
        }
        Some("exit") => {
            std::process::exit(args[1].parse().expect("an exit code"));
        }
        Some("say") => {
            println!("{}", args[1]);
            eprintln!("err:{}", args[1]);
        }
        other => {
            eprintln!("unknown probe subcommand {other:?}");
            std::process::exit(64);
        }
    }
}

/// The grandchild, with its stdio detached: the tests must observe its death
/// through the heartbeat file, never through a pipe it might hold open.
///
/// Never waited on — deliberately. The orphan is the test subject: the
/// sandbox's process-tree kill is what must reap it, and a probe that waited
/// would prove only that the probe can wait.
#[allow(clippy::zombie_processes)]
fn spawn_heartbeat(path: &str) {
    let me = std::env::current_exe().expect("current_exe");
    Command::new(me)
        .args(["heartbeat", path])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn heartbeat");
}
