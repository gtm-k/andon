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
        Some("allocate") => {
            // Commit memory in chunks, TOUCHING each page rather than only
            // reserving it: a job-object memory limit counts committed pages, so
            // an untouched allocation can sit under the cap forever and the
            // probe would prove nothing.
            //
            // Chunked so the process grows visibly instead of asking for the
            // whole amount at once, which an allocator may refuse outright
            // without the cap ever being the thing that stopped it.
            let target_mb: usize = args[1].parse().expect("megabytes");
            let mut held: Vec<Vec<u8>> = Vec::new();
            for _ in 0..target_mb {
                let mut chunk = vec![0u8; 1024 * 1024];
                for page in chunk.chunks_mut(4096) {
                    page[0] = 1;
                }
                held.push(chunk);
            }
            // Read it back so nothing above can be optimised away.
            let live: usize = held.iter().map(|c| c[0] as usize).sum();
            println!("allocated {target_mb}MiB live={live}");
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
