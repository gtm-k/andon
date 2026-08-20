//! `andon-mcp` — Andon's measurement pipeline behind an MCP stdio server.
//!
//! stdout carries JSON-RPC and nothing else: one stray print corrupts the
//! stream, which is why nothing in this crate writes to stdout outside the
//! transport, and anything the process has to say goes to stderr.
//!
//! The runtime is single-threaded on purpose. The tools are synchronous
//! wrappers over the CLI's measurement pipeline, whose iteration counter
//! assumes one writer per process — executing tool calls one at a time IS the
//! concurrency design (see the crate docs).

#![warn(clippy::all)]

use rmcp::ServiceExt;

fn main() -> std::process::ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("andon-mcp: the async runtime could not start: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    let outcome = runtime.block_on(async {
        let service = andon_mcp::AndonMcp::new()
            .serve(rmcp::transport::stdio())
            .await?;
        service.waiting().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    match outcome {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("andon-mcp: {e}");
            std::process::ExitCode::from(1)
        }
    }
}
