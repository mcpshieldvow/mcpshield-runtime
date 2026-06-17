use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::{message::check_policy_for_line, process::ChildProcess, McpRuntime, RuntimeError};

/// Run the stdio transport: bidirectional JSON-RPC proxy between the calling
/// process's stdin/stdout and the child MCP server process.
///
/// Policy is enforced on every `tools/call` and `resources/read` request.
/// Blocked requests receive a JSON-RPC error response; all other messages are
/// forwarded to the child unchanged and responses are relayed to the client.
pub async fn run(runtime: Arc<McpRuntime>) -> Result<(), RuntimeError> {
    let child = ChildProcess::spawn(&runtime.config().server_command).await?;
    let (mut child_stdin, child_stdout_lines, _child_guard) = child.into_parts();

    let mut client_in = BufReader::new(tokio::io::stdin()).lines();
    let mut client_out = tokio::io::stdout();

    // Bridge child stdout to a channel so we can select! across both directions.
    let (child_out_tx, mut child_out_rx) = tokio::sync::mpsc::channel::<String>(64);
    tokio::spawn(async move {
        let mut lines = child_stdout_lines;
        while let Ok(Some(line)) = lines.next_line().await {
            if child_out_tx.send(line).await.is_err() {
                break;
            }
        }
    });

    tracing::info!("stdio transport active");

    loop {
        tokio::select! {
            result = client_in.next_line() => {
                match result.map_err(|e| RuntimeError::Transport(e.into()))? {
                    None => break, // client closed stdin
                    Some(line) => {
                        if let Some(error_json) = check_policy_for_line(runtime.policy(), &line) {
                            tracing::warn!("stdio: policy blocked request; returning error to client");
                            write_line(&mut client_out, &error_json).await?;
                        } else {
                            write_line(&mut child_stdin, &line).await?;
                        }
                    }
                }
            }
            child_line = child_out_rx.recv() => {
                match child_line {
                    None => break, // child process exited
                    Some(line) => write_line(&mut client_out, &line).await?,
                }
            }
        }
    }

    tracing::info!("stdio transport shut down");
    Ok(())
}

async fn write_line<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    line: &str,
) -> Result<(), RuntimeError> {
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|e| RuntimeError::Transport(e.into()))?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|e| RuntimeError::Transport(e.into()))?;
    writer
        .flush()
        .await
        .map_err(|e| RuntimeError::Transport(e.into()))
}
