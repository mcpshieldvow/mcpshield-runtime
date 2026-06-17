use std::process::Stdio;

use tokio::{
    io::{AsyncBufReadExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout},
};

use crate::RuntimeError;

/// A spawned child MCP server process with split I/O handles.
pub struct ChildProcess {
    pub stdin: ChildStdin,
    pub stdout: Lines<BufReader<ChildStdout>>,
    // Kept alive so the process is killed on drop (kill_on_drop = true).
    _child: Child,
}

impl ChildProcess {
    pub async fn spawn(command: &[String]) -> Result<Self, RuntimeError> {
        let (program, args) = command.split_first().ok_or_else(|| {
            RuntimeError::Transport(anyhow::anyhow!("server_command must not be empty"))
        })?;

        let mut child = tokio::process::Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| RuntimeError::Transport(e.into()))?;

        let stdin = child.stdin.take().expect("stdin was configured as piped");
        let stdout =
            BufReader::new(child.stdout.take().expect("stdout was configured as piped")).lines();

        Ok(Self {
            stdin,
            stdout,
            _child: child,
        })
    }

    /// Decompose into individual I/O handles, returning the child process guard separately.
    ///
    /// The caller must keep the returned [`Child`] alive (e.g. bound to `_child_guard`)
    /// for the duration of the transport session; dropping it kills the process.
    pub fn into_parts(self) -> (ChildStdin, Lines<BufReader<ChildStdout>>, Child) {
        (self.stdin, self.stdout, self._child)
    }
}
