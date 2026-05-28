// Thin wrapper around the `limactl` CLI.
//
// All operations are best-effort and idempotent where Lima allows: --force on
// stop and delete swallows "instance not found" / "already stopped". We never
// parse limactl's free-text output; only `list --json` is structured, and we
// only look at the `name` field there.
//
// Every invocation is wrapped with a timeout and `kill_on_drop(true)`. If the
// timeout fires (or the future is cancelled), the child Lima process is
// dropped, which sends SIGKILL via tokio so we don't leak a permit forever
// waiting on a wedged `limactl`. Defaults are conservative; `shell` takes a
// caller-provided deadline because that's where the workload runs and the
// natural ceiling is JOB_MAX_RUNTIME_SECS.
//
// The `limactl` binary is supplied by config (LIMACTL_PATH) so production
// deployments can pin to an absolute Nix-built path rather than relying on
// $PATH resolution at run time.

use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;

pub struct Lima {
    bin: PathBuf,
}

const START_TIMEOUT: Duration = Duration::from_secs(300);
const STOP_TIMEOUT: Duration = Duration::from_secs(60);
const DELETE_TIMEOUT: Duration = Duration::from_secs(60);
const COPY_TIMEOUT: Duration = Duration::from_secs(60);
const LIST_TIMEOUT: Duration = Duration::from_secs(30);

impl Lima {
    pub fn new(bin: PathBuf) -> Self {
        Self { bin }
    }

    pub async fn start(&self, name: &str, template: &Path) -> Result<()> {
        let mut cmd = Command::new(&self.bin);
        cmd.args(["start", "--tty=false", "--name", name])
            .arg(template)
            .kill_on_drop(true);
        let status = run_with_timeout(cmd, START_TIMEOUT, "limactl start").await?;
        if !status.success() {
            anyhow::bail!("limactl start {name} exited {status}");
        }
        Ok(())
    }

    pub async fn copy_into(&self, name: &str, host_path: &Path, vm_path: &str) -> Result<()> {
        let dest = format!("{name}:{vm_path}");
        let mut cmd = Command::new(&self.bin);
        cmd.arg("copy").arg(host_path).arg(&dest).kill_on_drop(true);
        let status = run_with_timeout(cmd, COPY_TIMEOUT, "limactl copy").await?;
        if !status.success() {
            anyhow::bail!(
                "limactl copy {} -> {dest} exited {status}",
                host_path.display()
            );
        }
        Ok(())
    }

    /// Run a command inside the VM and wait for it to exit. Caller provides
    /// the deadline; the natural value is JOB_MAX_RUNTIME_SECS for the runner
    /// invocation, much shorter for diagnostics.
    ///
    /// stdout/stderr are discarded: the only caller is the GitHub Actions
    /// runner agent, which streams workflow output to GitHub itself. Letting
    /// the child inherit our streams would funnel attacker-controlled bytes
    /// (control sequences, line-noise floods) straight into launchd / journald
    /// where they're harder to bound and sanitize than at the source.
    pub async fn shell(&self, name: &str, cmd: &[&str], deadline: Duration) -> Result<ExitStatus> {
        let mut c = Command::new(&self.bin);
        c.arg("shell")
            .arg(name)
            .arg("--")
            .args(cmd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        run_with_timeout(c, deadline, "limactl shell").await
    }

    pub async fn stop(&self, name: &str) -> Result<()> {
        let mut cmd = Command::new(&self.bin);
        cmd.args(["stop", "--force", name]).kill_on_drop(true);
        let _ = run_with_timeout(cmd, STOP_TIMEOUT, "limactl stop").await?;
        Ok(())
    }

    pub async fn delete(&self, name: &str) -> Result<()> {
        let mut cmd = Command::new(&self.bin);
        cmd.args(["delete", "--force", name]).kill_on_drop(true);
        let _ = run_with_timeout(cmd, DELETE_TIMEOUT, "limactl delete").await?;
        Ok(())
    }

    pub async fn list_names(&self) -> Result<Vec<String>> {
        let mut cmd = Command::new(&self.bin);
        // Capture stderr rather than letting it inherit: with no instances,
        // `limactl list` prints "No instance found ..." to stderr on every
        // (successful) sweep, which would otherwise spam the daemon log. Keep
        // it for the failure path so a real error still surfaces.
        cmd.args(["list", "--json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = cmd.spawn().context("spawn limactl list")?;
        let out = tokio::time::timeout(LIST_TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| anyhow::anyhow!("limactl list timed out after {:?}", LIST_TIMEOUT))?
            .context("wait limactl list")?;
        if !out.status.success() {
            anyhow::bail!(
                "limactl list exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        // `limactl list --json` emits one JSON object per line.
        let mut names = Vec::new();
        for line in out.stdout.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_slice(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(n) = v.get("name").and_then(|n| n.as_str()) {
                names.push(n.to_string());
            }
        }
        Ok(names)
    }
}

async fn run_with_timeout(
    mut cmd: Command,
    deadline: Duration,
    what: &'static str,
) -> Result<ExitStatus> {
    let mut child = cmd.spawn().with_context(|| format!("spawn {what}"))?;
    match tokio::time::timeout(deadline, child.wait()).await {
        Ok(Ok(status)) => Ok(status),
        Ok(Err(e)) => Err(e).with_context(|| format!("wait {what}")),
        Err(_) => {
            let _ = child.kill().await;
            anyhow::bail!("{what} timed out after {:?}", deadline)
        }
    }
}
