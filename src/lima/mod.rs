// Thin wrapper around the `limactl` CLI.
//
// `stop` is best-effort and idempotent: --force swallows "already stopped" and
// its exit status is intentionally ignored (a VM may already be stopped). But
// `delete` is the reap *gate*: it must only report success once the instance is
// actually gone, so the GC reap guards can safely archive a claim and drop live
// state. `limactl delete --force` exits 0 even for an absent instance, so a
// clean exit-0 covers a genuinely-gone VM; on ANY other outcome (non-zero exit
// OR a timeout/command error) we re-check presence via `list` and return Err
// iff the instance survived (or if presence can't be determined). We never
// parse limactl's free-text output; only `list --json` is structured, and we
// only look at the `name` and `dir` fields there (`dir` is the per-instance
// directory holding the realized `lima.yaml`, which GC reads to learn each
// VM's booted guest image for stale-image reaping).
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

    /// Delete an instance. The contract is crisp: `delete` returns `Ok(())`
    /// **iff the VM is gone afterward**, and `Err` while it still exists (or
    /// when presence genuinely can't be determined — a conservative `Err`).
    /// Callers (GC's reap guards) rely on this to decide whether it's safe to
    /// archive a VM's claim and drop its live state: a delete that merely
    /// *spawned* limactl but left the VM (and its possibly-online runner) up
    /// must surface as `Err` so they retry instead of treating a live runner as
    /// unbacked.
    ///
    /// `limactl delete --force` exits 0 even for an already-absent instance (it
    /// logs "Ignoring non-existent instance" and succeeds), so a clean exit-0
    /// is the happy path: the VM is gone, no extra `list` call needed.
    ///
    /// On ANY failure to confirm that happy path — a non-zero exit (instance
    /// busy/locked, driver wedged) OR a `run_with_timeout` error/timeout (the
    /// command never produced a status) — we do NOT trust the failure to mean
    /// "still present": the VM may well have been reaped before limactl timed
    /// out or errored. We resolve the ambiguity the same way in both cases by
    /// re-checking presence via `instance_exists`: gone -> `Ok`, still present
    /// -> `Err`. A failure of the presence check itself propagates as `Err`
    /// (conservative — we couldn't prove the VM gone). Crucially we must not
    /// let the `?` on the delete command short-circuit past this re-check, so
    /// we capture its result rather than propagating.
    pub async fn delete(&self, name: &str) -> Result<()> {
        let mut cmd = Command::new(&self.bin);
        cmd.args(["delete", "--force", name]).kill_on_drop(true);
        // Capture (don't `?`-propagate): a timeout/wait error must still fall
        // through to the presence re-check below, since the VM may be gone.
        match run_with_timeout(cmd, DELETE_TIMEOUT, "limactl delete").await {
            Ok(status) if status.success() => return Ok(()),
            // Non-zero exit or command error/timeout: resolve via presence.
            // `instance_exists` failing propagates as a conservative Err.
            Ok(status) => {
                if self.instance_exists(name).await? {
                    anyhow::bail!("limactl delete {name} exited {status} and {name} still exists");
                }
            }
            Err(e) => {
                if self.instance_exists(name).await? {
                    return Err(e).with_context(|| {
                        format!("limactl delete {name} failed and {name} still exists")
                    });
                }
            }
        }
        Ok(())
    }

    /// True iff an instance with this exact name is still present per
    /// `limactl list`. Used by `delete` to turn a non-zero delete exit into a
    /// definitive "still present" / "actually gone" answer.
    async fn instance_exists(&self, name: &str) -> Result<bool> {
        let instances = self
            .list_instances()
            .await
            .with_context(|| format!("re-list to confirm delete of {name}"))?;
        Ok(instances.iter().any(|(n, _)| n == name))
    }

    /// Every existing Lima instance as `(name, instance_dir)`. The instance
    /// dir is the `.Dir` field (`build-prebuilt-image.sh` reads it the same
    /// way) and holds the realized `lima.yaml`; GC reads
    /// `<dir>/lima.yaml`'s `images:` `location:` to learn which guest image a
    /// VM was booted from for stale-image reaping. A row missing `dir` (older
    /// Lima, or a partially-realized instance) yields `None` so the caller can
    /// fail safe and skip it rather than misclassify.
    pub async fn list_instances(&self) -> Result<Vec<(String, Option<PathBuf>)>> {
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
        let mut instances = Vec::new();
        for line in out.stdout.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let v: serde_json::Value = match serde_json::from_slice(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(n) = v.get("name").and_then(|n| n.as_str()) {
                // `dir` is the lowercase JSON key for the Go `.Dir` field.
                let dir = v.get("dir").and_then(|d| d.as_str()).map(PathBuf::from);
                instances.push((n.to_string(), dir));
            }
        }
        Ok(instances)
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
