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
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::process::Command;
use tracing::warn;

pub struct Lima {
    bin: PathBuf,
}

const START_TIMEOUT: Duration = Duration::from_secs(300);
const STOP_TIMEOUT: Duration = Duration::from_secs(60);
const DELETE_TIMEOUT: Duration = Duration::from_secs(60);
const COPY_TIMEOUT: Duration = Duration::from_secs(60);
const LIST_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on the wall-clock all the per-job `limactl` invocations can
/// consume *around* the job's own `shell` run (which is bounded separately by
/// its caller-supplied deadline). Summed from the individual command timeouts
/// with the multiplicity each occurs while a job's cur/ claim is held:
///
///   * `start` (boot) + `copy` (seed the JIT blob) before the run;
///   * one `list` for the post-run serial-console capture (`serial_log_tail`);
///   * `stop` + `delete` at teardown, plus one more `list` when `delete`
///     re-checks presence after a non-zero/timed-out delete.
///
/// (The remaining per-job work — writing the JIT blob, reading the serial tail,
/// the final rename — is local filesystem I/O with no timeout, negligible next
/// to these.) The GC adds this, plus a GitHub-API budget, to a job's runtime
/// budget when deciding a cur/ claim is a stale orphan rather than an in-flight
/// job; see `gc::cur_claim_max_age_secs`.
pub const VM_PER_JOB_COMMAND_BUDGET: Duration = Duration::from_secs(
    START_TIMEOUT.as_secs()
        + COPY_TIMEOUT.as_secs()
        + STOP_TIMEOUT.as_secs()
        + DELETE_TIMEOUT.as_secs()
        + 2 * LIST_TIMEOUT.as_secs(),
);

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
        Ok(self
            .list_instances_detailed()
            .await?
            .into_iter()
            .map(|i| (i.name, i.dir))
            .collect())
    }

    /// Like `list_instances` but also carries each instance's `status`
    /// (`Running`/`Stopped`/…). Used by the control endpoint's VM-snapshot
    /// poller to show the daemon's live view of its managed VMs.
    pub async fn list_instances_detailed(&self) -> Result<Vec<LimaInstance>> {
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
        Ok(parse_list_json(&out.stdout))
    }

    /// Read the tail of a VM's guest serial console, if one exists.
    ///
    /// Lima mirrors the guest kernel console to a file in the per-instance
    /// directory: `serialv.log` under the vz driver (our `runner-aarch64.yaml`)
    /// and `serial.log` under qemu. We resolve that directory the same way GC
    /// does — the `.Dir` field of `limactl list --json` — then try the vz name
    /// first and fall back to the qemu one. `Ok(None)` when the VM is gone, has
    /// no dir, or carries neither log; those are expected races, not errors.
    ///
    /// Only the last `max_bytes` are returned. The console accumulates the whole
    /// boot log, but a kernel OOM-killer report is at the *end* (the death), so
    /// a bounded tail keeps this cheap and never slurps a pathologically large
    /// file. This costs one extra `limactl list` per call; callers invoke it
    /// once per job, which is negligible against a VM lifecycle.
    pub async fn serial_log_tail(&self, name: &str, max_bytes: u64) -> Result<Option<String>> {
        let instances = self
            .list_instances()
            .await
            .context("list instances to locate serial console")?;
        let Some((_, Some(dir))) = instances.into_iter().find(|(n, _)| n == name) else {
            return Ok(None);
        };
        for fname in ["serialv.log", "serial.log"] {
            let path = dir.join(fname);
            match read_file_tail(&path, max_bytes).await {
                Ok(Some(tail)) => return Ok(Some(tail)),
                Ok(None) => continue,
                // A readable dir whose log we can't read is worth a warn, but
                // never fatal — diagnostics must not fail a job's teardown.
                Err(e) => {
                    warn!(path = %path.display(), error = %format!("{e:#}"), "read serial console tail")
                }
            }
        }
        Ok(None)
    }
}

/// Read the last `max_bytes` of a file as lossy UTF-8. `Ok(None)` if the file
/// does not exist (an expected race — the VM may have been reaped) or is not a
/// regular file. Seeks to `len - max_bytes` so a large console log costs only a
/// bounded read.
///
/// Opened with `O_NOFOLLOW | O_NONBLOCK` + a post-open fstat regular-file check,
/// the same hardening `spool::read_spool_file` uses: this runs before
/// `teardown()` frees the VM slot, so a symlink or FIFO named `serialv.log` in a
/// tampered instance dir must not be followed or block the open indefinitely.
async fn read_file_tail(path: &Path, max_bytes: u64) -> Result<Option<String>> {
    let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let mut f = match tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .await
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("open {}", path.display())),
    };
    // fstat the open fd (no TOCTOU): a FIFO/dir/socket named serialv.log lands
    // here; a symlink was already refused by O_NOFOLLOW above. Skip, don't read.
    let md = f
        .metadata()
        .await
        .with_context(|| format!("fstat {}", path.display()))?;
    if !md.file_type().is_file() {
        warn!(path = %path.display(), "serial console path is not a regular file; skipping");
        return Ok(None);
    }
    let len = md.len();
    if len > max_bytes {
        f.seek(std::io::SeekFrom::Start(len - max_bytes))
            .await
            .with_context(|| format!("seek {}", path.display()))?;
    }
    let mut buf = Vec::with_capacity(len.min(max_bytes) as usize);
    f.take(max_bytes)
        .read_to_end(&mut buf)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// One row of `limactl list --json`. We only read the fields we use; the JSON
/// keys are the lowercase Go field names (`name`, `dir`, `status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimaInstance {
    pub name: String,
    pub dir: Option<PathBuf>,
    pub status: Option<String>,
}

/// Parse `limactl list --json` output: one JSON object per line. Rows without a
/// `name`, and lines that don't parse, are skipped. Pure (no I/O) so it's unit
/// tested directly; both list methods funnel through it.
fn parse_list_json(stdout: &[u8]) -> Vec<LimaInstance> {
    let mut instances = Vec::new();
    for line in stdout.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
            instances.push(LimaInstance {
                name: name.to_string(),
                dir: v.get("dir").and_then(|d| d.as_str()).map(PathBuf::from),
                status: v.get("status").and_then(|s| s.as_str()).map(str::to_string),
            });
        }
    }
    instances
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_json_extracts_name_dir_status() {
        // One object per line, as `limactl list --json` emits. Includes a row
        // with no dir, a line without a name (skipped), and a malformed line
        // (skipped).
        let out = concat!(
            r#"{"name":"gha-0000000000000001","status":"Running","dir":"/Users/ci/.lima/gha-0000000000000001"}"#,
            "\n",
            r#"{"name":"gha-000000000000002a","status":"Stopped"}"#,
            "\n",
            r#"{"status":"Running","dir":"/x"}"#,
            "\n",
            "not json at all",
            "\n",
        );
        let got = parse_list_json(out.as_bytes());
        assert_eq!(
            got,
            vec![
                LimaInstance {
                    name: "gha-0000000000000001".into(),
                    dir: Some(PathBuf::from("/Users/ci/.lima/gha-0000000000000001")),
                    status: Some("Running".into()),
                },
                LimaInstance {
                    name: "gha-000000000000002a".into(),
                    dir: None,
                    status: Some("Stopped".into()),
                },
            ]
        );
    }

    #[test]
    fn parse_list_json_empty_is_empty() {
        assert!(parse_list_json(b"").is_empty());
        assert!(parse_list_json(b"\n\n").is_empty());
    }

    #[tokio::test]
    async fn read_file_tail_returns_last_bytes_or_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("serialv.log");
        tokio::fs::write(&p, b"0123456789abcdef").await.unwrap();
        // Tail smaller than the file: only the last bytes.
        assert_eq!(
            read_file_tail(&p, 4).await.unwrap().as_deref(),
            Some("cdef")
        );
        // Cap larger than the file: the whole file.
        assert_eq!(
            read_file_tail(&p, 1024).await.unwrap().as_deref(),
            Some("0123456789abcdef")
        );
        // Cap exactly the file length: the whole file (no seek).
        assert_eq!(
            read_file_tail(&p, 16).await.unwrap().as_deref(),
            Some("0123456789abcdef")
        );
    }

    #[tokio::test]
    async fn read_file_tail_missing_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.log");
        assert_eq!(read_file_tail(&missing, 64).await.unwrap(), None);
    }

    #[tokio::test]
    async fn read_file_tail_skips_non_regular_file() {
        // A directory where a serialv.log is expected: the post-open fstat
        // regular-file check returns None rather than trying to read it.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("serialv.log");
        std::fs::create_dir(&p).unwrap();
        assert_eq!(read_file_tail(&p, 64).await.unwrap(), None);
    }

    #[tokio::test]
    async fn read_file_tail_does_not_follow_symlink() {
        // O_NOFOLLOW must refuse a symlink at the log path so a tampered
        // instance dir can't redirect the read at a daemon-readable file.
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, b"do not read through").unwrap();
        let link = dir.path().join("serialv.log");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        let got = read_file_tail(&link, 64).await;
        assert!(
            !matches!(&got, Ok(Some(s)) if s.contains("do not read through")),
            "must not read through a symlink, got {got:?}"
        );
    }
}
