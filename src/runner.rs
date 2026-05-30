// Per-job state machine.
//
// One call to `run_job` represents the entire life of a single workflow_job:
// mint a JIT runner config from GitHub, boot a Lima VM, drop the config into
// the VM, run the runner agent synchronously inside the VM, and then tear
// down the VM and deregister the runner.
//
// We split happy-path work from teardown so that teardown always runs, even
// on partial failure. Lima's stop/delete are idempotent, and we ignore 404
// when deleting the GH runner because a clean runner exit deregisters it.
//
// The JIT blob is a single-use runner registration. We write it to host
// scratch with mode 0o600 and unlink it on teardown.
//
// VM identity is derived from the signed workflow_job (repository.full_name
// + workflow_job.id), not from the webhook envelope. The HMAC covers the
// body but not the envelope, so an attacker who can write to the queue
// could replay an old body under a new delivery id. Tying VM identity to
// the body means a replay produces the same VM name; the second
// `limactl start` collides with an existing VM and refuses to boot.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use crate::config::Config;
use crate::github::event::WorkflowJob;
use crate::github::jit::{GhClient, JitConfigResp};
use crate::lima::Lima;
use crate::spool::sanitize_for_log;

pub struct Job {
    pub event: WorkflowJob,
}

impl Job {
    pub fn vm_name(&self) -> String {
        vm_name_for_event(&self.event)
    }
}

pub async fn run_job(
    job: Job,
    config: Arc<Config>,
    gh: Arc<GhClient>,
    lima: Arc<Lima>,
) -> Result<()> {
    let vm_name = job.vm_name();

    // Labels were validated against runner_labels in the supervisor; we
    // pass them through unchanged so the runner advertises exactly what
    // the workflow asked for (no broader).
    let labels: Vec<&str> = job
        .event
        .workflow_job
        .labels
        .iter()
        .map(|s| s.as_str())
        .collect();

    // Repo-scoped JIT: the resulting runner can only execute jobs from
    // this owner/repo even if the runner group permits others.
    let (owner, repo) = split_full_name(&job.event.repository.full_name)
        .with_context(|| format!("repo name: {}", job.event.repository.full_name))?;
    let jit = gh
        .generate_jit_config(owner, repo, &vm_name, &labels)
        .await
        .context("mint JIT runner config")?;

    let inner = run_in_vm(&job, &vm_name, &config, &lima, &jit).await;
    // Capture the guest serial console BEFORE teardown deletes the VM (and its
    // serialv.log with it). Runs regardless of `inner`: an in-guest build OOM
    // kills the build but the runner agent still exits 0, so the job finalizes
    // to done/ — an error-only capture would miss exactly that case.
    capture_oom_evidence(
        &vm_name,
        job.event.workflow_job.id,
        &config,
        &lima,
        inner.is_ok(),
    )
    .await;
    teardown(
        &vm_name,
        &config,
        Arc::clone(&gh),
        Arc::clone(&lima),
        owner,
        repo,
        jit.runner.id,
    )
    .await;
    inner
}

/// Bytes of guest serial console to scan for an OOM. The kernel OOM-killer
/// report and its surrounding dmesg context sit at the end of the log, so the
/// tail is enough and keeps the per-job read bounded.
const SERIAL_TAIL_BYTES: u64 = 64 * 1024;

/// Best-effort: before teardown destroys the VM, scan the guest serial console
/// for a kernel OOM and, if found, log it and preserve the tail for forensics.
///
/// Keys off the OOM signature in the console, NOT the job's pass/fail: the
/// failure we're chasing (an in-guest build OOM, surfacing in the runner log as
/// `build hook / unexpected EOF`) leaves the runner agent exiting 0, so the job
/// finalizes to done/. `inner_ok` only colors the log line for correlation.
///
/// Every failure here is logged and swallowed — capturing diagnostics must
/// never fail a job or delay the VM teardown that frees a concurrency slot.
async fn capture_oom_evidence(vm: &str, job_id: u64, config: &Config, lima: &Lima, inner_ok: bool) {
    let tail = match lima.serial_log_tail(vm, SERIAL_TAIL_BYTES).await {
        Ok(Some(t)) => t,
        Ok(None) => return,
        Err(e) => {
            warn!(vm, error = %format!("{e:#}"), "could not read guest serial console for OOM check");
            return;
        }
    };
    let Some(oom_line) = detect_guest_oom(&tail) else {
        return;
    };
    warn!(
        vm,
        job_id,
        finalized = if inner_ok { "done" } else { "error" },
        oom_line = %sanitize_for_log(oom_line),
        "guest OOM detected on serial console (VM died of in-guest memory pressure, not host)"
    );
    let dest = config
        .state_dir
        .join("logs")
        .join(format!("{vm}.serial.log"));
    match write_serial_evidence(&dest, tail.as_bytes()).await {
        Ok(()) => {
            info!(vm, path = %dest.display(), "preserved guest serial console tail for OOM forensics")
        }
        Err(e) => {
            warn!(vm, path = %dest.display(), error = %format!("{e:#}"), "could not preserve serial console tail")
        }
    }
}

/// Scan a guest serial-console tail for the Linux OOM-killer's signature,
/// returning the first matching line. The kernel emits `… Out of memory: Killed
/// process …` (and, for a cgroup limit, `Memory cgroup out of memory: …`) plus
/// an `oom-kill:` constraint line when it reaps a process to reclaim RAM.
/// Finding one means the *guest* ran out of memory and killed the build —
/// distinct from an incidental build failure, which leaves no such line. The
/// match is case-insensitive over the kernel's wording; we scan the console
/// (kernel dmesg), not the build's stdout (which the runner streams to GitHub),
/// so false positives are unlikely. Pure, so it's unit-tested directly.
fn detect_guest_oom(serial_tail: &str) -> Option<&str> {
    serial_tail.lines().find(|line| {
        let l = line.to_ascii_lowercase();
        l.contains("out of memory") || l.contains("oom-kill:")
    })
}

/// Write the serial-console tail to `path` owner-only (0600), overwriting any
/// prior capture for this VM (names are job-id-derived, so a re-capture reuses
/// the name). We unlink then `create_new` with `O_NOFOLLOW | O_NONBLOCK` rather
/// than truncate in place: `.mode()` only applies on creation, so an existing
/// symlink/FIFO or lax-perms file would otherwise be followed, truncated, or
/// block us — and this runs on OOM before the worker releases its VM slot. The
/// unlink+create races nobody: `state_dir/logs` is 0700 ours (same assumption
/// `stage_trusted_template` makes), so the file is born owner-only.
async fn write_serial_evidence(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    match fs::remove_file(path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("remove stale {}", path.display())),
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .mode(0o600)
        .open(path)
        .await?;
    f.write_all(contents).await?;
    f.sync_all().await?;
    Ok(())
}

async fn run_in_vm(
    job: &Job,
    vm_name: &str,
    config: &Config,
    lima: &Lima,
    jit: &JitConfigResp,
) -> Result<()> {
    let jit_host_path = jit_path(config, vm_name);
    write_jit_blob(&jit_host_path, jit.encoded_jit_config.as_bytes())
        .await
        .with_context(|| format!("write JIT blob to {}", jit_host_path.display()))?;

    lima.start(vm_name, &config.lima_template)
        .await
        .context("start Lima VM")?;
    lima.copy_into(vm_name, &jit_host_path, "/tmp/jit")
        .await
        .context("copy JIT blob into VM")?;

    let deadline = Duration::from_secs(config.job_max_runtime_secs);
    let exit = lima
        .shell(vm_name, &["sudo", "gha-run-once", "/tmp/jit"], deadline)
        .await
        .context("run gha-run-once")?;
    if !exit.success() {
        // repo.full_name and workflow_job.name are author-controlled even
        // though they're HMAC-signed; sanitize before splicing into the
        // error string so a workflow named with control characters can't
        // smuggle ANSI escapes or line breaks into the supervisor's log
        // line or the .err sidecar.
        anyhow::bail!(
            "runner exited non-zero ({}); repo={} job={}",
            exit,
            sanitize_for_log(&job.event.repository.full_name),
            sanitize_for_log(&job.event.workflow_job.name)
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn teardown(
    vm: &str,
    config: &Config,
    gh: Arc<GhClient>,
    lima: Arc<Lima>,
    owner: &str,
    repo: &str,
    runner_id: u64,
) {
    if let Err(e) = lima.stop(vm).await {
        warn!(vm, error = %e, "stop failed");
    }
    if let Err(e) = lima.delete(vm).await {
        warn!(vm, error = %e, "delete failed");
    }
    let _ = fs::remove_file(&jit_path(config, vm)).await;
    if let Err(e) = gh.delete_runner(owner, repo, runner_id).await {
        warn!(runner_id, error = %e, "delete runner failed");
    }
}

fn jit_path(config: &Config, vm: &str) -> PathBuf {
    config.state_dir.join("instances").join(format!("{vm}.jit"))
}

/// Owner/repo split. The full_name field is always `owner/repo` per the
/// GitHub schema; reject anything else as defence-in-depth. Each side is
/// further restricted to `[A-Za-z0-9._-]{1,100}` so a maliciously crafted
/// (but HMAC-signed) body can't slip URL-meaningful characters like `?`,
/// `#`, or `%` into the JIT-mint endpoint path.
fn split_full_name(full: &str) -> Result<(&str, &str)> {
    let (owner, repo) = full
        .split_once('/')
        .with_context(|| format!("expected owner/repo, got {full}"))?;
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        anyhow::bail!("not a single owner/repo pair: {full}");
    }
    if !is_safe_repo_segment(owner) || !is_safe_repo_segment(repo) {
        anyhow::bail!(
            "owner/repo {full} contains unsafe characters; \
             expected [A-Za-z0-9._-]{{1,100}} on each side"
        );
    }
    Ok((owner, repo))
}

fn is_safe_repo_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Derive a Lima-safe VM name from the signed `workflow_job.id`. GitHub
/// assigns globally-unique job IDs, so a u64 already namespaces across
/// repos. Using only this signed field means a replay produces the same
/// name; the second `limactl start` collides with the existing VM.
pub fn vm_name_for_event(event: &WorkflowJob) -> String {
    vm_name(event.workflow_job.id)
}

pub fn vm_name(job_id: u64) -> String {
    format!("gha-{job_id:016x}")
}

async fn write_jit_blob(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    // create_new(true) + mode(0o600) ensures we never write through an
    // existing file with permissive perms, and the file is born owner-only.
    // A stale file from a previous (crashed) attempt is itself a smell — the
    // caller should have either reused that VM or let teardown unlink it.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .await?;
    f.write_all(contents).await?;
    f.sync_all().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[tokio::test]
    async fn jit_blob_is_written_with_owner_only_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob.jit");
        write_jit_blob(&path, b"secret").await.unwrap();
        let md = std::fs::metadata(&path).unwrap();
        assert_eq!(md.mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
    }

    #[tokio::test]
    async fn jit_blob_refuses_to_clobber_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob.jit");
        std::fs::write(&path, b"stale").unwrap();
        let err = write_jit_blob(&path, b"new").await.unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("exists")
                || err
                    .downcast_ref::<std::io::Error>()
                    .map(|e| e.kind() == std::io::ErrorKind::AlreadyExists)
                    .unwrap_or(false)
        );
    }

    #[tokio::test]
    async fn write_serial_evidence_replaces_symlink_without_clobbering_target() {
        // A hostile/stale symlink sits at the evidence path. The unlink +
        // create_new(O_NOFOLLOW) must replace it with a fresh 0600 regular file
        // and leave whatever the link pointed at untouched.
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, b"untouched").unwrap();
        let dest = dir.path().join("gha-0000000000000001.serial.log");
        std::os::unix::fs::symlink(&secret, &dest).unwrap();

        write_serial_evidence(&dest, b"evidence").await.unwrap();

        assert_eq!(std::fs::read(&secret).unwrap(), b"untouched");
        let md = std::fs::symlink_metadata(&dest).unwrap();
        assert!(md.file_type().is_file(), "dest must be a regular file now");
        assert_eq!(md.mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&dest).unwrap(), b"evidence");
    }

    #[test]
    fn detect_guest_oom_matches_kernel_oom_report() {
        // A real OOM-killer report as it appears on the guest serial console,
        // with the `oom-kill:` constraint line and the `Out of memory: Killed
        // process` line. The first match (the oom-kill: line here) is returned.
        let tail = "[  123.456] systemd[1]: Started some.service\n\
             [  200.123] kernel: nix-daemon invoked oom-killer: gfp_mask=0x...\n\
             [  200.130] kernel: oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null)\n\
             [  200.140] kernel: Out of memory: Killed process 4567 (nix-daemon) total-vm:...\n";
        let hit = detect_guest_oom(tail).expect("OOM report must be detected");
        assert!(
            hit.contains("oom-kill:") || hit.contains("Out of memory"),
            "matched line should be an OOM line, got {hit:?}"
        );
    }

    #[test]
    fn detect_guest_oom_matches_cgroup_oom_case_insensitively() {
        let tail = "kernel: Memory cgroup out of memory: Killed process 99 (cc1plus)\n";
        assert!(
            detect_guest_oom(tail).is_some(),
            "cgroup OOM (lowercase 'out of memory') must match"
        );
    }

    #[test]
    fn detect_guest_oom_ignores_clean_and_eof_only_logs() {
        // The build-hook EOF symptom with NO kernel OOM line: memory was
        // incidental, so we must NOT cry OOM. (This string is what the runner
        // streams to GitHub, not the serial console — included to prove the
        // detector doesn't false-positive on it.)
        let eof_only = "[  10.0] systemd[1]: Reached target multi-user.target\n\
             runner: nix: while reading the response from the build hook: unexpected EOF reading a line\n";
        assert_eq!(detect_guest_oom(eof_only), None);
        assert_eq!(
            detect_guest_oom("normal boot log\nlocalhost login: \n"),
            None
        );
        assert_eq!(detect_guest_oom(""), None);
    }

    #[test]
    fn vm_name_is_deterministic_in_job_id() {
        assert_eq!(vm_name(42), vm_name(42));
        assert_ne!(vm_name(42), vm_name(43));
    }

    #[test]
    fn vm_name_shape() {
        let n = vm_name(0x123_4567_89ab);
        assert_eq!(n, "gha-00000123456789ab");
        let suf = &n[4..];
        assert_eq!(suf.len(), 16);
        assert!(suf
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn split_full_name_rejects_malformed() {
        assert_eq!(split_full_name("octo/cat").unwrap(), ("octo", "cat"));
        assert!(split_full_name("octo").is_err());
        assert!(split_full_name("octo/").is_err());
        assert!(split_full_name("/cat").is_err());
        assert!(split_full_name("a/b/c").is_err());
    }

    #[test]
    fn split_full_name_rejects_url_meaningful_chars() {
        // These would all parse as "owner/repo" under a naive split but slip
        // URL syntax into the JIT-mint endpoint path.
        assert!(split_full_name("octo/cat?x=y").is_err());
        assert!(split_full_name("octo/cat#frag").is_err());
        assert!(split_full_name("octo/cat%2e").is_err());
        assert!(split_full_name("octo/cat ").is_err());
        assert!(split_full_name("octo/cat\n").is_err());
        assert!(split_full_name("oct o/cat").is_err());
        // Length cap: 101 chars on either side is over.
        let too_long = "a".repeat(101);
        assert!(split_full_name(&format!("{too_long}/cat")).is_err());
        assert!(split_full_name(&format!("octo/{too_long}")).is_err());
    }

    #[test]
    fn split_full_name_accepts_realistic_names() {
        assert!(split_full_name("Octocat-Org/repo.name_with-dashes").is_ok());
        assert!(split_full_name("a/b").is_ok());
        assert!(split_full_name("digits-1/two_2.dot").is_ok());
    }
}
