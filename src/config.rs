use std::collections::HashSet;
use std::fs::Metadata;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use zeroize::Zeroizing;

/// Cap on files we read into memory through the credential / template path.
/// Lima templates are a few KiB in practice; the App PEM and webhook secret
/// are smaller still. A cap here protects us against being pointed at a
/// pathologically large file.
const MAX_PRIVATE_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Parser)]
#[command(name = "gh-actions-consumer", version, about)]
pub struct Config {
    /// Path to the gh-webhook-spool root (contains new/; we add cur/, done/, error/).
    #[arg(long, env = "SPOOL_DIR")]
    pub spool_dir: PathBuf,

    /// Per-process working state directory; holds JIT blobs, VM logs, etc.
    #[arg(long, env = "STATE_DIR")]
    pub state_dir: PathBuf,

    /// GitHub App numeric ID.
    #[arg(long, env = "GH_APP_ID")]
    pub app_id: u64,

    /// Path to the GitHub App's RSA private key (PEM).
    #[arg(long, env = "GH_APP_PRIVATE_KEY_FILE")]
    pub app_private_key_file: PathBuf,

    /// Webhook shared secret, read by HMAC re-verification on every claim.
    /// Inline form for ad-hoc use; prefer the file form below for daemons.
    #[arg(long, env = "GH_WEBHOOK_SECRET", hide_env_values = true)]
    pub webhook_secret: Option<String>,

    /// File containing the webhook shared secret (same secret the spool uses).
    /// One of `--webhook-secret` or this must be set; we re-verify HMAC
    /// independently of the spool.
    #[arg(long, env = "GH_WEBHOOK_SECRET_FILE")]
    pub webhook_secret_file: Option<PathBuf>,

    /// Repos we will accept jobs for, as `owner/name`. Comma-separated.
    /// The spool already enforces an allowlist; we re-enforce here as
    /// defence-in-depth against spool bugs or a tampered queue.
    #[arg(long, env = "GH_ALLOWED_REPOS", value_delimiter = ',')]
    pub allowed_repos: Vec<String>,

    /// Account login (owner) whose repositories we manage runners for. For a
    /// personal account this is your username; it's used to find the App
    /// installation and is the `owner` half of every repo in the allowlist.
    #[arg(long, env = "GH_ORG")]
    pub org: String,

    /// Gate label that workflows put in `runs-on` to opt into this factory.
    /// Must also appear in `runner_labels`.
    #[arg(long, env = "GH_RUNNER_LABEL", default_value = "lima-nix")]
    pub runner_label: String,

    /// Complete list of labels this factory is willing to advertise on a
    /// runner. A workflow_job's `labels` must be a subset of this; jobs
    /// requesting any label not in the set are dropped without minting a
    /// runner. This is the boundary that stops workflow files from
    /// fabricating runners with arbitrary trust labels (`prod`, `gpu`, …).
    #[arg(
        long,
        env = "GH_RUNNER_LABELS",
        value_delimiter = ',',
        default_values_t = default_runner_labels()
    )]
    pub runner_labels: Vec<String>,

    /// Maximum number of concurrent VMs.
    #[arg(long, env = "MAX_CONCURRENCY", default_value_t = 4)]
    pub max_concurrency: usize,

    /// Path to the Lima template YAML used as the base for each VM.
    #[arg(long, env = "LIMA_TEMPLATE")]
    pub lima_template: PathBuf,

    /// Absolute path to the `limactl` binary. No PATH lookup: a bare name
    /// would let the launch environment redirect every privileged host
    /// action through an attacker-chosen binary. Production deployments
    /// should point this at a Nix-pinned store path.
    #[arg(long, env = "LIMACTL_PATH")]
    pub limactl_path: PathBuf,

    /// Seconds between GC sweeps.
    #[arg(long, env = "GC_INTERVAL_SECS", default_value_t = 300)]
    pub gc_interval_secs: u64,

    /// Hard ceiling on a single job's runtime; longer-lived VMs are GC'd and
    /// the in-VM `limactl shell` is killed via kill_on_drop.
    #[arg(long, env = "JOB_MAX_RUNTIME_SECS", default_value_t = 6 * 60 * 60)]
    pub job_max_runtime_secs: u64,

    /// Per-request HTTP timeout for GitHub API calls.
    #[arg(long, env = "GH_API_TIMEOUT_SECS", default_value_t = 60)]
    pub api_timeout_secs: u64,

    /// GitHub API base URL (override for GHES). Must be `https://` so the
    /// bearer App JWT and installation tokens sent on every request aren't
    /// exposed on the wire. Set `GH_INSECURE_ALLOW_HTTP_API=true` to bypass
    /// only in local development.
    #[arg(long, env = "GH_API_URL", default_value = "https://api.github.com")]
    pub api_url: String,

    /// Dev-only escape hatch that permits an `http://` `GH_API_URL`. Off by
    /// default; bearer credentials would otherwise travel in clear text.
    #[arg(long, env = "GH_INSECURE_ALLOW_HTTP_API", default_value_t = false)]
    pub insecure_allow_http_api: bool,

    /// Optional loopback HTTP control endpoint for pause/resume/status, e.g.
    /// `127.0.0.1:9100`. Unset disables it. Non-loopback addresses are refused:
    /// the endpoint has no auth, so loopback is the trust boundary.
    #[arg(long, env = "CONTROL_ADDR")]
    pub control_addr: Option<String>,

    /// Master switch for the queued-job reconciler. When on, a periodic pass
    /// lists each allowed repo's still-`queued` workflow_jobs from GitHub and
    /// mints a runner for any that lacks one — the backstop that makes us
    /// correct despite GitHub's label-fungible runner matching (a runner we
    /// mint for one job can be handed an unrelated queued job). Requires the
    /// App's `Actions: read` permission; startup fails fast without it.
    #[arg(
        long,
        env = "RECONCILE_ENABLED",
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    pub reconcile_enabled: bool,

    /// Cadence of the reconciler pass. Kept separate from (and faster than)
    /// `GC_INTERVAL_SECS` so a stolen current-run job is re-minted promptly
    /// without running VM/runner cleanup every minute.
    #[arg(long, env = "RECONCILE_INTERVAL_SECS", default_value_t = 60)]
    pub reconcile_interval_secs: u64,

    /// When on, a finished runner's spool entry is finalized only after GitHub
    /// confirms its job left `queued`; a job still queued (our runner ran some
    /// other job) is logged as a steal. Off restores the legacy "runner exited
    /// => done" behavior. The reconciler is the correctness backstop either
    /// way; this keeps `done/` honest and recovers steals faster.
    #[arg(
        long,
        env = "JOB_COMPLETION_CHECK",
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    pub job_completion_check: bool,
}

fn default_runner_labels() -> Vec<String> {
    vec!["self-hosted".to_string(), "lima-nix".to_string()]
}

impl Config {
    pub fn ensure_paths(&mut self) -> Result<()> {
        // The spool root and new/ are owned by gh-webhook-spool's deployment,
        // so we don't create or chmod them — but we do depend on them being
        // strictly locked down: every file under new/ is a replayable signed
        // payload, and the consumer's same-uid trust model assumes nobody
        // else can drop forgeries into the queue. Verify the spooler's
        // hardening is actually in place rather than trusting deployment
        // order. The spooler sets both 0700 in `verify_dir_secure`.
        verify_strict_private_dir(&self.spool_dir)
            .with_context(|| format!("spool root {}", self.spool_dir.display()))?;
        let new_dir = self.spool_dir.join("new");
        verify_strict_private_dir(&new_dir).with_context(|| {
            format!(
                "spool new/ ({}); is SPOOL_DIR pointing at the spool root?",
                new_dir.display()
            )
        })?;
        // Lock down the subdirectories we create, since they hold in-flight
        // job bodies and per-job logs.
        for sub in ["cur", "done", "error"] {
            ensure_private_dir(&self.spool_dir.join(sub))?;
        }
        ensure_private_dir(&self.state_dir)?;
        for sub in ["instances", "logs"] {
            ensure_private_dir(&self.state_dir.join(sub))?;
        }
        // Validate the operator-supplied LIMA_TEMPLATE, then stage a copy
        // inside state_dir (which we just chmod'd to 0700, ours). Anything
        // downstream — including `limactl start` — reads the staged copy,
        // closing the TOCTOU window between our `require_trusted_template`
        // stat and limactl's later open.
        let staged = self.state_dir.join("lima-template.yaml");
        stage_trusted_template(&self.lima_template, &staged)?;
        self.lima_template = staged;
        // limactl is the sole entrypoint for every privileged host action
        // (VM start/stop/delete, shelling into the guest). A bare name or
        // attacker-writable file here would turn that into arbitrary code
        // execution as the daemon user, so reject both at startup.
        verify_trusted_executable(&self.limactl_path)
            .with_context(|| format!("LIMACTL_PATH {}", self.limactl_path.display()))?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.allowed_repos.is_empty() {
            anyhow::bail!("GH_ALLOWED_REPOS is empty; refusing to start with no repo allowlist");
        }
        if !self.runner_labels.iter().any(|l| l == &self.runner_label) {
            anyhow::bail!(
                "GH_RUNNER_LABEL `{}` is not in GH_RUNNER_LABELS {:?}; \
                 the gate label must be advertised",
                self.runner_label,
                self.runner_labels
            );
        }
        // Zero is a footgun rather than a useful value: MAX_CONCURRENCY=0
        // makes every claimed job wait forever on the semaphore (leaking
        // cur/ entries until GC sweeps them to error/), GC_INTERVAL_SECS=0
        // panics inside tokio::time::interval, JOB_MAX_RUNTIME_SECS=0 kills
        // every job the instant it starts, and a 0s HTTP timeout cancels
        // every GitHub API call before the TCP handshake completes. Reject
        // each at startup with a specific message rather than letting the
        // daemon limp.
        if self.max_concurrency == 0 {
            anyhow::bail!("MAX_CONCURRENCY must be >= 1");
        }
        if self.gc_interval_secs == 0 {
            anyhow::bail!("GC_INTERVAL_SECS must be >= 1");
        }
        if self.reconcile_interval_secs == 0 {
            anyhow::bail!("RECONCILE_INTERVAL_SECS must be >= 1");
        }
        if self.job_max_runtime_secs == 0 {
            anyhow::bail!("JOB_MAX_RUNTIME_SECS must be >= 1");
        }
        if self.api_timeout_secs == 0 {
            anyhow::bail!("GH_API_TIMEOUT_SECS must be >= 1");
        }
        // The VM reaper (startup orphan reap + stale-image sweep, see gc.rs)
        // runs unconditionally and archives a reaped job's cur/ claim to error/.
        // Only the reconciler re-mints a runner for a job GitHub still reports
        // queued, so with reconciliation off a claimed-but-still-queued job
        // whose VM is reaped would be stranded. Refuse the unsafe combination
        // up front rather than silently dropping such jobs.
        if !self.reconcile_enabled {
            anyhow::bail!(
                "RECONCILE_ENABLED must be true: the VM reaper relies on the \
                 reconciler to re-mint any reaped job still queued on GitHub; \
                 with reconciliation disabled a claimed-but-queued job whose VM \
                 is reaped would be stranded"
            );
        }
        // GitHub App JWTs, installation tokens, and JIT config requests all
        // ride this base URL with bearer credentials in the Authorization
        // header. An http:// override leaks those credentials to anyone on
        // the network path; refuse outright unless an operator explicitly
        // opts in for local development.
        if !self.api_url.starts_with("https://") && !self.insecure_allow_http_api {
            anyhow::bail!(
                "GH_API_URL must be https:// (got {:?}); set \
                 GH_INSECURE_ALLOW_HTTP_API=true only for local development",
                self.api_url
            );
        }
        // Fail fast on a malformed/non-loopback control address rather than at
        // server-spawn time.
        self.control_socket_addr()?;
        Ok(())
    }

    /// Parse and validate `CONTROL_ADDR`. `None` when unset. Errors if it isn't
    /// a valid socket address or isn't a loopback address (the control endpoint
    /// has no auth, so it must not be exposed off-host).
    pub fn control_socket_addr(&self) -> Result<Option<SocketAddr>> {
        let Some(s) = &self.control_addr else {
            return Ok(None);
        };
        let addr: SocketAddr = s
            .parse()
            .with_context(|| format!("CONTROL_ADDR {s:?} is not a valid socket address"))?;
        if !addr.ip().is_loopback() {
            anyhow::bail!(
                "CONTROL_ADDR {addr} is not loopback; the control endpoint has no auth \
                 and must bind a loopback address"
            );
        }
        Ok(Some(addr))
    }

    pub fn allowed_repos_set(&self) -> HashSet<String> {
        self.allowed_repos.iter().cloned().collect()
    }

    pub fn runner_labels_set(&self) -> HashSet<String> {
        self.runner_labels.iter().cloned().collect()
    }

    pub fn load_webhook_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        if let Some(s) = &self.webhook_secret {
            if s.is_empty() {
                anyhow::bail!("GH_WEBHOOK_SECRET is set but empty");
            }
            return Ok(Zeroizing::new(s.as_bytes().to_vec()));
        }
        if let Some(path) = &self.webhook_secret_file {
            let mut bytes = read_private_file(path)
                .with_context(|| format!("read webhook secret file {}", path.display()))?;
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            if bytes.is_empty() {
                anyhow::bail!("webhook secret file is empty");
            }
            return Ok(bytes);
        }
        anyhow::bail!("set GH_WEBHOOK_SECRET or GH_WEBHOOK_SECRET_FILE")
    }
}

/// Ensure a private working directory exists at `p` with mode 0700, owned by
/// us, and that the path itself is not a symlink. We check with
/// `symlink_metadata` first so a pre-existing symlink at `p` can't redirect
/// our subsequent `set_permissions` (chmod-follows-symlinks) onto a foreign
/// target. Ownership is checked too, since `create_dir_all` is a silent
/// no-op when the path already exists.
fn ensure_private_dir(p: &Path) -> Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(md) => {
            if md.file_type().is_symlink() {
                anyhow::bail!(
                    "{} is a symlink; refusing to manage it (point at a real directory)",
                    p.display()
                );
            }
            if !md.file_type().is_dir() {
                anyhow::bail!("{} exists but is not a directory", p.display());
            }
            require_owned_by_us(p, &md)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(p).with_context(|| format!("create {}", p.display()))?;
        }
        Err(e) => return Err(e).with_context(|| format!("lstat {}", p.display())),
    }
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", p.display()))?;
    Ok(())
}

/// Verify a pre-existing directory is a real (non-symlink) directory owned
/// by us with no group/other access bits. Unlike `ensure_private_dir`, this
/// neither creates nor chmods — it's the right primitive for paths whose
/// lifecycle we don't own (the spool root and new/, owned by the spooler).
fn verify_strict_private_dir(p: &Path) -> Result<()> {
    let md = std::fs::symlink_metadata(p).with_context(|| format!("stat {}", p.display()))?;
    if md.file_type().is_symlink() {
        anyhow::bail!(
            "{} is a symlink; point at the real directory so the spooler's hardening applies",
            p.display()
        );
    }
    if !md.file_type().is_dir() {
        anyhow::bail!("{} is not a directory", p.display());
    }
    require_owned_by_us(p, &md)?;
    let mode = md.permissions().mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "{} has mode {:04o}; require 0700 or stricter (gh-webhook-spool sets this)",
            p.display(),
            mode & 0o777
        );
    }
    Ok(())
}

/// Read a credential file (PEM, webhook secret) into memory, refusing to
/// follow symlinks and enforcing 0600 + same-uid ownership.
///
/// The previous code did `symlink_metadata` + `std::fs::read` as two distinct
/// syscalls, leaving a TOCTOU window where an attacker with write access to
/// the containing directory could swap a 0600 file they own in between. Here
/// we open with `O_NOFOLLOW | O_NONBLOCK` first, then fstat the resulting fd
/// — the inode is fixed for the rest of the call, so the metadata and the
/// read both observe the same file.
pub fn read_private_file(p: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)
        .with_context(|| format!("open {}", p.display()))?;
    let md = f
        .metadata()
        .with_context(|| format!("fstat {}", p.display()))?;
    // O_NOFOLLOW above refuses to traverse a symlink at the final path
    // component, but the fd could still point at a directory or special file
    // if the path happened to name one. Re-check after fstat.
    if !md.file_type().is_file() {
        anyhow::bail!("{} is not a regular file", p.display());
    }
    require_owned_by_us(p, &md)?;
    let mode = md.permissions().mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "{} has mode {:04o}; must be readable only by the owner (chmod 600)",
            p.display(),
            mode & 0o777
        );
    }
    if md.len() > MAX_PRIVATE_FILE_BYTES {
        anyhow::bail!(
            "{} is {} bytes; exceeds {}-byte cap for credential files",
            p.display(),
            md.len(),
            MAX_PRIVATE_FILE_BYTES
        );
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(md.len() as usize));
    f.read_to_end(&mut bytes)
        .with_context(|| format!("read {}", p.display()))?;
    Ok(bytes)
}

fn require_owned_by_us(p: &Path, md: &Metadata) -> Result<()> {
    // SAFETY: geteuid is always safe.
    let our_uid = unsafe { libc::geteuid() };
    if md.uid() != our_uid {
        anyhow::bail!(
            "{} is owned by uid {} but this process runs as uid {}",
            p.display(),
            md.uid(),
            our_uid
        );
    }
    Ok(())
}

/// Looser counterpart to `require_owned_by_us`: accepts files owned by root.
/// The daemon usually runs unprivileged, and the binaries it execs (limactl)
/// live under root-owned trees like `/nix/store` or `/usr/local`. Anything
/// outside {us, root} is a foreign uid we don't trust.
fn require_owned_by_us_or_root(p: &Path, md: &Metadata) -> Result<()> {
    // SAFETY: geteuid is always safe.
    let our_uid = unsafe { libc::geteuid() };
    if md.uid() != our_uid && md.uid() != 0 {
        anyhow::bail!(
            "{} is owned by uid {}; expected root (0) or this process's uid {}",
            p.display(),
            md.uid(),
            our_uid
        );
    }
    Ok(())
}

/// Validate that `p` is safe to hand to `Command::new` as the *only* allowed
/// host-side entrypoint.
///
/// We can't stage a copy the way `stage_trusted_template` does — re-execing
/// out of state_dir would break macOS code signing. Instead we stat-in-place
/// via an `O_NOFOLLOW` open + `fstat`, the same TOCTOU-closing trick used by
/// `read_private_file`. Required properties:
///
/// - **Absolute path.** A bare name (or anything relative) makes `execvp`
///   walk `$PATH`, which the launch environment controls.
/// - **Regular file.** Not a directory, fifo, socket, or device.
/// - **Owned by root or us.** A foreign-uid binary in our exec path is
///   either a misconfiguration or hostile.
/// - **No group/world write.** Otherwise another local user could swap the
///   bytes between our check and `exec`.
/// - **Some execute bit set.** Surfaces "not executable" as a clear startup
///   error rather than a confusing failure on first job dispatch.
fn verify_trusted_executable(p: &Path) -> Result<()> {
    if !p.is_absolute() {
        anyhow::bail!(
            "{} must be an absolute path; bare names trigger PATH lookup",
            p.display()
        );
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)
        .with_context(|| format!("open {}", p.display()))?;
    let md = f
        .metadata()
        .with_context(|| format!("fstat {}", p.display()))?;
    if !md.file_type().is_file() {
        anyhow::bail!("{} is not a regular file", p.display());
    }
    require_owned_by_us_or_root(p, &md)?;
    let mode = md.permissions().mode();
    if mode & 0o022 != 0 {
        anyhow::bail!(
            "{} mode {:04o} permits group/world write; an exec target must be \
             owner-writable only",
            p.display(),
            mode & 0o777
        );
    }
    if mode & 0o111 == 0 {
        anyhow::bail!(
            "{} mode {:04o} has no execute bit set",
            p.display(),
            mode & 0o777
        );
    }
    Ok(())
}

/// Validate the operator-supplied LIMA template and stage a copy inside our
/// private state directory, returning ownership of that copy via `dst`.
///
/// Why we copy instead of just stat'ing in place: the template path is
/// eventually opened by `limactl start`, not by us. Checking the source with
/// stat and then passing the same path along leaves a TOCTOU window where an
/// attacker who can write to any ancestor directory could swap the file in
/// between our check and limactl's open. By snapshotting the verified bytes
/// into `state_dir` (chmod 0700, owned by us) we anchor the file under a
/// directory whose ancestry we control, so limactl reads the exact bytes we
/// verified.
fn stage_trusted_template(src: &Path, dst: &Path) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(src)
        .with_context(|| format!("open {}", src.display()))?;
    let md = f
        .metadata()
        .with_context(|| format!("fstat {}", src.display()))?;
    if !md.file_type().is_file() {
        anyhow::bail!("{} is not a regular file", src.display());
    }
    require_owned_by_us(src, &md)?;
    let mode = md.permissions().mode();
    if mode & 0o022 != 0 {
        anyhow::bail!(
            "{} mode {:04o} permits group/world write; LIMA_TEMPLATE must be \
             owner-writable only",
            src.display(),
            mode & 0o777
        );
    }
    if md.len() > MAX_PRIVATE_FILE_BYTES {
        anyhow::bail!(
            "LIMA_TEMPLATE {} is {} bytes; exceeds {}-byte cap",
            src.display(),
            md.len(),
            MAX_PRIVATE_FILE_BYTES
        );
    }
    let mut contents = Vec::with_capacity(md.len() as usize);
    f.read_to_end(&mut contents)
        .with_context(|| format!("read {}", src.display()))?;

    // Replace any prior staged copy. We unlink first because `create_new`
    // would otherwise fail on the second startup. The unlink + create-new is
    // safe inside state_dir because that directory is 0700, owned by us, and
    // not reachable through any attacker-writable parent.
    if let Err(e) = std::fs::remove_file(dst) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e).with_context(|| format!("remove stale {}", dst.display()));
        }
    }
    let mut out = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dst)
        .with_context(|| format!("create {}", dst.display()))?;
    out.write_all(&contents)
        .with_context(|| format!("write {}", dst.display()))?;
    out.sync_all()
        .with_context(|| format!("fsync {}", dst.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_private_file_rejects_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        std::fs::write(&target, b"x").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // O_NOFOLLOW open refuses the symlink at the OS layer.
        let err = read_private_file(&link).unwrap_err().to_string();
        assert!(!err.is_empty(), "expected open to fail through symlink");
    }

    #[test]
    fn read_private_file_rejects_lax_modes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secret");
        std::fs::write(&p, b"x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = read_private_file(&p).unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "unexpected error: {err}");
    }

    #[test]
    fn read_private_file_returns_contents_for_0600_file_we_own() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secret");
        std::fs::write(&p, b"hunter2").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let bytes = read_private_file(&p).expect("0600 file owned by us should pass");
        assert_eq!(&bytes[..], b"hunter2");
    }

    #[test]
    fn ensure_private_dir_rejects_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = ensure_private_dir(&link).unwrap_err().to_string();
        assert!(
            err.contains("symlink"),
            "expected symlink rejection, got: {err}"
        );
    }

    #[test]
    fn ensure_private_dir_creates_and_chmods() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("private");
        ensure_private_dir(&p).unwrap();
        let md = std::fs::metadata(&p).unwrap();
        assert!(md.is_dir());
        assert_eq!(md.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn verify_strict_private_dir_accepts_0700_owned_dir() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("d");
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        verify_strict_private_dir(&p).expect("0700 dir owned by us should pass");
    }

    #[test]
    fn verify_strict_private_dir_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = verify_strict_private_dir(&link).unwrap_err().to_string();
        assert!(err.contains("symlink"), "unexpected error: {err}");
    }

    #[test]
    fn verify_strict_private_dir_rejects_group_readable() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("d");
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o750)).unwrap();
        let err = verify_strict_private_dir(&p).unwrap_err().to_string();
        assert!(
            err.contains("0750") || err.contains("0700"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_strict_private_dir_rejects_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope");
        let err = verify_strict_private_dir(&p).unwrap_err().to_string();
        assert!(!err.is_empty(), "expected an error for missing path");
    }

    #[test]
    fn stage_trusted_template_copies_into_dst_with_0600() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("template.yaml");
        std::fs::write(&src, b"vm:\n  type: vz\n").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o644)).unwrap();
        let state = dir.path().join("state");
        ensure_private_dir(&state).unwrap();
        let dst = state.join("lima-template.yaml");
        stage_trusted_template(&src, &dst).expect("stage trusted template");
        let md = std::fs::metadata(&dst).unwrap();
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&dst).unwrap(), b"vm:\n  type: vz\n");
    }

    #[test]
    fn stage_trusted_template_rejects_world_writable_source() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("template.yaml");
        std::fs::write(&src, b"x").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o666)).unwrap();
        let state = dir.path().join("state");
        ensure_private_dir(&state).unwrap();
        let dst = state.join("lima-template.yaml");
        let err = stage_trusted_template(&src, &dst).unwrap_err().to_string();
        assert!(err.contains("group/world write"), "unexpected error: {err}");
    }

    #[test]
    fn verify_trusted_executable_rejects_relative_path() {
        let err = verify_trusted_executable(Path::new("limactl"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("absolute"), "unexpected error: {err}");
    }

    #[test]
    fn verify_trusted_executable_rejects_missing() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope");
        // Path must be absolute so we reach the open() check, not the
        // is_absolute() check.
        assert!(p.is_absolute());
        let err = verify_trusted_executable(&p).unwrap_err().to_string();
        assert!(!err.is_empty(), "expected an error for missing path");
    }

    #[test]
    fn verify_trusted_executable_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = verify_trusted_executable(dir.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("regular file"), "unexpected error: {err}");
    }

    #[test]
    fn verify_trusted_executable_rejects_world_writable() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bin");
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = verify_trusted_executable(&p).unwrap_err().to_string();
        assert!(err.contains("group/world write"), "unexpected error: {err}");
    }

    #[test]
    fn verify_trusted_executable_rejects_non_executable() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bin");
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = verify_trusted_executable(&p).unwrap_err().to_string();
        assert!(err.contains("execute bit"), "unexpected error: {err}");
    }

    #[test]
    fn verify_trusted_executable_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real");
        std::fs::write(&target, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // O_NOFOLLOW refuses the symlink at the OS layer.
        let err = verify_trusted_executable(&link).unwrap_err().to_string();
        assert!(!err.is_empty(), "expected open to fail through symlink");
    }

    #[test]
    fn verify_trusted_executable_accepts_0755_file_we_own() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bin");
        std::fs::write(&p, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        verify_trusted_executable(&p).expect("0755 file owned by us should pass");
    }

    #[test]
    fn stage_trusted_template_replaces_existing_dst() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("template.yaml");
        std::fs::write(&src, b"new contents").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o644)).unwrap();
        let state = dir.path().join("state");
        ensure_private_dir(&state).unwrap();
        let dst = state.join("lima-template.yaml");
        std::fs::write(&dst, b"stale").unwrap();
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o600)).unwrap();
        stage_trusted_template(&src, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"new contents");
    }
}
