// Spool consumption.
//
// The companion gh-webhook-spool writes one file per accepted webhook into
// `<root>/new/`, formatted as:
//
//     <JSON envelope line>\n<raw webhook body>
//
// We extend the maildir with `cur/`, `done/`, and `error/`. A claim is an
// atomic rename from new/<name> to cur/<name>; only one process can win.
// On success the file moves to done/, on failure to error/ with a sidecar
// `<name>.err` log next to it.
//
// Wire contract (envelope schema 1 or 2):
//   * Filename is `<workflow_job_id>.job` — a u64 from a signed body field.
//   * Envelope JSON carries the spool's copies of signed body fields
//     (repo_id, repo, action, workflow_job_id) plus unauthenticated header
//     data (event, delivery, received_at_ms) and the original HMAC.
//
// Trust posture: the spool runs in the same trust domain as us, but bugs in
// it (or an attacker who can write to new/) shouldn't get an attacker free
// runner capacity. We independently:
//   * skip non-regular-file entries (FIFOs, symlinks, dirs),
//   * open with O_NOFOLLOW + O_NONBLOCK and fstat the open fd; reject if not
//     a regular file (no TOCTOU window),
//   * cap file size and envelope-line size (defence against memory blowup),
//   * verify HMAC-SHA256 over the body using a shared webhook secret,
//   * require schema in 1..=2,
//   * require the filename's workflow_job_id to match envelope.workflow_job_id,
//   * cross-check every signed envelope field against the body it came from,
//   * require envelope.repo to be in our allowlist.
//
// VM names are derived from signed body fields only. See runner::vm_name.
//
// `watch` drives the supervisor: it first emits every name already in new/,
// then watches for new arrivals via `notify` and also rescans periodically
// in case a filesystem event is dropped.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use notify::{RecursiveMode, Watcher};
use serde::Deserialize;
use sha2::Sha256;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

/// Hard cap on a single spool file. The spool itself caps body at 5 MiB; we
/// allow some envelope overhead, and reject anything larger as a defence
/// against an attacker (or a buggy spool) writing a giant file that
/// exhausts memory at read time.
pub const MAX_FILE_BYTES: u64 = 6 * 1024 * 1024;

/// Hard cap on the JSON envelope line, well above the ~250 bytes the spool
/// produces.
pub const MAX_ENVELOPE_BYTES: usize = 4 * 1024;

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields are part of the spool contract; we only read some
pub struct Envelope {
    pub schema: u32,
    pub event: String,
    pub delivery: String,
    pub repo_id: u64,
    pub repo: String,
    pub action: String,
    pub workflow_job_id: u64,
    pub received_at_ms: u128,
    pub signature: String,
}

/// Process-global serialization of archive-marker mutations in `done/` and
/// `error/`.
///
/// Both `finalize_*` (which, on the supported steal/reconcile re-archive path,
/// can install a *fresh* marker over an expired one of the same job id at the
/// same path) and the GC prune (which deletes markers it has judged expired)
/// take this lock around their mutate-the-marker critical section. Without it a
/// prune that observed `done/<id>.job` as expired could, in the gap between that
/// observation and its `remove_file`, unlink a fresh marker a concurrent
/// finalize installed at that path — dropping the replay guard and completion
/// record for a job that just finished. There is no portable atomic
/// "unlink-this-inode" syscall, so mutual exclusion is the fix.
///
/// Sound because deployment is singleton per `SPOOL_DIR` (see the gc.rs header):
/// every writer to these directories lives in this process. A single global
/// mutex (rather than per-path) is fine — the critical sections are a couple of
/// renames/stats and concurrency is bounded by `MAX_CONCURRENCY`.
static ARCHIVE_MUTATION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

/// Acquire the process-global archive-mutation lock. Held across the
/// install-or-skip in `finalize_*` and the recheck-then-unlink in the GC prune.
/// See [`ARCHIVE_MUTATION_LOCK`].
pub async fn lock_archive_mutation() -> tokio::sync::MutexGuard<'static, ()> {
    ARCHIVE_MUTATION_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

pub struct Spool {
    root: PathBuf,
}

impl Spool {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn new_dir(&self) -> PathBuf {
        self.root.join("new")
    }
    pub fn cur_dir(&self) -> PathBuf {
        self.root.join("cur")
    }
    pub fn done_dir(&self) -> PathBuf {
        self.root.join("done")
    }
    pub fn error_dir(&self) -> PathBuf {
        self.root.join("error")
    }

    /// Atomically move `new/<name>` into `cur/<name>`, then stamp the file's
    /// mtime to now so the GC ages from when we took ownership, not from
    /// when the spool created the file in new/.
    ///
    /// Returns `Ok(None)` for any of:
    ///
    /// 1. **Missing.** `new/<name>` is already gone (another process won, or
    ///    it was hand-cleaned).
    /// 2. **Live collision.** `cur/<name>` already holds a claim. Plain
    ///    rename(2) on Unix/macOS would silently clobber, letting a duplicate
    ///    or forged `new/<name>` displace an in-flight entry; we use an
    ///    exclusive primitive so the rename fails instead. The stray new/
    ///    copy is unlinked so it stops being rescanned.
    /// 3. **Archived replay.** `done/<name>` or `error/<name>` already
    ///    exists, meaning we've already processed this `workflow_job_id`.
    ///    A replay would otherwise mint another JIT runner and boot another
    ///    VM for a job GitHub already considers finished — bounded but
    ///    wasteful (a concurrency slot tied up until `JOB_MAX_RUNTIME_SECS`
    ///    expires). Filenames are stable across the new→cur→done|error
    ///    transitions, so the archive presence check is exact.
    ///
    ///    Two checks: a pre-rename one as a fast path (most replays are
    ///    caught here without a needless rename+unlink), and a post-rename
    ///    one as the authority. The post-rename check closes the window
    ///    where the original entry finalizes out of cur/ between our
    ///    pre-check and our exclusive rename: without it, our rename would
    ///    succeed against the just-vacated slot and the supervisor would
    ///    mint a duplicate JIT runner. On a post-rename hit we unlink the
    ///    just-claimed `cur/<name>` ourselves; on a pre-rename hit we unlink
    ///    the stray `new/<name>`. Either way the replay stops being rescanned.
    ///
    /// The archive directories are 0700 owned by us, so the stat checks are
    /// authoritative — nothing outside our uid can race a file into them.
    pub async fn try_claim(&self, name: &str) -> Result<Option<PathBuf>> {
        self.try_claim_inner(name, std::future::ready(())).await
    }

    /// Test-seam variant. `between_checks` fires after the pre-rename
    /// archive check returns false and before `rename_no_clobber` runs;
    /// production calls it with `ready(())`. Tests pass a future that
    /// finalizes a concurrent original out of cur/, so the post-rename
    /// archive re-check exercises the race-closing branch.
    async fn try_claim_inner<F>(&self, name: &str, between_checks: F) -> Result<Option<PathBuf>>
    where
        F: std::future::Future<Output = ()>,
    {
        let from = self.new_dir().join(name);
        if self.is_archived(name).await {
            warn!(
                file = %sanitize_for_log(name),
                "replay of archived entry; removing new/ copy"
            );
            if let Err(e) = fs::remove_file(&from).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!(file = %sanitize_for_log(name), error = %e, "remove archived-replay new/ entry");
                }
            }
            return Ok(None);
        }
        between_checks.await;
        let to = self.cur_dir().join(name);
        match rename_no_clobber(&from, &to) {
            Ok(()) => {
                // Authoritative archive check. The pre-check above is a fast
                // path; between it and the rename, a concurrent finalize_*
                // could have moved the original out of cur/, freeing the
                // slot for this replay's rename to succeed against an
                // already-archived workflow_job_id. Undo the claim.
                if self.is_archived(name).await {
                    warn!(
                        file = %sanitize_for_log(name),
                        "replay finalized between pre-check and rename; reverting claim"
                    );
                    if let Err(e) = fs::remove_file(&to).await {
                        warn!(file = %sanitize_for_log(name), error = %e, "remove reverted claim from cur/");
                    }
                    return Ok(None);
                }
                stamp_mtime_now(&to);
                Ok(Some(to))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // cur/<name> already holds a claim. Either we crashed and
                // restarted while a VM is still alive (GC will eventually
                // expire that cur/ entry), or someone wrote a duplicate
                // new/<name> to try to displace it. Don't touch cur/; just
                // remove the new/ copy so we stop rescanning it.
                warn!(file = %sanitize_for_log(name), "duplicate claim: cur/ already holds this name; removing new/ copy");
                if let Err(e) = fs::remove_file(&from).await {
                    warn!(file = %sanitize_for_log(name), error = %e, "remove duplicate new/ entry");
                }
                Ok(None)
            }
            Err(e) => Err(e).with_context(|| format!("claim {name}")),
        }
    }

    /// True iff this `name` has already been finalized to done/ or error/.
    /// Used to reject replays of completed jobs before we burn a JIT mint
    /// and a VM boot on them.
    async fn is_archived(&self, name: &str) -> bool {
        fs::try_exists(self.done_dir().join(name))
            .await
            .unwrap_or(false)
            || fs::try_exists(self.error_dir().join(name))
                .await
                .unwrap_or(false)
    }

    pub async fn finalize_done(&self, cur_path: &Path) -> Result<()> {
        let name = cur_path.file_name().context("cur path has no filename")?;
        let dest = self.done_dir().join(name);
        // Serialize with the GC prune so it cannot unlink a marker we install
        // here in the window between its expiry check and its delete (see
        // lock_archive_mutation).
        let _guard = lock_archive_mutation().await;
        // archive renames, which preserves the source's claim-time mtime; stamp
        // the archive to now so its mtime is the *completion* time the
        // "completed" view (and future age-based pruning) reads. Stamp ONLY when
        // archive actually installed our file — on the idempotent path (source
        // already archived elsewhere) it leaves an existing marker untouched,
        // and re-stamping that would make an old completion look fresh.
        if archive(cur_path, &dest).await.context("move to done/")? {
            stamp_mtime_now(&dest);
        }
        Ok(())
    }

    pub async fn finalize_error(&self, cur_path: &Path, reason: &str) -> Result<()> {
        let name = cur_path.file_name().context("cur path has no filename")?;
        // Serialize with the GC prune (see finalize_done / lock_archive_mutation).
        // Held across the sidecar write too so the `.err` and its `.job` install
        // as one unit relative to a prune pass.
        let _guard = lock_archive_mutation().await;
        let err_path = self
            .error_dir()
            .join(format!("{}.err", name.to_string_lossy()));
        // Best-effort sidecar; if we can't write it, still attempt the rename
        // so the file doesn't get retried on next startup.
        let _ = fs::write(&err_path, reason).await;
        let dest = self.error_dir().join(name);
        // Stamp completion time only on an actual install (see finalize_done).
        if archive(cur_path, &dest).await.context("move to error/")? {
            stamp_mtime_now(&dest);
        }
        Ok(())
    }

    /// Mint a `cur/<job_id>.job` record directly from authenticated GitHub API
    /// data, bypassing `new/` and the HMAC ingress check. Used only by the
    /// reconciler to track a runner it mints for a still-`queued` job whose
    /// webhook we never claimed (e.g. it was stolen and archived, or never
    /// arrived). The record carries an HMAC we compute ourselves so it stays
    /// re-verifiable, and the canonical `<job_id>.job` filename means GC's
    /// `live_vm_names_from_cur` derives the matching `vm_name(job_id)`.
    ///
    /// Returns `Ok(None)` when a live `cur/<job_id>.job` already exists (a
    /// webhook claim, or a prior reconciler mint) — the exclusive rename is the
    /// dedup. Unlike `try_claim`, this deliberately does **not** consult
    /// `done/`/`error/`: the reconciler only mints for jobs GitHub reports as
    /// queued *right now*, so a stale archive of the same id (e.g. from a steal
    /// we finalized to `done/`) must not block re-minting. GitHub's queue is
    /// authoritative here, not our local archive.
    pub async fn write_synthetic_claim(
        &self,
        job: &crate::github::jit::JobStatus,
        full_name: &str,
        secret: &[u8],
    ) -> Result<Option<PathBuf>> {
        let name = format!("{}.job", job.id);
        let dst = self.cur_dir().join(&name);
        if fs::try_exists(&dst).await.unwrap_or(false) {
            return Ok(None);
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "action": "queued",
            "workflow_job": {
                "id": job.id,
                "run_id": job.run_id,
                "run_attempt": job.run_attempt,
                "name": job.name,
                "labels": job.labels,
            },
            "repository": { "id": job.repo_id, "full_name": full_name },
        }))
        .context("serialize synthetic body")?;
        let envelope = serde_json::to_vec(&serde_json::json!({
            "schema": 2,
            "event": "workflow_job",
            "delivery": format!("reconciler:{}", job.id),
            "repo_id": job.repo_id,
            "repo": full_name,
            "action": "queued",
            "workflow_job_id": job.id,
            "received_at_ms": 0,
            "signature": sign_body(secret, &body),
        }))
        .context("serialize synthetic envelope")?;
        let mut bytes = envelope;
        bytes.push(b'\n');
        bytes.extend_from_slice(&body);

        // Stage under a temp name in cur/ (0700, ours), then exclusive-rename
        // to the canonical name so a concurrent webhook claim can't be
        // clobbered and a partial write is never visible as `<id>.job`. The
        // temp name is unique per process and per attempt (pid + a nanosecond
        // nonce) so two consumers sharing a SPOOL_DIR — a documented-safe
        // config — never race on the same temp path; the canonical
        // `rename_no_clobber` below remains the single dedup point. A temp left
        // by a crashed process is harmless: it carries no `.job` suffix (so GC's
        // `live_vm_names_from_cur` ignores it) and stale-expiry sweeps it later.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp = self.cur_dir().join(format!(
            ".tmp-reconcile-{}-{}-{}",
            job.id,
            std::process::id(),
            nonce
        ));
        write_private_file(&tmp, &bytes)
            .await
            .with_context(|| format!("write synthetic claim {name}"))?;
        match rename_no_clobber(&tmp, &dst) {
            Ok(()) => {
                stamp_mtime_now(&dst);
                Ok(Some(dst))
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&tmp).await;
                Ok(None)
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp).await;
                Err(e).with_context(|| format!("synthetic claim rename {name}"))
            }
        }
    }
}

/// Move `cur_path` into its archive slot `dest`, preserving any prior archive
/// of the same `workflow_job_id` as `<dest>.<unix_millis>.bak`. The same id can
/// be archived twice — a job stolen by another runner is finalized to `done/`,
/// then the reconciler re-mints it and finalizes the real completion to the
/// same `done/<id>.job`.
///
/// Ordering guarantees the canonical archive marker is never absent — replay
/// protection in `try_claim` keys on `done/<id>.job` / `error/<id>.job`
/// *existing*, not on its contents:
///
/// * dest free: one exclusive rename installs it.
/// * cur_path already gone: GC (`expire_stale_cur`) or a concurrent finalize
///   already archived this id; leave the existing marker untouched (idempotent).
/// * dest occupied: the exclusive rename proved cur_path still exists, so
///   preserve the old marker then install ours; if cur_path vanishes in the
///   race window, restore the preserved copy so a marker survives.
///
/// Returns `true` iff this call actually installed `cur_path` at `dest`, and
/// `false` on the idempotent no-op path (source already archived, existing
/// marker left untouched). The caller stamps the completion mtime only on a
/// real install — re-stamping an existing marker would make an old completion
/// look fresh and reset its age for future pruning.
async fn archive(cur_path: &Path, dest: &Path) -> Result<bool> {
    match rename_no_clobber(cur_path, dest) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!(cur = %cur_path.display(), "finalize: source already archived; leaving existing marker");
            Ok(false)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let Some(bak) = preserve_existing(dest).await else {
                // Marker vanished between the rename and now; just install ours.
                fs::rename(cur_path, dest).await?;
                return Ok(true);
            };
            match fs::rename(cur_path, dest).await {
                Ok(()) => Ok(true),
                Err(e) => {
                    // Our source disappeared; put the preserved marker back so
                    // replay protection still sees an archive at `dest`.
                    let _ = fs::rename(&bak, dest).await;
                    Err(e).with_context(|| format!("install archive {}", dest.display()))
                }
            }
        }
        Err(e) => Err(e).with_context(|| format!("archive {}", dest.display())),
    }
}

/// Move an existing `dest` aside to `<dest>.<unix_millis>.bak`, returning the
/// `.bak` path (so the caller can restore it if the follow-up install fails).
/// `None` if there was nothing to preserve or the move failed.
async fn preserve_existing(dest: &Path) -> Option<PathBuf> {
    if !fs::try_exists(dest).await.unwrap_or(false) {
        return None;
    }
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let mut bak = dest.as_os_str().to_owned();
    bak.push(format!(".{millis}.bak"));
    let bak = PathBuf::from(bak);
    match fs::rename(dest, &bak).await {
        Ok(()) => Some(bak),
        Err(e) => {
            warn!(dest = %dest.display(), error = %e, "could not preserve prior archive");
            None
        }
    }
}

/// HMAC-SHA256 a body into the `sha256=<hex>` wire format `verify_signature`
/// accepts. Used to self-sign reconciler-minted records.
fn sign_body(secret: &[u8], body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Create `path` owner-only (0600), failing if it already exists. Mirrors the
/// posture of `runner::write_jit_blob`.
async fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
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

/// Set a file's mtime to the current wall clock. Best-effort: any failure is
/// logged (a missing file silently — that's an expected race) and swallowed,
/// because failing a claim or finalize over a missing utimens would be worse
/// than the clock effect we're trying to set.
///
/// Two uses, both wanting "stamp this file's clock to now":
///   * after a claim renames `new/<name>` into cur/, so GC ages the in-flight
///     job from when we took ownership (`gc::expire_stale_cur`);
///   * after a finalize/expiry archives a file into done/ or error/, so the
///     archive's mtime is its *completion* time. `rename(2)` preserves the
///     source's mtime (= claim time), so without this the control UI's
///     "completed" view — and the future mailbox-GC that prunes by age —
///     would mistake claim time for finish time.
///
/// Uses the same O_NOFOLLOW + O_NONBLOCK + post-open fstat dance as
/// read_spool_file so a hostile file (symlink, FIFO, etc.) can't be opened
/// through its target here. A non-regular file is logged and skipped —
/// read_spool_file rejects it on the same grounds downstream.
pub(crate) fn stamp_mtime_now(p: &Path) {
    let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(p)
    {
        Ok(f) => f,
        // A missing file is an expected race: a concurrent finalize won the
        // archive, or the just-claimed file was finalized out from under us.
        // Other open errors are worth a warn.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!(path = %p.display(), error = %e, "open for mtime stamp");
            return;
        }
    };
    let md = match file.metadata() {
        Ok(m) => m,
        Err(e) => {
            warn!(path = %p.display(), error = %e, "fstat for mtime stamp");
            return;
        }
    };
    if !md.file_type().is_file() {
        warn!(path = %p.display(), "mtime stamp: not a regular file; skipping");
        return;
    }
    if let Err(e) = file.set_modified(std::time::SystemTime::now()) {
        warn!(path = %p.display(), error = %e, "set_modified");
    }
}

/// Rename `from` → `to` but fail with AlreadyExists if `to` already exists,
/// rather than the silent clobber that plain rename(2) does on Unix/macOS.
/// Uses `renameatx_np(RENAME_EXCL)` on macOS and `renameat2(RENAME_NOREPLACE)`
/// on Linux; both are atomic and supported on the kernel versions we target.
fn rename_no_clobber(from: &Path, to: &Path) -> std::io::Result<()> {
    let from_c = CString::new(from.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let to_c = CString::new(to.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // SAFETY: pointers are valid CStrings owned by us for the duration of the
    // call; AT_FDCWD is a valid sentinel; the libc bindings match the kernel
    // signatures on the targeted platforms.
    let ret = unsafe { rename_exclusive_syscall(from_c.as_ptr(), to_c.as_ptr()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
unsafe fn rename_exclusive_syscall(
    from: *const libc::c_char,
    to: *const libc::c_char,
) -> libc::c_int {
    libc::renameatx_np(libc::AT_FDCWD, from, libc::AT_FDCWD, to, libc::RENAME_EXCL)
}

#[cfg(target_os = "linux")]
unsafe fn rename_exclusive_syscall(
    from: *const libc::c_char,
    to: *const libc::c_char,
) -> libc::c_int {
    libc::renameat2(
        libc::AT_FDCWD,
        from,
        libc::AT_FDCWD,
        to,
        libc::RENAME_NOREPLACE,
    )
}

/// Read a spool file and split into (envelope, raw body bytes), enforcing
/// the file-size, envelope-size, and file-type caps. Held as raw bytes (not
/// parsed JSON) because HMAC must be computed over the exact bytes the spool
/// stored.
pub async fn read_spool_file(path: &Path) -> Result<(Envelope, Vec<u8>)> {
    // O_NOFOLLOW: refuse to open through a symlink (rejects an attacker who
    // swapped in a link to a daemon-readable file).
    // O_NONBLOCK: a FIFO sneaking past enumerate_new() would otherwise block
    // open() forever waiting for a writer. On regular files O_NONBLOCK is
    // effectively a no-op.
    let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    // fstat the open fd — closes the TOCTOU window between enumerate_new's
    // lstat and our open. The fd points at a specific inode; the type can't
    // change underfoot.
    let md = f
        .metadata()
        .await
        .with_context(|| format!("fstat {}", path.display()))?;
    if !md.file_type().is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }
    if md.len() > MAX_FILE_BYTES {
        anyhow::bail!(
            "spool file {} is {} bytes; exceeds {} byte cap",
            path.display(),
            md.len(),
            MAX_FILE_BYTES
        );
    }
    // Belt-and-braces: enforce the cap on the read itself rather than just on
    // the fstat'd length. Files in cur/ shouldn't grow under us (we put them
    // there and nobody else writes), but a bounded reader removes any race
    // between fstat and read_to_end as a class.
    let mut bytes = Vec::with_capacity(md.len() as usize);
    let mut limited = f.take(MAX_FILE_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        anyhow::bail!(
            "spool file {} grew past {} byte cap during read",
            path.display(),
            MAX_FILE_BYTES
        );
    }
    let nl = bytes
        .iter()
        .position(|&b| b == b'\n')
        .context("no newline after envelope")?;
    if nl > MAX_ENVELOPE_BYTES {
        anyhow::bail!("envelope line is {nl} bytes; exceeds {MAX_ENVELOPE_BYTES} byte cap");
    }
    let env: Envelope = serde_json::from_slice(&bytes[..nl]).context("parse envelope")?;
    let body = bytes[nl + 1..].to_vec();
    Ok((env, body))
}

/// Verify the envelope's signature header against the raw body using a
/// shared HMAC-SHA256 secret. The signature wire format is `sha256=<hex>`,
/// the same format GitHub originally sent.
pub fn verify_signature(sig_header: &str, body: &[u8], secret: &[u8]) -> bool {
    let Some(hex_sig) = sig_header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_sig) else {
        return false;
    };
    if expected.len() != 32 {
        return false;
    }
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// Parse a spool filename: `<workflow_job_id>.job`. The id is a u64 from
/// the signed body, so using it as the queue key means a replay can't
/// produce a fresh entry.
pub fn parse_spool_filename(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".job")?;
    stem.parse::<u64>().ok()
}

/// Strip control characters and cap length so an attacker-controlled string
/// (filename from `new/`, workflow_job.name, envelope.delivery, …) can't
/// smuggle ANSI escapes or line breaks into structured log output. The
/// envelope is not under HMAC and workflow names are author-controlled, so
/// any field originating off-host gets piped through this before it lands
/// in a `tracing` field.
pub fn sanitize_for_log(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(256).collect()
}

/// Watch a `new/` directory, streaming filenames into `tx`.
///
/// Strategy:
///   * on startup, emit every existing file in new/,
///   * watch new/ with `notify` (FSEvents on macOS) and rescan on any event,
///   * also rescan every 10s in case an event is missed (FSEvents has
///     coalescing semantics that can drop events under load).
pub async fn watch(root: PathBuf, tx: mpsc::Sender<String>) -> Result<()> {
    enumerate_new(&root, &tx).await?;

    let (evt_tx, mut evt_rx) = mpsc::unbounded_channel::<()>();
    let mut watcher =
        notify::recommended_watcher(move |res: notify::Result<notify::Event>| match res {
            Ok(_) => {
                let _ = evt_tx.send(());
            }
            Err(e) => {
                warn!(error = %e, "fs watcher error");
            }
        })?;
    watcher.watch(&root, RecursiveMode::NonRecursive)?;

    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Err(e) = enumerate_new(&root, &tx).await {
                    warn!(error = %e, "rescan failed");
                }
            }
            opt = evt_rx.recv() => {
                if opt.is_none() {
                    break;
                }
                // Coalesce burst of events into one rescan.
                while evt_rx.try_recv().is_ok() {}
                if let Err(e) = enumerate_new(&root, &tx).await {
                    warn!(error = %e, "post-event scan failed");
                }
            }
            _ = tx.closed() => {
                break;
            }
        }
    }
    Ok(())
}

async fn enumerate_new(root: &Path, tx: &mpsc::Sender<String>) -> Result<()> {
    let mut rd = fs::read_dir(root).await?;
    while let Some(ent) = rd.next_entry().await? {
        let name = ent.file_name();
        let Some(s) = name.to_str() else { continue };
        if !s.ends_with(".job") {
            continue;
        }
        // DirEntry::file_type is lstat-based on Unix, so symlinks, FIFOs,
        // sockets and directories are all rejected here. read_spool_file
        // does a stricter post-open fstat check that closes the TOCTOU
        // window, but this filter avoids even claiming garbage.
        let ft = match ent.file_type().await {
            Ok(ft) => ft,
            Err(e) => {
                warn!(file = %s, error = %e, "file_type failed; skipping");
                continue;
            }
        };
        if !ft.is_file() {
            warn!(file = %s, "skipping non-regular spool entry");
            continue;
        }
        if tx.send(s.to_string()).await.is_err() {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn sign(secret: &[u8], body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    async fn write_job(root: &Path, name: &str, envelope: &str, body: &[u8]) -> PathBuf {
        let path = root.join("new").join(name);
        fs::create_dir_all(root.join("new")).await.unwrap();
        let mut bytes = envelope.as_bytes().to_vec();
        bytes.push(b'\n');
        bytes.extend_from_slice(body);
        fs::write(&path, &bytes).await.unwrap();
        path
    }

    async fn spool_tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        for sub in ["new", "cur", "done", "error"] {
            fs::create_dir_all(root.join(sub)).await.unwrap();
        }
        (dir, root)
    }

    /// Minimal schema-1 envelope for tests.
    fn envelope(action: &str, repo_id: u64, repo: &str, job_id: u64, signature: &str) -> String {
        format!(
            r#"{{"schema":1,"event":"workflow_job","delivery":"d","repo_id":{repo_id},"repo":"{repo}","action":"{action}","workflow_job_id":{job_id},"received_at_ms":1,"signature":"{signature}"}}"#
        )
    }

    #[tokio::test]
    async fn claim_and_finalize_done_moves_file() {
        let (_dir, root) = spool_tmp().await;
        let env = envelope("queued", 42, "o/r", 1, "sha256=00");
        write_job(&root, "1.job", &env, b"{}").await;

        let s = Spool::new(root.clone());
        let cur = s.try_claim("1.job").await.unwrap().expect("claimed");
        assert!(cur.starts_with(root.join("cur")));
        let (parsed, _body) = read_spool_file(&cur).await.unwrap();
        assert_eq!(parsed.workflow_job_id, 1);

        s.finalize_done(&cur).await.unwrap();
        assert!(!cur.exists());
        assert!(root.join("done/1.job").exists());
    }

    #[tokio::test]
    async fn claim_missing_file_returns_none() {
        let (_dir, root) = spool_tmp().await;
        let s = Spool::new(root);
        assert!(s.try_claim("nope.job").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn finalize_error_writes_sidecar_and_moves_file() {
        let (_dir, root) = spool_tmp().await;
        let env = envelope("queued", 42, "o/r", 2, "sha256=00");
        write_job(&root, "2.job", &env, b"{}").await;
        let s = Spool::new(root.clone());
        let cur = s.try_claim("2.job").await.unwrap().unwrap();
        s.finalize_error(&cur, "oh no").await.unwrap();
        assert!(root.join("error/2.job").exists());
        let sidecar = fs::read_to_string(root.join("error/2.job.err"))
            .await
            .unwrap();
        assert_eq!(sidecar, "oh no");
    }

    /// archive() renames, which preserves the claim-time mtime; finalize must
    /// re-stamp the archived file to ~now so the control UI's "completed" view
    /// (and future age-based pruning) reads finish time, not claim time.
    #[tokio::test]
    async fn finalize_done_stamps_archive_mtime_to_now() {
        let (_dir, root) = spool_tmp().await;
        let env = envelope("queued", 42, "o/r", 50, "sha256=00");
        write_job(&root, "50.job", &env, b"{}").await;
        let s = Spool::new(root.clone());
        let cur = s.try_claim("50.job").await.unwrap().unwrap();
        // Simulate a long-running job: backdate the claim mtime into the past.
        let backdate = std::time::SystemTime::now() - Duration::from_secs(3 * 3600);
        std::fs::File::open(&cur)
            .unwrap()
            .set_modified(backdate)
            .unwrap();

        let before = std::time::SystemTime::now();
        s.finalize_done(&cur).await.unwrap();
        let after = std::time::SystemTime::now();

        let m = std::fs::metadata(root.join("done/50.job"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            m >= before.checked_sub(Duration::from_secs(2)).unwrap()
                && m <= after + Duration::from_secs(2),
            "archive mtime must be finalize time, not the backdated claim time; got {m:?}"
        );
    }

    /// The idempotent finalize path (source already archived, existing marker
    /// kept) must NOT restamp that marker's mtime — doing so would make an old
    /// completion look fresh and reset its age for future pruning.
    #[tokio::test]
    async fn finalize_does_not_restamp_existing_marker_when_source_gone() {
        let (_dir, root) = spool_tmp().await;
        let s = Spool::new(root.clone());
        // A pre-existing archive marker with an OLD mtime, and NO cur/ source.
        fs::write(root.join("done/90.job"), b"old").await.unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(3 * 3600);
        std::fs::File::open(root.join("done/90.job"))
            .unwrap()
            .set_modified(old)
            .unwrap();

        // finalize with a missing cur source: archive is a no-op that keeps the
        // marker; the mtime must be left as-is.
        s.finalize_done(&root.join("cur/90.job")).await.unwrap();

        let m = std::fs::metadata(root.join("done/90.job"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            m <= std::time::SystemTime::now() - Duration::from_secs(3600),
            "idempotent finalize must not restamp an existing marker; got {m:?}"
        );
    }

    #[tokio::test]
    async fn finalize_error_stamps_archive_mtime_to_now() {
        let (_dir, root) = spool_tmp().await;
        let env = envelope("queued", 42, "o/r", 51, "sha256=00");
        write_job(&root, "51.job", &env, b"{}").await;
        let s = Spool::new(root.clone());
        let cur = s.try_claim("51.job").await.unwrap().unwrap();
        let backdate = std::time::SystemTime::now() - Duration::from_secs(3 * 3600);
        std::fs::File::open(&cur)
            .unwrap()
            .set_modified(backdate)
            .unwrap();

        let before = std::time::SystemTime::now();
        s.finalize_error(&cur, "boom").await.unwrap();

        let m = std::fs::metadata(root.join("error/51.job"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(
            m >= before.checked_sub(Duration::from_secs(2)).unwrap(),
            "error archive mtime must be ~finalize time, not the backdated claim time; got {m:?}"
        );
    }

    #[tokio::test]
    async fn oversize_file_is_rejected() {
        let (_dir, root) = spool_tmp().await;
        let env = envelope("queued", 42, "o/r", 3, "sha256=00");
        let huge = vec![b'a'; (MAX_FILE_BYTES + 1) as usize];
        let path = write_job(&root, "3.job", &env, &huge).await;
        let err = read_spool_file(&path).await.unwrap_err().to_string();
        assert!(err.contains("exceeds"), "unexpected error: {err}");
    }

    #[test]
    fn signature_verifies_only_when_secret_matches() {
        let body = br#"{"x":1}"#;
        let sig = sign(b"hunter2", body);
        assert!(verify_signature(&sig, body, b"hunter2"));
        assert!(!verify_signature(&sig, body, b"wrong"));
        assert!(!verify_signature("sha1=deadbeef", body, b"hunter2"));
        assert!(!verify_signature("sha256=notHex", body, b"hunter2"));
        assert!(!verify_signature("sha256=00", body, b"hunter2"));
    }

    #[test]
    fn sanitize_for_log_strips_control_chars() {
        assert_eq!(sanitize_for_log("hello"), "hello");
        assert_eq!(sanitize_for_log("a\nb\tc\rd"), "abcd");
        // ANSI colour escape: 0x1b is control; `[31mred[0m` survives.
        assert_eq!(sanitize_for_log("a\x1b[31mred\x1b[0m"), "a[31mred[0m");
        // NUL is a control char; printable Unicode passes through.
        assert_eq!(sanitize_for_log("hi\0there"), "hithere");
        assert_eq!(sanitize_for_log("héllo"), "héllo");
    }

    #[test]
    fn sanitize_for_log_caps_length() {
        let long = "a".repeat(1000);
        assert_eq!(sanitize_for_log(&long).chars().count(), 256);
    }

    #[test]
    fn parse_filename_extracts_u64() {
        assert_eq!(parse_spool_filename("12345.job"), Some(12345));
        assert_eq!(parse_spool_filename("0.job"), Some(0));
        assert_eq!(
            parse_spool_filename("18446744073709551615.job"),
            Some(u64::MAX)
        );

        assert!(parse_spool_filename("nope").is_none());
        assert!(parse_spool_filename("nope.job").is_none());
        assert!(parse_spool_filename(".job").is_none());
        assert!(parse_spool_filename("12.34.job").is_none());
        assert!(parse_spool_filename("-1.job").is_none());
        assert!(parse_spool_filename("18446744073709551616.job").is_none());
    }

    #[tokio::test]
    async fn try_claim_stamps_mtime_to_now() {
        let (_dir, root) = spool_tmp().await;
        let env = envelope("queued", 42, "o/r", 4, "sha256=00");
        let path = write_job(&root, "4.job", &env, b"{}").await;
        let backdate = std::time::SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::open(&path)
            .unwrap()
            .set_modified(backdate)
            .unwrap();

        let s = Spool::new(root.clone());
        let before = std::time::SystemTime::now();
        let cur = s.try_claim("4.job").await.unwrap().unwrap();
        let after = std::time::SystemTime::now();
        let m = std::fs::metadata(&cur).unwrap().modified().unwrap();
        assert!(
            m >= before.checked_sub(Duration::from_secs(2)).unwrap()
                && m <= after + Duration::from_secs(2),
            "expected mtime ~now, got {m:?}"
        );
    }

    #[tokio::test]
    async fn symlink_in_new_is_rejected_by_read_spool_file() {
        let (_dir, root) = spool_tmp().await;
        let target = root.join("secret.txt");
        std::fs::write(&target, b"hunter2").unwrap();
        let link = root.join("cur").join("5.job");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = read_spool_file(&link).await.unwrap_err().to_string();
        assert!(!err.is_empty(), "expected open to fail through symlink");
    }

    #[tokio::test]
    async fn non_regular_file_is_rejected_by_read_spool_file() {
        let (_dir, root) = spool_tmp().await;
        let pretender = root.join("cur").join("6.job");
        std::fs::create_dir(&pretender).unwrap();
        std::fs::set_permissions(&pretender, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = read_spool_file(&pretender).await.unwrap_err().to_string();
        assert!(
            err.contains("not a regular file") || !err.is_empty(),
            "unexpected error: {err}"
        );
    }

    /// A duplicate or forged new/<name> must not displace a live cur/<name>.
    /// Plain rename(2) would silently overwrite cur/; an exclusive rename
    /// primitive returns AlreadyExists instead. We then unlink the stray new/
    /// entry so it stops being rescanned, but the original claim is intact.
    #[tokio::test]
    async fn duplicate_claim_does_not_clobber_live_cur_entry() {
        let (_dir, root) = spool_tmp().await;
        let env = envelope("queued", 42, "o/r", 7, "sha256=00");
        write_job(&root, "7.job", &env, b"first").await;

        let s = Spool::new(root.clone());
        let cur1 = s.try_claim("7.job").await.unwrap().expect("first claim");
        let original = fs::read(&cur1).await.unwrap();

        // A duplicate (or attacker-forged) new/7.job appears while cur/7.job
        // is still in-flight.
        write_job(&root, "7.job", &env, b"forged-payload").await;

        let outcome = s.try_claim("7.job").await.unwrap();
        assert!(
            outcome.is_none(),
            "duplicate claim should not return a new path, got {outcome:?}"
        );

        // The live cur/ entry is byte-for-byte unchanged.
        assert!(cur1.exists());
        assert_eq!(fs::read(&cur1).await.unwrap(), original);

        // The duplicate new/ entry was removed so the dispatcher stops
        // rescanning it.
        assert!(
            !root.join("new").join("7.job").exists(),
            "duplicate new/ entry should be removed"
        );
    }

    /// A replay against `done/<name>` (already-processed job) must not
    /// reclaim. We never want to mint a second JIT runner / boot a second
    /// VM for a job GitHub has already retired. The new/ copy is removed
    /// so the dispatcher stops rescanning it; the archived entry is
    /// untouched.
    #[tokio::test]
    async fn replay_against_archived_done_is_rejected() {
        let (_dir, root) = spool_tmp().await;
        let env = envelope("completed", 42, "o/r", 9, "sha256=00");
        // Archive entry already present.
        let archived = root.join("done/9.job");
        fs::write(&archived, b"archived-bytes").await.unwrap();
        // Spooler (or a bug) drops the same workflow_job_id into new/.
        write_job(&root, "9.job", &env, b"replay-payload").await;

        let s = Spool::new(root.clone());
        assert!(s.try_claim("9.job").await.unwrap().is_none());

        assert!(
            !root.join("new/9.job").exists(),
            "replay new/ entry should be removed so rescans stop"
        );
        // cur/ must NOT have been written.
        assert!(!root.join("cur/9.job").exists());
        // The archived bytes are untouched.
        assert_eq!(fs::read(&archived).await.unwrap(), b"archived-bytes");
    }

    /// Same protection against `error/<name>`. The `.err` sidecar lives at
    /// a *different* filename (`<name>.err`) so it must not false-positive
    /// the archive check when only the sidecar is present.
    #[tokio::test]
    async fn replay_against_archived_error_is_rejected() {
        let (_dir, root) = spool_tmp().await;
        let env = envelope("completed", 42, "o/r", 10, "sha256=00");
        fs::write(root.join("error/10.job"), b"err-bytes")
            .await
            .unwrap();
        write_job(&root, "10.job", &env, b"replay-payload").await;

        let s = Spool::new(root.clone());
        assert!(s.try_claim("10.job").await.unwrap().is_none());
        assert!(!root.join("new/10.job").exists());
        assert!(!root.join("cur/10.job").exists());
    }

    /// A stray `<name>.err` sidecar (no canonical `<name>`) must not be
    /// mistaken for an archived completion — the archive check matches the
    /// exact filename, not a prefix.
    #[tokio::test]
    async fn sidecar_alone_does_not_count_as_archived() {
        let (_dir, root) = spool_tmp().await;
        let env = envelope("queued", 42, "o/r", 11, "sha256=00");
        // Sidecar without the canonical entry — pathological but possible
        // if an operator hand-cleaned the .job and left the .err.
        fs::write(root.join("error/11.job.err"), b"stale sidecar")
            .await
            .unwrap();
        write_job(&root, "11.job", &env, b"{}").await;

        let s = Spool::new(root.clone());
        let cur = s.try_claim("11.job").await.unwrap();
        assert!(cur.is_some(), "sidecar-only must not block a fresh claim");
    }

    /// A replay that lands while the original is in flight, then finalizes
    /// out of cur/ *between* our pre-rename archive check and our exclusive
    /// rename, would otherwise mint a duplicate JIT runner: the rename
    /// succeeds against the just-vacated cur/ slot. The post-rename archive
    /// re-check catches it, unlinks the just-claimed cur/ entry, and
    /// returns None.
    ///
    /// We can't hit this window reliably from the outside, so we use the
    /// `try_claim_inner` test seam to perform the original's finalize
    /// exactly between the two archive checks.
    #[tokio::test]
    async fn replay_finalizing_concurrent_with_claim_is_rejected() {
        let (_dir, root) = spool_tmp().await;
        let env = envelope("queued", 42, "o/r", 12, "sha256=00");

        // Original arrives, is claimed normally.
        write_job(&root, "12.job", &env, b"original-payload").await;
        let s = Spool::new(root.clone());
        let cur1 = s.try_claim("12.job").await.unwrap().expect("first claim");
        let original_bytes = fs::read(&cur1).await.unwrap();

        // Replay lands while the original is still in cur/.
        write_job(&root, "12.job", &env, b"replay-payload").await;

        // Drive a finalize_done between the pre-check (which sees no archive)
        // and the rename (which finds cur/ now vacant).
        let s_for_hook = Spool::new(root.clone());
        let cur1_for_hook = cur1.clone();
        let outcome = s
            .try_claim_inner("12.job", async move {
                s_for_hook.finalize_done(&cur1_for_hook).await.unwrap();
            })
            .await
            .unwrap();

        assert!(
            outcome.is_none(),
            "post-rename archive check must revert the claim, got {outcome:?}"
        );

        // done/ holds the original, byte-for-byte — finalize moved it before
        // the replay landed in cur/.
        assert_eq!(
            fs::read(root.join("done/12.job")).await.unwrap(),
            original_bytes,
        );
        // The reverted cur/ entry was unlinked.
        assert!(
            !root.join("cur/12.job").exists(),
            "post-rename revert must remove cur/ entry"
        );
        // The replay's new/ entry was consumed by the (later-reverted)
        // rename, so rescans stop on it too.
        assert!(!root.join("new/12.job").exists());
    }

    /// stamp_mtime_now must not follow a symlink that an attacker (or buggy
    /// spool) placed at new/<name> before we claimed it. rename(2) moves the
    /// symlink itself into cur/; if we then re-open without O_NOFOLLOW we'd
    /// touch the symlink target's mtime. With O_NOFOLLOW the open fails and
    /// the link survives untouched for read_spool_file to reject downstream.
    #[tokio::test]
    async fn claim_does_not_follow_symlink_when_stamping_mtime() {
        let (_dir, root) = spool_tmp().await;
        // A sensitive file outside cur/ that an attacker would like us to
        // touch via a symlink swap.
        let target = root.join("victim.txt");
        std::fs::write(&target, b"do not touch").unwrap();
        let original_mtime = std::fs::metadata(&target).unwrap().modified().unwrap();
        // Backdate so any accidental utimens is detectable.
        std::fs::File::open(&target)
            .unwrap()
            .set_modified(original_mtime - Duration::from_secs(3600))
            .unwrap();
        let pre = std::fs::metadata(&target).unwrap().modified().unwrap();

        // Drop a symlink into new/ where the spool would normally put a job
        // file; the daemon's claim must not chase it.
        let new_link = root.join("new").join("8.job");
        std::os::unix::fs::symlink(&target, &new_link).unwrap();

        let s = Spool::new(root.clone());
        let claimed = s.try_claim("8.job").await.unwrap();
        // The rename succeeds (we moved the link itself), but the secure
        // O_NOFOLLOW open in stamp_mtime_now refuses to follow it, so we
        // never set_modified on the target.
        assert!(claimed.is_some(), "rename of the symlink itself succeeds");

        let post = std::fs::metadata(&target).unwrap().modified().unwrap();
        assert_eq!(pre, post, "stamp_mtime_now must not follow symlink");
    }

    #[tokio::test]
    async fn write_synthetic_claim_creates_parseable_record() {
        let (_dir, root) = spool_tmp().await;
        let s = Spool::new(root.clone());
        let job = crate::github::jit::JobStatus {
            id: 4242,
            status: "queued".into(),
            run_id: 9,
            run_attempt: 1,
            name: "build".into(),
            labels: vec!["self-hosted".into(), "lima-nix".into()],
            repo_id: 7,
        };
        let cur = s
            .write_synthetic_claim(&job, "o/r", b"k")
            .await
            .unwrap()
            .expect("minted");
        assert_eq!(cur, root.join("cur/4242.job"));
        // Canonical filename -> GC derives the matching vm_name.
        assert_eq!(parse_spool_filename("4242.job"), Some(4242));
        let (env, body) = read_spool_file(&cur).await.unwrap();
        assert_eq!(env.workflow_job_id, 4242);
        assert_eq!(env.repo, "o/r");
        assert_eq!(env.schema, 2);
        // The self-computed HMAC re-verifies, keeping invariant #1 honest.
        assert!(
            verify_signature(&env.signature, &body, b"k"),
            "self-HMAC must verify"
        );
    }

    #[tokio::test]
    async fn write_synthetic_claim_skips_when_cur_exists() {
        let (_dir, root) = spool_tmp().await;
        let s = Spool::new(root.clone());
        fs::write(root.join("cur/4242.job"), b"live").await.unwrap();
        let job = crate::github::jit::JobStatus {
            id: 4242,
            status: "queued".into(),
            ..Default::default()
        };
        let out = s.write_synthetic_claim(&job, "o/r", b"k").await.unwrap();
        assert!(out.is_none(), "must not clobber a live cur/ claim");
        assert_eq!(fs::read(root.join("cur/4242.job")).await.unwrap(), b"live");
    }

    #[tokio::test]
    async fn finalize_done_preserves_existing_archive() {
        let (_dir, root) = spool_tmp().await;
        let s = Spool::new(root.clone());
        // Prior archive from an earlier processing of the same id (a steal we
        // finalized to done/), then a fresh cur/ entry (reconciler re-mint).
        fs::write(root.join("done/77.job"), b"prior").await.unwrap();
        fs::write(root.join("cur/77.job"), b"fresh").await.unwrap();
        s.finalize_done(&root.join("cur/77.job")).await.unwrap();
        assert_eq!(fs::read(root.join("done/77.job")).await.unwrap(), b"fresh");
        let mut found_bak = false;
        let mut rd = fs::read_dir(root.join("done")).await.unwrap();
        while let Some(ent) = rd.next_entry().await.unwrap() {
            let n = ent.file_name().to_string_lossy().to_string();
            if n.starts_with("77.job.") && n.ends_with(".bak") {
                assert_eq!(fs::read(ent.path()).await.unwrap(), b"prior");
                found_bak = true;
            }
        }
        assert!(found_bak, "prior done/ archive should be preserved as .bak");
    }

    #[tokio::test]
    async fn finalize_keeps_marker_when_source_already_archived() {
        // GC (expire_stale_cur) already moved the cur entry to error/. The
        // worker then finalizes the now-missing cur path; the existing archive
        // marker must survive (replay protection in try_claim depends on it)
        // and no marker should be moved aside to a .bak.
        let (_dir, root) = spool_tmp().await;
        let s = Spool::new(root.clone());
        fs::write(root.join("error/88.job"), b"gc-archived")
            .await
            .unwrap();
        // cur/88.job does NOT exist.
        s.finalize_error(&root.join("cur/88.job"), "boom")
            .await
            .unwrap();
        assert!(
            root.join("error/88.job").exists(),
            "archive marker must survive a finalize whose source is already gone"
        );
        assert_eq!(
            fs::read(root.join("error/88.job")).await.unwrap(),
            b"gc-archived"
        );
        let mut rd = fs::read_dir(root.join("error")).await.unwrap();
        while let Some(ent) = rd.next_entry().await.unwrap() {
            assert!(
                !ent.file_name().to_string_lossy().ends_with(".bak"),
                "no marker should have been moved aside"
            );
        }
    }
}
