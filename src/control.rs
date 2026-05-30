// Loopback HTTP control endpoint: pause/resume claiming and report status,
// plus a tiny embedded web UI (`/` + `/app.js`) over the same JSON API.
//
// "Pause" stops the supervisor claiming *new* jobs (they wait in new/);
// in-flight VMs and the GC keep running. The primary use is a clean
// shutdown/migration: pause, wait for `in_flight` to reach 0, then stop the
// daemon — so no in-flight VM is orphaned.
//
// No auth: the endpoint must bind a loopback address (enforced in Config), so
// the host boundary is the trust boundary. Pausing is the only state it can
// change, and it can't exfiltrate anything sensitive. The UI is just a client
// for that same API, so it widens no capability.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tracing::warn;
use zeroize::Zeroizing;

use crate::gc::is_managed_vm_name;
use crate::github::event::WorkflowJob;
use crate::lima::Lima;
use crate::spool::{parse_spool_filename, read_spool_file, sanitize_for_log, Spool};
use crate::supervisor::{classify_validated_entry, EntryVerdict};

#[derive(Clone)]
pub struct ControlState {
    /// Drives the supervisor's pause gate; `true` = stop claiming new jobs.
    pub pause: watch::Sender<bool>,
    /// Shared with the supervisor so `in_flight` reflects live permit usage.
    pub permits: Arc<Semaphore>,
    pub max_concurrency: usize,
    /// Read-only handle to the maildir spool, for listing new/cur/done/error.
    /// An `Arc<Spool>` (not a bare `PathBuf`) so we reuse the `*_dir()` path
    /// helpers and `read_spool_file` parser, and hand a future reorder action a
    /// real handle.
    pub spool: Arc<Spool>,
    /// The webhook HMAC secret, shared with the supervisor. Used to authenticate
    /// `new/` entries before the listing trusts their fields — the dispatcher
    /// hasn't validated them yet (that happens at claim). Not a new exposure:
    /// this process already holds the GitHub App key and mints JIT configs.
    pub webhook_secret: Arc<Zeroizing<Vec<u8>>>,
    /// Repo allowlist + label policy, shared with the supervisor so the queued
    /// listing applies the dispatcher's *exact* validation (`prepare()` via
    /// `classify_validated_entry`) and shows only jobs that would actually run.
    pub allowed_repos: Arc<HashSet<String>>,
    pub runner_labels: Arc<HashSet<String>>,
    pub runner_label: String,
    /// Latest snapshot of managed Lima VMs, published by the daemon's own poller
    /// (`poll_vm_snapshots`). Reading it is lock-free and instant — the UI sees
    /// what the service *believes* is running, not a fresh per-request query.
    pub vms: watch::Receiver<Arc<VmSnapshot>>,
}

/// A point-in-time view of managed (`gha-<16hex>`) Lima VMs the daemon polled.
#[derive(Debug, Clone, Default)]
pub struct VmSnapshot {
    /// Wall-clock ms when taken; `0` = never polled yet (poller hasn't run, or
    /// `limactl list` has not yet succeeded).
    pub taken_ms: u128,
    /// Managed VM name -> Lima status (`Running`/`Stopped`/…); `None` if limactl
    /// omitted a status for the row.
    pub vms: HashMap<String, Option<String>>,
}

/// How often the VM-snapshot poller refreshes (only while the control server is
/// enabled). Matches the UI's `/jobs` cadence so a shown VM status is at most
/// about one cycle stale.
const VM_SNAPSHOT_POLL: Duration = Duration::from_secs(5);

/// Publish the daemon's view of its managed Lima VMs on an interval, so the
/// control UI reads a cached snapshot instead of spawning `limactl` per request.
///
/// On a failed/timed-out `limactl list` we keep the last good snapshot rather
/// than blanking it: its `taken_ms` simply stops advancing, which the UI
/// surfaces as growing staleness — more honest than flapping every VM to
/// "unknown" on a single transient error. Exits when the control server (the
/// only receiver) is gone.
pub async fn poll_vm_snapshots(lima: Arc<Lima>, tx: watch::Sender<Arc<VmSnapshot>>) {
    let mut tick = tokio::time::interval(VM_SNAPSHOT_POLL);
    // First tick fires immediately, so the snapshot populates promptly.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        if tx.is_closed() {
            break;
        }
        match lima.list_instances_detailed().await {
            Ok(instances) => {
                let vms = instances
                    .into_iter()
                    .filter(|i| is_managed_vm_name(&i.name))
                    .map(|i| (i.name, i.status))
                    .collect();
                let snap = VmSnapshot {
                    taken_ms: ms_since_epoch(SystemTime::now()),
                    vms,
                };
                if tx.send(Arc::new(snap)).is_err() {
                    break;
                }
            }
            Err(e) => {
                warn!(error = %format!("{e:#}"), "control: limactl list for VM snapshot failed; keeping last");
            }
        }
    }
}

#[derive(Serialize)]
struct Status {
    paused: bool,
    in_flight: usize,
    max_concurrency: usize,
}

/// Rolling window for the "completed" tab: only done/error entries whose mtime
/// is within this many seconds of now are listed. Echoed to the client as
/// `completed_window_hours`. Nothing prunes done/error today (GC only ages a
/// stale cur/ entry into error/), so the archive grows unbounded; this window
/// plus the result cap keep the endpoint's cost bounded regardless.
const COMPLETED_WINDOW_SECS: u64 = 24 * 60 * 60;

/// Hard cap on completed records returned in one response. Together with the
/// window above this bounds both the work (bodies are read only for the capped
/// subset) and the payload size. `completed_truncated` reports the cap being
/// hit.
const COMPLETED_CAP: usize = 200;

/// Cap on bytes read from an `.err` sidecar when extracting its first line as a
/// failure `reason`. The sidecar holds our own `{e:#}` error chain (bounded in
/// practice), but a bounded read stops a pathological file from blowing up the
/// listing.
const MAX_ERR_PREVIEW_BYTES: u64 = 8 * 1024;

/// Safety valve on the completed scan. done/ and error/ are not pruned today
/// (the separate mailbox-GC plan will do that), so a single poll's readdir +
/// stat walk would otherwise grow with the whole historical archive — the 24h
/// window and row cap only bound the *body reads* and output, not the walk. We
/// stop after examining this many entries across both dirs and set
/// `completed_truncated`, bounding worst-case poll cost regardless of archive
/// size. In the steady state (small/pruned archive) this is never hit; when it
/// is, the real fix is pruning, not a bigger cap.
const COMPLETED_SCAN_CAP: usize = 10_000;

/// Cap on entries examined per active list (new/ or cur/) in one poll. cur/ is
/// naturally bounded by `max_concurrency`, but new/ can balloon while the daemon
/// is paused or a big matrix enqueues, and each examined queued entry costs a
/// body read + HMAC. We stop after this many and set the list's `*_truncated`
/// flag, so merely opening the page can't trigger unbounded repeated I/O.
const ACTIVE_CAP: usize = 500;

/// One queued or in-flight job. A single shape serves both lists (the UI uses
/// one row renderer); only the timestamp field that applies is populated and
/// the other is omitted. `id` is a JSON **string**: `workflow_job_id` is a u64
/// that can exceed JS's 2^53 safe-integer range, and a future reorder POST keys
/// on it.
#[derive(Serialize)]
struct JobSummary {
    id: String,
    repo: String,
    /// From the body (`workflow_job.name`); `null` if the body is unparseable.
    name: Option<String>,
    labels: Vec<String>,
    /// From the body (`workflow_job.run_id`), as a string for the same 2^53
    /// reason as `id`. Lets the UI build the GitHub Actions deep link
    /// `…/actions/runs/{run_id}/job/{id}`; `null` if the body is unparseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    /// Queued only: enqueue time (`envelope.received_at_ms`, or file mtime when
    /// that is 0, as reconciler-minted claims hard-code).
    #[serde(skip_serializing_if = "Option::is_none")]
    enqueued_ms: Option<u128>,
    /// In-flight only: claim time = file mtime (the GC clock — "running since").
    #[serde(skip_serializing_if = "Option::is_none")]
    claimed_ms: Option<u128>,
    age_secs: u64,
    /// In-flight only: the Lima VM name, to correlate with `limactl list`.
    #[serde(skip_serializing_if = "Option::is_none")]
    vm: Option<String>,
    /// In-flight only: the VM's status from the latest snapshot ("Running"/…),
    /// or `null` when the VM isn't in the snapshot (booting / torn down) or no
    /// snapshot exists yet. The UI reads `vm_snapshot_ms` to tell those apart.
    #[serde(skip_serializing_if = "Option::is_none")]
    vm_status: Option<String>,
}

/// One finished job from done/ or error/, within the completed window.
#[derive(Serialize)]
struct CompletedSummary {
    id: String,
    /// From `envelope.repo`; `null` if the archived file can't be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    repo: Option<String>,
    /// From the body (`workflow_job.name`); `null` if unreadable/unparseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    /// "done" (done/) or "error" (error/).
    outcome: &'static str,
    /// Completion time: the archive file's mtime, stamped at finalize/expiry
    /// (`spool::stamp_mtime_now`) — rename(2) would otherwise leave it at the
    /// claim-time mtime.
    finished_ms: u128,
    /// First line of the `.err` sidecar, for error outcomes only.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize)]
struct JobsResponse {
    queued: Vec<JobSummary>,
    in_flight: Vec<JobSummary>,
    completed: Vec<CompletedSummary>,
    completed_window_hours: u64,
    /// Each `*_truncated` flag means that list hit its cap and may be
    /// incomplete (more entries exist than were examined/returned).
    queued_truncated: bool,
    in_flight_truncated: bool,
    completed_truncated: bool,
    /// When the VM snapshot driving `vm_status` was taken (epoch ms); `null` if
    /// the poller hasn't produced one yet. The UI shows its age as staleness.
    #[serde(skip_serializing_if = "Option::is_none")]
    vm_snapshot_ms: Option<u128>,
    /// Managed VMs Lima knows about that have no live cur/ claim — i.e. orphans
    /// GC will reap. Derived from the snapshot; empty in the steady state.
    orphan_vms: Vec<String>,
}

/// Which active bucket a listing pass is reading — selects the timestamp source
/// and whether a vm name is attached.
#[derive(Clone, Copy)]
enum Bucket {
    Queued,
    InFlight,
}

impl ControlState {
    fn status(&self) -> Status {
        // A claimed/running job holds a permit; available_permits() is what's
        // free, so the difference is what's in flight.
        let in_flight = self
            .max_concurrency
            .saturating_sub(self.permits.available_permits());
        Status {
            paused: *self.pause.borrow(),
            in_flight,
            max_concurrency: self.max_concurrency,
        }
    }

    /// Read the spool into the three lists in one pass. Best-effort and never
    /// fails: a vanished entry (a file moving new→cur→done mid-read yields
    /// `NotFound`) or a malformed file is skipped, so the handler always
    /// returns 200 with whatever it could read. We deliberately do not lock the
    /// spool — that would contend with dispatch — and a brief double-listing
    /// across a move is benign and self-corrects on the next poll.
    async fn jobs(&self) -> JobsResponse {
        let now = SystemTime::now();
        // Cheap, lock-free read of the daemon's latest VM view.
        let snapshot = self.vms.borrow().clone();
        let (queued, queued_truncated) = list_active(self, Bucket::Queued, now, &snapshot).await;
        let (in_flight, in_flight_truncated) =
            list_active(self, Bucket::InFlight, now, &snapshot).await;
        let (completed, completed_truncated) = list_completed(self.spool.as_ref(), now).await;

        // Orphans: managed VMs Lima knows about with no live cur/ claim. The
        // in-flight rows already carry their derived vm name; any snapshot VM
        // not among them is unbacked (GC will reap it).
        let claimed: HashSet<&str> = in_flight.iter().filter_map(|j| j.vm.as_deref()).collect();
        let orphan_vms = orphan_vm_names(&snapshot, &claimed);
        let vm_snapshot_ms = (snapshot.taken_ms != 0).then_some(snapshot.taken_ms);

        JobsResponse {
            queued,
            in_flight,
            completed,
            completed_window_hours: COMPLETED_WINDOW_SECS / 3600,
            queued_truncated,
            in_flight_truncated,
            completed_truncated,
            vm_snapshot_ms,
            orphan_vms,
        }
    }
}

async fn get_status(State(s): State<ControlState>) -> Json<Status> {
    Json(s.status())
}

async fn get_jobs(State(s): State<ControlState>) -> Json<JobsResponse> {
    Json(s.jobs().await)
}

async fn pause(State(s): State<ControlState>) -> Json<Status> {
    // send() only errors if every receiver is gone, i.e. the supervisor has
    // exited; nothing useful to do then, and status still reflects the flag.
    let _ = s.pause.send(true);
    Json(s.status())
}

async fn resume(State(s): State<ControlState>) -> Json<Status> {
    let _ = s.pause.send(false);
    Json(s.status())
}

// The UI is two static assets baked into the binary; no filesystem, no extra
// deps. The JS client drives the JSON API above.
async fn index() -> Html<&'static str> {
    Html(include_str!("web/index.html"))
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("web/app.js"),
    )
}

/// List new/ (queued) or cur/ (in-flight), `(rows, truncated)`; `truncated` is
/// true if the `ACTIVE_CAP` scan budget was hit before the dir was exhausted.
///
/// The two buckets differ by trust:
///   * **Queued (new/)** is *unvalidated* — the dispatcher hasn't claimed these
///     yet. We run the dispatcher's exact validation (`classify_validated_entry`,
///     shared with `prepare()`): canonical filename, HMAC, schema, envelope↔body
///     cross-checks, repo allowlist, and label policy. Only entries that would
///     actually **Run** are listed, and their repo/name/labels are taken from the
///     authenticated body — so the UI never shows a job we'd reject or drop.
///   * **In flight (cur/)** already crossed `prepare()` (or was minted by the
///     reconciler with a self-computed HMAC), so it is trusted: we read display
///     fields directly without re-validating, and stamp each row's VM status
///     from `vm_snapshot`.
///
/// Takes `&ControlState` (rather than a long parameter list) for the spool +
/// validation context; `vm_snapshot` is only consulted for the InFlight pass.
async fn list_active(
    state: &ControlState,
    bucket: Bucket,
    now: SystemTime,
    vm_snapshot: &VmSnapshot,
) -> (Vec<JobSummary>, bool) {
    let spool = state.spool.as_ref();
    let secret: &[u8] = &state.webhook_secret;
    let allowed_repos = state.allowed_repos.as_ref();
    let runner_label = state.runner_label.as_str();
    let runner_labels = state.runner_labels.as_ref();
    let now_ms = ms_since_epoch(now);
    let dir = match bucket {
        Bucket::Queued => spool.new_dir(),
        Bucket::InFlight => spool.cur_dir(),
    };
    let mut out = Vec::new();
    let mut examined = 0usize;
    let mut rd = match fs::read_dir(&dir).await {
        Ok(rd) => rd,
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "control: read_dir for job listing");
            return (out, false);
        }
    };
    loop {
        if examined >= ACTIVE_CAP {
            return (out, true);
        }
        let ent = match rd.next_entry().await {
            Ok(Some(ent)) => ent,
            Ok(None) => break,
            Err(e) => {
                warn!(dir = %dir.display(), error = %e, "control: read_dir entry");
                break;
            }
        };
        examined += 1;
        let name = ent.file_name();
        let Some(s) = name.to_str() else { continue };
        // Only canonical `<id>.job` entries. `parse_spool_filename` rejects
        // `.err`/`.bak` sidecars (and anything else), so they never appear.
        let Some(id) = parse_spool_filename(s) else {
            continue;
        };
        let path = ent.path();
        let mtime_ms = ent
            .metadata()
            .await
            .ok()
            .and_then(|m| m.modified().ok())
            .map(ms_since_epoch);
        let (env, body) = match read_spool_file(&path).await {
            Ok(v) => v,
            Err(e) => {
                // A file that moved new→cur→done between our read_dir and our
                // open yields NotFound — benign, skip silently. Anything else
                // is worth a warn but still omitted (never 500).
                if !is_vanished(&e) {
                    warn!(file = %sanitize_for_log(s), error = %format!("{e:#}"), "control: read spool entry for listing");
                }
                continue;
            }
        };
        let summary = match bucket {
            Bucket::Queued => {
                // Reject forged filename aliases (e.g. `09001.job` for id 9001):
                // the spooler only ever writes the canonical `{id}.job`, and
                // `prepare()` rejects anything else. This is the one prepare()
                // check that needs the raw filename, so we do it here.
                if s != format!("{id}.job") {
                    continue;
                }
                // Show only entries the dispatcher would actually Run; anything
                // it would Drop (not for us) or Reject (forged/malformed) is not
                // authentic, runnable queued work. Fields come from the body the
                // HMAC authenticated, not the envelope.
                let event = match classify_validated_entry(
                    id,
                    &env,
                    &body,
                    secret,
                    allowed_repos,
                    runner_label,
                    runner_labels,
                ) {
                    EntryVerdict::Run(event) => event,
                    EntryVerdict::Drop(_) | EntryVerdict::Reject(_) => continue,
                };
                // Mirror try_claim's dedupe/replay guard (read-only): a duplicate
                // redelivery whose id is already in cur/ (in flight) or archived
                // in done//error/ will be skipped-and-removed at claim, never run.
                // Don't show it as queued — most visible while paused.
                if already_claimed_or_archived(spool, s).await {
                    continue;
                }
                // received_at_ms is the spooler's enqueue time (authentic entry);
                // reconciler mints hard-code 0, so fall back to the file mtime.
                let enqueued_ms = if env.received_at_ms != 0 {
                    env.received_at_ms
                } else {
                    mtime_ms.unwrap_or(0)
                };
                JobSummary {
                    id: id.to_string(),
                    repo: sanitize_for_log(&event.repository.full_name),
                    name: Some(sanitize_for_log(&event.workflow_job.name)),
                    labels: event
                        .workflow_job
                        .labels
                        .iter()
                        .map(|l| sanitize_for_log(l))
                        .collect(),
                    run_id: Some(event.workflow_job.run_id.to_string()),
                    enqueued_ms: Some(enqueued_ms),
                    claimed_ms: None,
                    age_secs: age_secs(now_ms, enqueued_ms),
                    vm: None,
                    vm_status: None,
                }
            }
            Bucket::InFlight => {
                // Trusted bucket: read display fields directly, and stamp the
                // VM's status from the snapshot. Absent from the snapshot ->
                // None (booting / torn down, or no snapshot yet).
                let (job_name, labels, run_id) = parse_display_fields(&body);
                let claimed_ms = mtime_ms.unwrap_or(0);
                let vm = crate::runner::vm_name(id);
                let vm_status = vm_snapshot.vms.get(&vm).cloned().flatten();
                JobSummary {
                    id: id.to_string(),
                    repo: sanitize_for_log(&env.repo),
                    name: job_name,
                    labels,
                    run_id,
                    enqueued_ms: None,
                    claimed_ms: Some(claimed_ms),
                    age_secs: age_secs(now_ms, claimed_ms),
                    vm: Some(vm),
                    vm_status,
                }
            }
        };
        out.push(summary);
    }
    (out, false)
}

/// True iff a canonical `<id>.job` `name` already collides with an in-flight
/// claim (`cur/`) or a finalized archive (`done/`/`error/`) — exactly the states
/// `Spool::try_claim` treats as "won't run" (it skips + removes the duplicate
/// new/ copy). Read-only: the listing never mutates the spool; dispatch does the
/// removal. Mirrors `try_claim`'s `is_archived` + the cur/ AlreadyExists guard.
async fn already_claimed_or_archived(spool: &Spool, name: &str) -> bool {
    fs::try_exists(spool.cur_dir().join(name))
        .await
        .unwrap_or(false)
        || fs::try_exists(spool.done_dir().join(name))
            .await
            .unwrap_or(false)
        || fs::try_exists(spool.error_dir().join(name))
            .await
            .unwrap_or(false)
}

/// Best-effort `(name, labels, run_id)` from a spool body. name/labels go
/// through `sanitize_for_log`: they are author-controlled and the payload is
/// served off-host (not under HMAC). run_id is a GitHub-minted integer rendered
/// as a string (same 2^53 reason as `JobSummary::id`), so it needs no
/// sanitizing. All three are `None`/empty when the body doesn't parse.
fn parse_display_fields(body: &[u8]) -> (Option<String>, Vec<String>, Option<String>) {
    match serde_json::from_slice::<WorkflowJob>(body) {
        Ok(wj) => (
            Some(sanitize_for_log(&wj.workflow_job.name)),
            wj.workflow_job
                .labels
                .iter()
                .map(|l| sanitize_for_log(l))
                .collect(),
            Some(wj.workflow_job.run_id.to_string()),
        ),
        Err(_) => (None, Vec::new(), None),
    }
}

/// List done/ + error/ within the completed window, newest first, capped. Two
/// phases keep cost bounded: a cheap mtime-filtered walk that opens no bodies,
/// then body reads only for the windowed + capped subset.
async fn list_completed(spool: &Spool, now: SystemTime) -> (Vec<CompletedSummary>, bool) {
    let cutoff = now.checked_sub(Duration::from_secs(COMPLETED_WINDOW_SECS));
    let mut found: Vec<(u64, &'static str, u128, PathBuf)> = Vec::new();
    // Shared scan budget across both dirs, so a huge done/ can't make a poll
    // walk unboundedly before we even reach error/.
    let mut scanned = 0usize;
    let mut scan_capped =
        collect_window(&spool.done_dir(), "done", cutoff, &mut found, &mut scanned).await;
    scan_capped |= collect_window(
        &spool.error_dir(),
        "error",
        cutoff,
        &mut found,
        &mut scanned,
    )
    .await;
    if scan_capped {
        warn!(
            scan_cap = COMPLETED_SCAN_CAP,
            "control: completed scan hit its entry cap; listing may be incomplete (archive needs pruning)"
        );
    }

    // Newest first (by finished_ms), then cap.
    found.sort_by_key(|e| std::cmp::Reverse(e.2));
    let row_capped = found.len() > COMPLETED_CAP;
    found.truncate(COMPLETED_CAP);
    // `completed_truncated` means "results may be incomplete" — either more
    // than COMPLETED_CAP rows matched, or the scan budget was exhausted.
    let truncated = row_capped || scan_capped;

    let mut out = Vec::with_capacity(found.len());
    for (id, outcome, finished_ms, path) in found {
        // repo/name are best-effort and read only for this bounded subset; a
        // stale/unreadable archive still lists by id/outcome/time.
        let (repo, name) = match read_spool_file(&path).await {
            Ok((env, body)) => (
                Some(sanitize_for_log(&env.repo)),
                parse_display_fields(&body).0,
            ),
            Err(_) => (None, None),
        };
        let reason = if outcome == "error" {
            err_first_line(&path).await
        } else {
            None
        };
        out.push(CompletedSummary {
            id: id.to_string(),
            repo,
            name,
            outcome,
            finished_ms,
            reason,
        });
    }
    (out, truncated)
}

/// Phase-1 walk: push `(id, outcome, finished_ms, path)` for every canonical
/// `<id>.job` in `dir` whose mtime is within the window. Opens no bodies; skips
/// `.err`/`.bak` sidecars (they don't parse as `<id>.job`) and stats mtime
/// *before* committing the entry so out-of-window files are never opened later.
///
/// `scanned` is a shared, monotonic budget across all dirs in one poll: each
/// directory entry examined bumps it, and the walk stops once it reaches
/// `COMPLETED_SCAN_CAP`. Returns `true` iff it stopped on the cap (so the
/// caller can flag the listing as possibly incomplete).
async fn collect_window(
    dir: &Path,
    outcome: &'static str,
    cutoff: Option<SystemTime>,
    out: &mut Vec<(u64, &'static str, u128, PathBuf)>,
    scanned: &mut usize,
) -> bool {
    let mut rd = match fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "control: read_dir for completed listing");
            return false;
        }
    };
    loop {
        if *scanned >= COMPLETED_SCAN_CAP {
            return true;
        }
        let ent = match rd.next_entry().await {
            Ok(Some(ent)) => ent,
            Ok(None) => break,
            Err(e) => {
                warn!(dir = %dir.display(), error = %e, "control: read_dir entry");
                break;
            }
        };
        *scanned += 1;
        let name = ent.file_name();
        let Some(s) = name.to_str() else { continue };
        let Some(id) = parse_spool_filename(s) else {
            continue;
        };
        let Ok(md) = ent.metadata().await else {
            continue;
        };
        let Ok(mtime) = md.modified() else { continue };
        if let Some(cutoff) = cutoff {
            if mtime < cutoff {
                continue;
            }
        }
        out.push((id, outcome, ms_since_epoch(mtime), ent.path()));
    }
    false
}

/// First line of `<job_path>.err`, bounded and sanitized. `None` if there is no
/// sidecar, it is empty, or it isn't a plain file.
///
/// Hardened like `read_spool_file` even though the sidecar lives in our 0700
/// archive dir: O_NOFOLLOW so a swapped-in symlink can't redirect us to an
/// arbitrary daemon-readable file, O_NONBLOCK so a FIFO can't wedge the `/jobs`
/// handler on open, and a post-open fstat regular-file check.
async fn err_first_line(job_path: &Path) -> Option<String> {
    let mut p = job_path.as_os_str().to_owned();
    p.push(".err");
    let flags = libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(PathBuf::from(p))
        .await
        .ok()?;
    if !f.metadata().await.ok()?.file_type().is_file() {
        return None;
    }
    let mut buf = Vec::new();
    f.take(MAX_ERR_PREVIEW_BYTES)
        .read_to_end(&mut buf)
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&buf);
    let line = text.lines().next().unwrap_or("").trim();
    if line.is_empty() {
        None
    } else {
        Some(sanitize_for_log(line))
    }
}

fn ms_since_epoch(t: SystemTime) -> u128 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Whole seconds between two epoch-ms instants, saturating at 0 (clock skew /
/// future timestamps) and `u64::MAX`.
fn age_secs(now_ms: u128, then_ms: u128) -> u64 {
    u64::try_from(now_ms.saturating_sub(then_ms) / 1000).unwrap_or(u64::MAX)
}

/// Managed VM names present in the snapshot but absent from `claimed` (the set
/// of vm names backed by a live cur/ entry) — orphans GC will reap. Sorted for
/// stable output.
fn orphan_vm_names(snapshot: &VmSnapshot, claimed: &HashSet<&str>) -> Vec<String> {
    let mut orphans: Vec<String> = snapshot
        .vms
        .keys()
        .filter(|name| !claimed.contains(name.as_str()))
        .cloned()
        .collect();
    orphans.sort();
    orphans
}

/// True iff this error chain bottoms out in a `NotFound` — the benign case
/// where an entry moved (new→cur→done) between our `read_dir` and our open.
fn is_vanished(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .map(|io| io.kind() == std::io::ErrorKind::NotFound)
            .unwrap_or(false)
    })
}

fn router(state: ControlState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/status", get(get_status))
        .route("/jobs", get(get_jobs))
        .route("/pause", post(pause))
        .route("/resume", post(resume))
        .with_state(state)
}

/// Bind the loopback control listener. Separate from `serve` so the caller can
/// fail startup when the port is unavailable, rather than discovering it inside
/// a detached task. The caller has already validated `addr` is loopback (Config).
pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind control server on {addr}"))
}

/// Serve the control endpoints on an already-bound listener until exit.
pub async fn serve(listener: TcpListener, state: ControlState) -> Result<()> {
    axum::serve(listener, router(state))
        .await
        .context("control server")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Return the receiver too; a watch::Sender::send errors if every receiver
    // is dropped, and in production the supervisor holds one for the daemon's
    // life. Keep it alive for the test the same way. The returned TempDir is
    // the spool maildir's root — callers must keep it bound so it isn't
    // deleted out from under the listing endpoint.
    const TEST_SECRET: &[u8] = b"testsecret";
    const GATE_LABEL: &str = "lima-nix";

    fn state(max: usize) -> (ControlState, watch::Receiver<bool>, tempfile::TempDir) {
        let (pause, rx) = watch::channel(false);
        let dir = tempfile::tempdir().unwrap();
        for sub in ["new", "cur", "done", "error"] {
            std::fs::create_dir_all(dir.path().join(sub)).unwrap();
        }
        let labels: HashSet<String> = ["self-hosted", GATE_LABEL]
            .iter()
            .map(|s| s.to_string())
            .collect();
        // Seed an empty VM snapshot; tests that exercise vm_status replace it
        // via `with_vm_snapshot`. The sender is dropped — a watch receiver still
        // reads the initial value after the sender is gone.
        let (_vm_tx, vm_rx) = watch::channel(Arc::new(VmSnapshot::default()));
        let state = ControlState {
            pause,
            permits: Arc::new(Semaphore::new(max)),
            max_concurrency: max,
            spool: Arc::new(Spool::new(dir.path().to_path_buf())),
            webhook_secret: Arc::new(Zeroizing::new(TEST_SECRET.to_vec())),
            allowed_repos: Arc::new(["o/r".to_string()].into_iter().collect()),
            runner_labels: Arc::new(labels),
            runner_label: GATE_LABEL.to_string(),
            vms: vm_rx,
        };
        (state, rx, dir)
    }

    /// Override a state's VM snapshot for tests. `vms` is `(name, status)`;
    /// `taken_ms` of 0 means "never polled".
    fn with_vm_snapshot(s: &mut ControlState, taken_ms: u128, vms: &[(&str, Option<&str>)]) {
        let map = vms
            .iter()
            .map(|(n, st)| (n.to_string(), st.map(str::to_string)))
            .collect();
        let (_tx, rx) = watch::channel(Arc::new(VmSnapshot { taken_ms, vms: map }));
        s.vms = rx;
    }

    /// HMAC-SHA256 a body into the `sha256=<hex>` form `verify_signature` wants.
    fn sign(secret: &[u8], body: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    /// Schema-1 envelope line for a seeded spool entry, carrying `signature`.
    fn env_line(repo: &str, job_id: u64, received_at_ms: u128, signature: &str) -> String {
        format!(
            r#"{{"schema":1,"event":"workflow_job","delivery":"d","repo_id":42,"repo":"{repo}","action":"queued","workflow_job_id":{job_id},"received_at_ms":{received_at_ms},"signature":"{signature}"}}"#
        )
    }

    /// workflow_job body for a seeded spool entry.
    fn job_body(job_id: u64, name: &str, labels: &[&str]) -> Vec<u8> {
        let labels: Vec<serde_json::Value> = labels.iter().map(|l| serde_json::json!(l)).collect();
        serde_json::to_vec(&serde_json::json!({
            "action": "queued",
            "workflow_job": { "id": job_id, "run_id": 2, "name": name, "labels": labels },
            "repository": { "id": 42, "full_name": "o/r" }
        }))
        .unwrap()
    }

    /// Write `<root>/<subdir>/<name>` as a spool file (envelope line + body).
    async fn seed(root: &Path, subdir: &str, name: &str, env: &str, body: &[u8]) -> PathBuf {
        let path = root.join(subdir).join(name);
        let mut bytes = env.as_bytes().to_vec();
        bytes.push(b'\n');
        bytes.extend_from_slice(body);
        fs::write(&path, &bytes).await.unwrap();
        path
    }

    /// Seed a validly-HMAC'd `<id>.job` (signed with `TEST_SECRET`) into a dir —
    /// what the queued path requires to pass verification.
    async fn seed_signed(
        root: &Path,
        subdir: &str,
        id: u64,
        name: &str,
        labels: &[&str],
        received_at_ms: u128,
    ) -> PathBuf {
        let body = job_body(id, name, labels);
        let env = env_line("o/r", id, received_at_ms, &sign(TEST_SECRET, &body));
        seed(root, subdir, &format!("{id}.job"), &env, &body).await
    }

    /// Write the `error/<name>.err` sidecar for a seeded error entry.
    async fn seed_err(root: &Path, job_name: &str, contents: &str) {
        fs::write(root.join("error").join(format!("{job_name}.err")), contents)
            .await
            .unwrap();
    }

    #[test]
    fn in_flight_tracks_held_permits() {
        let (s, _rx, _dir) = state(4);
        assert_eq!(s.status().in_flight, 0);
        let _p1 = s.permits.clone().try_acquire_owned().unwrap();
        let _p2 = s.permits.clone().try_acquire_owned().unwrap();
        assert_eq!(s.status().in_flight, 2);
    }

    #[test]
    fn pause_flag_reflects_in_status() {
        let (s, _rx, _dir) = state(2);
        assert!(!s.status().paused);
        s.pause.send(true).unwrap();
        assert!(s.status().paused);
        s.pause.send(false).unwrap();
        assert!(!s.status().paused);
    }

    // Exercise the real HTTP wiring (routes + JSON), not just the state logic.
    #[tokio::test]
    async fn http_pause_resume_roundtrip() {
        let (s, _rx, _dir) = state(2); // keep _rx alive so pause/resume sends succeed
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { serve(listener, s).await.unwrap() });

        let base = format!("http://{addr}");
        let http = reqwest::Client::new();
        let get = |p: String| {
            let http = http.clone();
            async move {
                http.get(p)
                    .send()
                    .await
                    .unwrap()
                    .json::<serde_json::Value>()
                    .await
                    .unwrap()
            }
        };
        let post = |p: String| {
            let http = http.clone();
            async move {
                http.post(p)
                    .send()
                    .await
                    .unwrap()
                    .json::<serde_json::Value>()
                    .await
                    .unwrap()
            }
        };

        let v = get(format!("{base}/status")).await;
        assert_eq!(v["paused"], serde_json::json!(false));
        assert_eq!(v["max_concurrency"], serde_json::json!(2));

        let v = post(format!("{base}/pause")).await;
        assert_eq!(v["paused"], serde_json::json!(true));

        let v = post(format!("{base}/resume")).await;
        assert_eq!(v["paused"], serde_json::json!(false));
    }

    // The UI assets must actually serve (guarding the include_str! paths) with
    // content types a browser will render as HTML / execute as a script.
    #[tokio::test]
    async fn serves_embedded_ui() {
        let (s, _rx, _dir) = state(2);
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { serve(listener, s).await.unwrap() });

        let base = format!("http://{addr}");
        let http = reqwest::Client::new();

        let r = http.get(format!("{base}/")).send().await.unwrap();
        assert_eq!(r.status(), 200);
        let ct = r.headers()[reqwest::header::CONTENT_TYPE].to_str().unwrap();
        assert!(ct.starts_with("text/html"), "content-type was {ct:?}");
        assert!(r.text().await.unwrap().contains("<html"));

        let r = http.get(format!("{base}/app.js")).send().await.unwrap();
        assert_eq!(r.status(), 200);
        let ct = r.headers()[reqwest::header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .to_string();
        assert!(ct.contains("javascript"), "content-type was {ct:?}");
        assert!(!r.text().await.unwrap().is_empty());
    }

    // Seed one entry in each dir (+ an .err sidecar) and assert each lands in
    // the right bucket with the expected derived fields.
    #[tokio::test]
    async fn jobs_lists_queued_cur_and_completed() {
        let (s, _rx, dir) = state(4);
        let root = dir.path();
        seed_signed(root, "new", 1, "build", &["self-hosted", "lima-nix"], 1000).await;
        seed_signed(root, "cur", 2, "test", &["lima-nix"], 2000).await;
        seed_signed(root, "done", 3, "lint", &[], 3000).await;
        seed_signed(root, "error", 4, "deploy", &[], 4000).await;
        seed_err(root, "4.job", "boom: it broke\nsecond line").await;

        let jobs = s.jobs().await;

        assert_eq!(jobs.queued.len(), 1, "one queued entry");
        assert_eq!(jobs.queued[0].id, "1");
        assert_eq!(jobs.queued[0].repo, "o/r");
        assert_eq!(jobs.queued[0].name.as_deref(), Some("build"));
        assert_eq!(jobs.queued[0].labels, vec!["self-hosted", "lima-nix"]);
        assert_eq!(jobs.queued[0].enqueued_ms, Some(1000));
        assert!(jobs.queued[0].claimed_ms.is_none());
        assert!(jobs.queued[0].vm.is_none());
        // run_id comes from the body so the UI can deep-link to GitHub Actions.
        assert_eq!(jobs.queued[0].run_id.as_deref(), Some("2"));

        assert_eq!(jobs.in_flight.len(), 1, "one in-flight entry");
        assert_eq!(jobs.in_flight[0].id, "2");
        assert_eq!(jobs.in_flight[0].name.as_deref(), Some("test"));
        assert_eq!(jobs.in_flight[0].run_id.as_deref(), Some("2"));
        assert!(
            jobs.in_flight[0].claimed_ms.is_some(),
            "claimed_ms = file mtime"
        );
        assert!(jobs.in_flight[0].enqueued_ms.is_none());
        assert_eq!(
            jobs.in_flight[0].vm.as_deref(),
            Some(crate::runner::vm_name(2).as_str())
        );

        assert_eq!(jobs.completed.len(), 2, "one done + one error");
        let err = jobs.completed.iter().find(|c| c.id == "4").unwrap();
        assert_eq!(err.outcome, "error");
        assert_eq!(err.name.as_deref(), Some("deploy"));
        assert_eq!(
            err.reason.as_deref(),
            Some("boom: it broke"),
            "reason is the first line of the .err sidecar"
        );
        let done = jobs.completed.iter().find(|c| c.id == "3").unwrap();
        assert_eq!(done.outcome, "done");
        assert!(done.reason.is_none(), "done entries carry no reason");

        assert_eq!(jobs.completed_window_hours, 24);
        assert!(!jobs.completed_truncated);
    }

    // Backdating an entry's mtime past the window must drop it from completed.
    #[tokio::test]
    async fn jobs_completed_window_filters_old() {
        let (s, _rx, dir) = state(4);
        let root = dir.path();
        seed_signed(root, "done", 10, "fresh", &[], 0).await;
        let old = seed_signed(root, "done", 11, "old", &[], 0).await;
        // Move the old entry's mtime well past the 24h window.
        let backdate = SystemTime::now() - Duration::from_secs(COMPLETED_WINDOW_SECS + 3600);
        std::fs::File::open(&old)
            .unwrap()
            .set_modified(backdate)
            .unwrap();

        let jobs = s.jobs().await;
        let ids: Vec<&str> = jobs.completed.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"10"), "fresh entry should be listed: {ids:?}");
        assert!(
            !ids.contains(&"11"),
            "out-of-window entry should be filtered: {ids:?}"
        );
    }

    // `.err` and `.bak` sidecars must never be emitted as their own records.
    #[tokio::test]
    async fn jobs_skips_sidecars_and_baks() {
        let (s, _rx, dir) = state(4);
        let root = dir.path();
        seed_signed(root, "done", 20, "ok", &[], 0).await;
        // A preserved prior-archive .bak (see spool.rs preserve_existing).
        fs::write(root.join("done").join("20.job.1700000000000.bak"), b"prior")
            .await
            .unwrap();
        seed_signed(root, "error", 21, "boom", &[], 0).await;
        seed_err(root, "21.job", "the failure reason").await;

        let jobs = s.jobs().await;
        let mut ids: Vec<&str> = jobs.completed.iter().map(|c| c.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            vec!["20", "21"],
            "only canonical .job entries become records"
        );
        // The .err is surfaced as the error entry's reason, not as its own row.
        let e = jobs.completed.iter().find(|c| c.id == "21").unwrap();
        assert_eq!(e.reason.as_deref(), Some("the failure reason"));
    }

    // A malformed entry is omitted, not fatal: the listing still returns and
    // good entries alongside it still appear.
    #[tokio::test]
    async fn jobs_tolerates_unparseable_entry() {
        let (s, _rx, dir) = state(4);
        let root = dir.path();
        seed_signed(root, "new", 30, "good", &[GATE_LABEL], 5000).await;
        // No envelope newline -> read_spool_file errors -> entry omitted.
        fs::write(root.join("new").join("31.job"), b"garbage-without-newline")
            .await
            .unwrap();

        let jobs = s.jobs().await;
        let ids: Vec<&str> = jobs.queued.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["30"],
            "malformed entry omitted, good one still listed"
        );
    }

    // new/ is the unvalidated bucket: a tampered/forged entry (bad HMAC) must
    // not be rendered as a legitimate queued job; an authentic one shows.
    #[tokio::test]
    async fn jobs_omits_unauthenticated_queued_entry() {
        let (s, _rx, dir) = state(4);
        let root = dir.path();
        seed_signed(root, "new", 40, "good", &[GATE_LABEL], 0).await;
        // Forged: body signed with the wrong secret.
        let body = job_body(41, "forged", &[]);
        let env = env_line("o/r", 41, 0, &sign(b"wrong-secret", &body));
        seed(root, "new", "41.job", &env, &body).await;

        let jobs = s.jobs().await;
        let ids: Vec<&str> = jobs.queued.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["40"],
            "unauthenticated queued entry must be omitted"
        );
    }

    // Full dispatch parity: an authentic but not-for-us queued entry (missing
    // the gate label) is omitted, so the UI never shows a job we won't run.
    #[tokio::test]
    async fn jobs_omits_not_for_us_queued_entry() {
        let (s, _rx, dir) = state(4);
        let root = dir.path();
        // Missing the gate label -> prepare() would Drop it -> not listed.
        seed_signed(root, "new", 50, "wrong-pool", &["self-hosted"], 0).await;
        // Has the gate label -> would Run -> listed.
        seed_signed(root, "new", 51, "ours", &[GATE_LABEL], 0).await;

        let jobs = s.jobs().await;
        let ids: Vec<&str> = jobs.queued.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["51"], "not-for-us queued entry must be omitted");
    }

    // A queued redelivery whose id is already in flight (cur/) or archived
    // (done//error/) will be skipped at claim, so it must not show as queued.
    #[tokio::test]
    async fn jobs_omits_queued_duplicate_of_claimed_or_archived() {
        let (s, _rx, dir) = state(4);
        let root = dir.path();
        // Duplicate of an in-flight claim.
        seed_signed(root, "new", 60, "dup-inflight", &[GATE_LABEL], 0).await;
        seed_signed(root, "cur", 60, "dup-inflight", &[GATE_LABEL], 0).await;
        // Replay of a done/ archive.
        seed_signed(root, "new", 61, "dup-done", &[GATE_LABEL], 0).await;
        seed_signed(root, "done", 61, "dup-done", &[GATE_LABEL], 0).await;
        // Replay of an error/ archive.
        seed_signed(root, "new", 62, "dup-error", &[GATE_LABEL], 0).await;
        seed_signed(root, "error", 62, "dup-error", &[GATE_LABEL], 0).await;
        // A genuinely-runnable queued entry (no collision).
        seed_signed(root, "new", 63, "fresh", &[GATE_LABEL], 0).await;

        let jobs = s.jobs().await;
        let ids: Vec<&str> = jobs.queued.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["63"],
            "duplicates of cur/done/error must be omitted from queued"
        );
    }

    // Guards the 2^53 decision: ids serialize as JSON strings, not numbers.
    #[tokio::test]
    async fn jobs_id_is_string() {
        let (s, _rx, dir) = state(4);
        let root = dir.path();
        // Beyond JS's 2^53 safe-integer range.
        let big: u64 = 9_007_199_254_740_993;
        seed_signed(root, "new", big, "n", &[GATE_LABEL], 1).await;

        let v = serde_json::to_value(s.jobs().await).unwrap();
        assert!(
            v["queued"][0]["id"].is_string(),
            "id must serialize as a string"
        );
        assert_eq!(v["queued"][0]["id"], serde_json::json!(big.to_string()));
    }

    // A symlinked .err sidecar must not be followed (O_NOFOLLOW): the error
    // entry still lists, but with no reason rather than the link target's bytes.
    #[tokio::test]
    async fn jobs_err_sidecar_symlink_is_not_followed() {
        let (s, _rx, dir) = state(4);
        let root = dir.path();
        seed_signed(root, "error", 70, "boom", &[], 0).await;
        // A secret the daemon can read, and a sidecar symlink pointing at it.
        let secret = root.join("secret.txt");
        std::fs::write(&secret, b"SECRET-CONTENTS").unwrap();
        std::os::unix::fs::symlink(&secret, root.join("error").join("70.job.err")).unwrap();

        let jobs = s.jobs().await;
        let e = jobs.completed.iter().find(|c| c.id == "70").unwrap();
        assert_eq!(e.outcome, "error");
        assert!(
            e.reason.is_none(),
            "must not follow the symlinked sidecar; got {:?}",
            e.reason
        );
    }

    // The completed walk must stop once the shared scan budget is exhausted,
    // so a huge unpruned archive can't make a poll walk unboundedly.
    #[tokio::test]
    async fn jobs_completed_scan_respects_budget_cap() {
        let (s, _rx, dir) = state(4);
        let root = dir.path();
        for id in 0..3u64 {
            seed_signed(root, "done", id, "n", &[], 0).await;
        }
        // Start one short of the cap: exactly one more entry can be examined.
        let mut found = Vec::new();
        let mut scanned = COMPLETED_SCAN_CAP - 1;
        let capped =
            collect_window(&s.spool.done_dir(), "done", None, &mut found, &mut scanned).await;
        assert!(capped, "should report hitting the scan cap");
        assert_eq!(found.len(), 1, "only one entry examined before the cap");
        assert_eq!(scanned, COMPLETED_SCAN_CAP);
    }

    // In-flight rows are stamped with the VM's status from the snapshot, and
    // snapshot VMs with no live claim are reported as orphans.
    #[tokio::test]
    async fn jobs_inflight_vm_status_and_orphans() {
        let (mut s, _rx, dir) = state(4);
        seed_signed(dir.path(), "cur", 2, "test", &[GATE_LABEL], 0).await;
        let claimed_vm = crate::runner::vm_name(2);
        let orphan_vm = crate::runner::vm_name(999);
        with_vm_snapshot(
            &mut s,
            1_700_000_000_000,
            &[
                (claimed_vm.as_str(), Some("Running")),
                (orphan_vm.as_str(), Some("Running")),
            ],
        );

        let jobs = s.jobs().await;
        assert_eq!(jobs.in_flight.len(), 1);
        assert_eq!(jobs.in_flight[0].vm.as_deref(), Some(claimed_vm.as_str()));
        assert_eq!(jobs.in_flight[0].vm_status.as_deref(), Some("Running"));
        assert_eq!(jobs.orphan_vms, vec![orphan_vm]);
        assert_eq!(jobs.vm_snapshot_ms, Some(1_700_000_000_000));
    }

    // No snapshot entry for a claimed VM (just booted / torn down) -> vm_status
    // is null, and an empty snapshot yields no orphans.
    #[tokio::test]
    async fn jobs_inflight_vm_status_none_when_absent() {
        let (mut s, _rx, dir) = state(4);
        seed_signed(dir.path(), "cur", 3, "test", &[GATE_LABEL], 0).await;
        with_vm_snapshot(&mut s, 1_700_000_000_000, &[]);

        let jobs = s.jobs().await;
        assert_eq!(jobs.in_flight.len(), 1);
        assert!(jobs.in_flight[0].vm_status.is_none());
        assert!(jobs.orphan_vms.is_empty());
    }

    #[test]
    fn orphan_vm_names_excludes_claimed() {
        let snap = VmSnapshot {
            taken_ms: 1,
            vms: [
                ("gha-a".to_string(), Some("Running".to_string())),
                ("gha-b".to_string(), None),
            ]
            .into_iter()
            .collect(),
        };
        let claimed: HashSet<&str> = ["gha-a"].into_iter().collect();
        assert_eq!(orphan_vm_names(&snap, &claimed), vec!["gha-b".to_string()]);
    }

    // Smoke-test the route wiring end to end over HTTP.
    #[tokio::test]
    async fn jobs_endpoint_serves_json() {
        let (s, _rx, dir) = state(2);
        seed_signed(dir.path(), "new", 55, "n", &["self-hosted", GATE_LABEL], 1).await;
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { serve(listener, s).await.unwrap() });

        let http = reqwest::Client::new();
        let v = http
            .get(format!("http://{addr}/jobs"))
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(v["queued"][0]["id"], serde_json::json!("55"));
        assert_eq!(v["completed_window_hours"], serde_json::json!(24));
        assert!(v["completed"].is_array());
        // dir.path() was used above; keep `dir` alive until the request is done.
        drop(dir);
    }
}
