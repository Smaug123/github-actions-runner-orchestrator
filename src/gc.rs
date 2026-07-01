// Reconciliation sweep.
//
// Truth lives in three places:
//   1. cur/ on the spool filesystem — claimed jobs we believe are in flight,
//   2. `limactl list` on the host — VMs that actually exist,
//   3. /repos/{owner}/{repo}/actions/runners on GitHub, for each allowed repo —
//      runners GH thinks are registered.
//
// A periodic sweep walks all three and resolves drift:
//
//   * cur/ files older than JOB_MAX_RUNTIME_SECS are moved to error/ (we
//     assume the daemon was restarted mid-job and the VM is now an orphan).
//     Age is measured from claim time (mtime is stamped on rename into cur/);
//   * any Lima VM whose name has our `gha-` prefix but no live cur/ file is
//     stopped and deleted,
//   * any managed VM booted from a *superseded* guest image (its
//     `<instance>/lima.yaml` `images:` identity — the full normalized
//     `location:` plus, when both carry one, the `digest:` — differs from
//     the image the consumer's current LIMA_TEMPLATE points at) is reaped even
//     if it still holds a live cur/ claim. Such VMs are the wrong-config
//     leftovers from an operator image rebuild + restart: they oversubscribe
//     the host and, being still-online GitHub runners, steal freshly-queued
//     jobs and run them under the old image. We finalize their cur/ claim to
//     error/ so the runner-orphan branch below deletes the now-offline
//     runner. A VM whose image we cannot read is left alone (fail safe — we
//     never reap something we can't classify),
//   * any GH runner with our `gha-` prefix that isn't backed by a live cur/
//     file and is offline (or simply not busy) is DELETEd via API.
//
// `live` is built by reading each cur/ file's body and computing the same
// vm_name the supervisor would: signed (repo, workflow_job.id) → SHA-256.
// We never derive a vm_name from envelope/header data; using only signed
// fields means a replay produces the same name we already know about.
//
// SINGLETON DEPLOYMENT REQUIRED — EXACTLY ONE CONSUMER PER SPOOL_DIR, AND
// PER (account, set of allowed repos).
//
// The runner branch below treats *this* process's cur/ as the single
// source of truth for what `gha-<16hex>` runners should exist on each
// allowed repo. Two consumers covering the same repo with separate
// SPOOL_DIRs would each see the other's freshly-minted (online, not yet
// busy) runners as orphans and delete them in the window between mint
// and job pickup — a self-inflicted denial of service.
//
// The VM reaper (startup orphan reap + stale-image sweep) raises the bar
// further: it assumes a SINGLE consumer per SPOOL_DIR. Running multiple
// consumers against one shared SPOOL_DIR is NO LONGER SUPPORTED. Each
// consumer stops + deletes the others' managed `gha-<16hex>` VMs (the
// startup reap deletes *every* pre-existing managed VM by name shape; the
// stale-image sweep deletes any whose booted image differs from *this*
// consumer's LIMA_TEMPLATE) and finalizes the corresponding live cur/
// claims to error/, failing those peers' in-flight jobs.
//
// Safe configurations:
//   * one process per repo (or per disjoint set of repos);
//   * separate consumers covering *disjoint* repo sets, each with its own
//     SPOOL_DIR.
//
// Unsafe: separate consumers covering the same repo with separate
// SPOOL_DIRs; and multiple consumers sharing one SPOOL_DIR. There's no
// in-band check for either — the repo runner list doesn't carry "which
// consumer minted me", and the reaper can't tell a peer's live VM from a
// crashed predecessor's — so the launchd plist / deployment harness is the
// right place to enforce singleton. A future option is namespacing runner
// names per consumer (e.g. `gha-<consumer-id>-<jobid>`) and restricting GC
// to that namespace.
//
// REQUIRES RECONCILIATION (`RECONCILE_ENABLED=true`, the default). Reaping a
// *claimed* VM (both the startup orphan reap and the stale-image sweep)
// archives the reaped job's cur/ record to error/, and the queued-job
// reconciler is the only code that ignores archives to re-mint a runner for a
// job GitHub still reports as queued. With reconciliation disabled, a job that
// was claimed-but-still-queued when its VM is reaped is archived and never
// re-run. `Config::validate` therefore refuses to start with
// `RECONCILE_ENABLED=false`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::github::event::{Repository, WorkflowJob, WorkflowJobInfo};
use crate::github::jit::{GhClient, JobStatus, Runner};
use crate::lima::Lima;
use crate::runner::vm_name;
use crate::spool::{
    lock_archive_mutation, parse_spool_filename, sanitize_for_log, stamp_mtime_now, Spool,
};
use crate::supervisor::{classify_job_labels, spawn_job, LabelVerdict};

const VM_NAME_PREFIX: &str = "gha-";

/// How many times the one-shot startup reap tries to delete a single
/// pre-existing managed VM before giving up and leaving its cur/ claim for the
/// 6h stale-claim expiry. Small: each attempt already wraps a timeout, and a VM
/// that survives a few back-to-back deletes is wedged enough that more spinning
/// won't help.
const STARTUP_DELETE_ATTEMPTS: u32 = 3;
/// Fixed backoff between startup delete attempts. Short — this runs before the
/// supervisor starts claiming work, so it's on the daemon's startup path, but a
/// brief pause gives a busy/locked instance a moment to settle.
const STARTUP_DELETE_BACKOFF: std::time::Duration = std::time::Duration::from_secs(2);

/// True iff `name` matches the exact shape this factory ever mints:
/// `gha-` followed by 16 lowercase hex chars (the `{:016x}` of a u64
/// workflow_job id). The bare `gha-` prefix is too broad — other tooling in
/// the same org/host can plausibly use the same prefix, and GC's runner
/// branch deletes idle online runners, so a loose match risks blasting away
/// unrelated infrastructure.
pub(crate) fn is_managed_vm_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(VM_NAME_PREFIX) else {
        return false;
    };
    suffix.len() == 16
        && suffix
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub async fn sweep(config: &Config, gh: &GhClient, lima: &Lima) {
    if let Err(e) = sweep_inner(config, gh, lima).await {
        warn!(error = %e, "gc sweep error");
    }
}

/// Startup reap: stop + delete EVERY pre-existing managed (`gha-<16hex>`) VM,
/// then finalize EVERY pre-existing cur/ claim to error/ — including claims that
/// never had a VM.
///
/// A freshly-started consumer cannot re-adopt an in-flight job's `limactl shell`
/// session (the supervisor that owned it is gone), so every pre-existing claim
/// is unmanageable regardless of whether a VM exists: a VM would linger until
/// JOB_MAX_RUNTIME_SECS while its still-online runner steals freshly-queued
/// jobs, and a claim whose VM was never created — a crash between `try_claim`
/// and `limactl start` — would suppress the reconciler's re-mint (its cur/ file
/// makes `should_mint` return false) until the 6h stale-claim expiry. Finalizing
/// all of them to error/ lets the reconciler re-mint any still-queued job within
/// a tick. The one exception is a claim whose VM delete FAILED: that VM (and its
/// runner) may still be up, so its claim is left for the 6h expiry rather than
/// finalized here. This is safe under the documented pause -> drain -> restart
/// procedure: after a clean drain there are no managed VMs and no live claims,
/// so this is a no-op; after a crash it cleans up the wreckage.
///
/// MUST run before the supervisor begins claiming/launching jobs, so it can
/// never reap a VM the new consumer just started (it deletes by `gha-<16hex>`
/// shape, and a just-launched job would match) or finalize a claim it just
/// wrote. The runner-orphan branch of the periodic sweep deletes the now-offline
/// GitHub runners whose claims we finalize here.
pub async fn reap_all_managed_vms_at_startup(config: &Config, lima: &Lima) {
    let cur_dir = config.spool_dir.join("cur");
    // We finalize every reapable claim below, so an unreadable cur/ only costs us
    // the claim map — VMs are still reaped by name shape. Surface the read
    // failure (don't swallow it): the affected claims are backstopped by the 6h
    // stale-claim expiry rather than finalized here.
    let claims = live_vm_map_from_cur(&cur_dir).await.unwrap_or_else(|e| {
        warn!(error = %e, "startup reap: cannot read cur/ to map claims; VMs still reaped, unfinalized claims left for the 6h expiry");
        HashMap::new()
    });
    let spool = Spool::new(config.spool_dir.clone());

    let instances = match lima.list_instances().await {
        Ok(i) => i,
        Err(e) => {
            warn!(error = %e, "startup reap: limactl list failed; skipping");
            return;
        }
    };

    // Stop + delete every managed VM. Record which managed VM names limactl
    // listed (`present`) and which we FAILED to delete (`delete_failed`) so the
    // pure planner below can decide each claim's fate. Finalizing is deferred to
    // one pass after the delete loop rather than done inline: a claim's fate
    // depends on whether *its* VM survived, and a VM-less claim (crash between
    // `try_claim` and `limactl start`) has no instance to key off here at all.
    let mut present: HashSet<String> = HashSet::new();
    let mut delete_failed: HashSet<String> = HashSet::new();
    for (name, _dir) in instances {
        if !is_managed_vm_name(&name) {
            continue;
        }
        present.insert(name.clone());
        info!(vm = %name, "startup: reaping pre-existing managed VM (fresh consumer cannot re-adopt)");
        if let Err(e) = lima.stop(&name).await {
            warn!(vm = %name, error = %e, "startup reap: stop");
        }
        // `delete` returns Ok iff the VM is *actually* gone. A failure (limactl
        // error/timeout, VM still present) means the VM — and its possibly-live
        // runner — may still be up, so we must NOT finalize its cur/ claim to
        // error/: doing so would make the runner-orphan branch treat a live
        // runner as unbacked.
        //
        // Unlike the stale-image SWEEP path (which re-runs every GC_INTERVAL_SECS
        // and naturally re-attempts a still-present VM), this startup reap is
        // one-shot. Worse, a pre-existing orphan booted from the CURRENT image
        // that we fail to delete here would never be re-reaped by the periodic
        // sweep — it's current-image with a live cur/ claim, so it looks like a
        // healthy in-flight job — and would linger until the 6h stale-claim
        // expiry. So give the delete a bounded retry with a short fixed backoff
        // before giving up and recording it as delete_failed.
        if let Err(e) = delete_with_retry(lima, &name).await {
            error!(
                vm = %sanitize_for_log(&name),
                error = %e,
                "startup reap: delete failed after retries; leaving cur/ claim intact (will only be cleaned by the 6h stale-claim expiry)"
            );
            delete_failed.insert(name);
        }
    }

    // Finalize every reapable claim to error/ so the reconciler re-mints any
    // still-queued job within a tick. This covers both claims whose VM we just
    // deleted AND claims that never had a VM (the crash window between try_claim
    // and `limactl start`), which were previously stranded until the 6h expiry.
    // Claims whose VM delete failed are excluded (see delete_failed above).
    for fin in plan_startup_claim_finalizes(&claims, &present, &delete_failed) {
        if let Err(e) = spool
            .finalize_error(&fin.cur_path, fin.reason.message())
            .await
        {
            warn!(path = %fin.cur_path.display(), error = %e, "startup reap: finalize_error");
        }
    }
}

/// Bounded-retry wrapper around `Lima::delete` for the one-shot startup reap.
/// `delete` already returns `Ok` iff the VM is gone, so each `Err` means it's
/// still present (or presence couldn't be confirmed); we retry a few times with
/// a short fixed backoff and return the last error if it never succeeds. Used
/// only at startup: the periodic sweep retries naturally every GC_INTERVAL_SECS,
/// but a current-image orphan we fail to reap here would otherwise look healthy
/// to the sweep and linger until the 6h stale-claim expiry.
async fn delete_with_retry(lima: &Lima, name: &str) -> anyhow::Result<()> {
    let mut last_err = None;
    for attempt in 1..=STARTUP_DELETE_ATTEMPTS {
        match lima.delete(name).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                warn!(
                    vm = %sanitize_for_log(name),
                    attempt,
                    max = STARTUP_DELETE_ATTEMPTS,
                    error = %e,
                    "startup reap: delete attempt failed"
                );
                last_err = Some(e);
                if attempt < STARTUP_DELETE_ATTEMPTS {
                    tokio::time::sleep(STARTUP_DELETE_BACKOFF).await;
                }
            }
        }
    }
    Err(last_err.expect("loop runs at least once, so an Err was recorded on failure"))
}

/// A managed Lima VM as the sweep sees it: its name and, for a VM that still
/// holds a live claim, the guest image it booted (read from
/// `<instance>/lima.yaml`). `image` is `None` for an orphan (we never read it —
/// the VM is deleted regardless of image) or when the instance's lima.yaml
/// can't be read/parsed (the stale-image check then skips it, fail-safe).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedVm {
    name: String,
    image: Option<ImageIdentity>,
}

/// A destructive VM action the sweep decided on, kept as data so the *decision*
/// (`plan_vm_reaps`) is a pure function of its inputs, separable from the
/// limactl/spool *effects* that carry it out.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VmReap {
    /// Managed VM with no live claim. Stop + delete; there is no claim to
    /// finalize (an orphan is by definition unbacked).
    Orphan { name: String },
    /// Live-claimed VM booted from a superseded image. Stop + delete, and only
    /// on a *successful* delete finalize `cur_path` to error/ so the
    /// runner-orphan pass removes the now-offline runner this same sweep.
    /// `vm_location` is carried for the log/finalize reason.
    StaleImage {
        name: String,
        cur_path: PathBuf,
        vm_location: String,
    },
}

/// Why the startup reap is finalizing a pre-existing cur/ claim to error/. Both
/// cases are unmanageable by a fresh consumer (the supervisor that owned the
/// runner's `limactl shell` session is gone); they differ only in whether a VM
/// was found, which is useful operator signal in the error/ sidecar + log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartupFinalizeReason {
    /// The claim's managed VM existed and was stopped+deleted this startup.
    ReapedVm,
    /// No managed VM existed for this claim: the daemon crashed between
    /// `try_claim` and `limactl start`, stranding a still-queued job. Finalizing
    /// lets the reconciler re-mint within a tick instead of after the 6h expiry.
    NoVm,
}

impl StartupFinalizeReason {
    /// The reason string written to the error/ `.err` sidecar (and logged).
    fn message(self) -> &'static str {
        match self {
            StartupFinalizeReason::ReapedVm => {
                "startup: reaped orphan VM (fresh consumer cannot re-adopt)"
            }
            StartupFinalizeReason::NoVm => {
                "startup: claim had no live VM (crashed between claim and VM creation); reconciler will re-mint"
            }
        }
    }
}

/// A cur/ claim the startup reap decided to finalize to error/, kept as data so
/// the *decision* (`plan_startup_claim_finalizes`) is a pure function of its
/// inputs, separable from the spool *effects* that carry it out.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StartupClaimFinalize {
    cur_path: PathBuf,
    reason: StartupFinalizeReason,
}

/// Decide which managed VMs to reap this sweep, purely.
///
/// `live` is `None` when cur/ could not be read this tick. On that uncertainty
/// we must reap NOTHING: a transient unreadable cur/ mistaken for "no live
/// claims" would orphan (and delete) every managed VM and fail their in-flight
/// jobs. Every other branch fails safe on uncertainty too — a VM we can't
/// positively classify as stale (no current image, unreadable/unparsable booted
/// image) is left alone.
fn plan_vm_reaps(
    managed: &[ManagedVm],
    live: Option<&HashMap<String, PathBuf>>,
    current: Option<&ImageIdentity>,
) -> Vec<VmReap> {
    // Unknown live set (unreadable cur/) -> reap nothing. This is THE guard that
    // stops a transient FS error from deleting every managed VM.
    let Some(live) = live else {
        return Vec::new();
    };
    let mut plan = Vec::new();
    for vm in managed {
        match live.get(&vm.name) {
            // No live claim -> classic orphan.
            None => plan.push(VmReap::Orphan {
                name: vm.name.clone(),
            }),
            // Live claim: reap only if positively classified as stale-image.
            Some(cur_path) => {
                if let (Some(current), Some(image)) = (current, vm.image.as_ref()) {
                    if is_stale_image(image, current) {
                        plan.push(VmReap::StaleImage {
                            name: vm.name.clone(),
                            cur_path: cur_path.clone(),
                            vm_location: image.location.clone(),
                        });
                    }
                }
            }
        }
    }
    plan
}

/// Decide which pre-existing cur/ claims the startup reap should finalize to
/// error/, purely.
///
/// The startup reap runs BEFORE the supervisor claims or reconciles anything, so
/// every claim in cur/ belongs to a dead predecessor: its runner's `limactl
/// shell` session cannot be re-adopted, so the claim is unmanageable regardless
/// of whether a VM exists. Once the reap has stopped+deleted every managed VM it
/// could, we therefore finalize every remaining claim to error/ so the
/// reconciler re-mints any still-queued job within a tick — instead of stranding
/// it until the 6h stale-claim expiry.
///
/// The sole exception is a claim whose VM's delete FAILED (`delete_failed`):
/// that VM, and its possibly-live runner, may still be up, so finalizing would
/// make the runner-orphan pass treat a live runner as unbacked and delete it.
/// Those claims are left for the 6h expiry (the periodic sweep can't re-reap a
/// current-image VM that still holds a live claim, so that expiry is the
/// backstop).
///
/// `present` is every managed VM name limactl listed; a claim whose vm_name is
/// absent had no VM at all — the crash between `try_claim` and `limactl start` —
/// and is classified `NoVm` for the operator record. An empty `claims` (an
/// unreadable cur/, per the caller) yields an empty plan: nothing is finalized,
/// same fail-safe as before this pass existed.
fn plan_startup_claim_finalizes(
    claims: &HashMap<String, PathBuf>,
    present: &HashSet<String>,
    delete_failed: &HashSet<String>,
) -> Vec<StartupClaimFinalize> {
    let mut plan = Vec::new();
    for (vm, cur_path) in claims {
        // A VM we failed to delete may still be up with a live runner; leaving
        // its claim intact keeps the runner-orphan pass from deleting that
        // runner. Such a claim falls back to the 6h stale-claim expiry.
        if delete_failed.contains(vm) {
            continue;
        }
        let reason = if present.contains(vm) {
            StartupFinalizeReason::ReapedVm
        } else {
            StartupFinalizeReason::NoVm
        };
        plan.push(StartupClaimFinalize {
            cur_path: cur_path.clone(),
            reason,
        });
    }
    plan
}

/// Decide which GH runners to delete as orphans, purely. `live` is the claim
/// set AFTER this sweep's VM reaps (a reaped stale VM has dropped out so its
/// now-offline runner is deleted here). `None` -> delete nothing, for the same
/// reason as `plan_vm_reaps`: uncertainty must not delete live runners.
///
/// A runner is an orphan iff it has our exact managed name shape, no live claim
/// backs it, and it can't currently be doing useful work — offline, or online
/// but idle. A busy run-once runner is left alone: it's executing a (possibly
/// stolen) job and exits on its own afterward.
fn plan_runner_reaps<'a>(runners: &'a [Runner], live: Option<&HashSet<String>>) -> Vec<&'a Runner> {
    // Unknown live set (unreadable cur/) -> delete nothing, same reason as
    // plan_vm_reaps.
    let Some(live) = live else {
        return Vec::new();
    };
    runners
        .iter()
        .filter(|r| {
            is_managed_vm_name(&r.name)
                && !live.contains(&r.name)
                && (r.status == "offline" || !r.busy)
        })
        .collect()
}

/// Decide which GH runners to reap for one repo, reading cur/ *now* — after the
/// caller obtained `runners` from `list_runners`. Reading here, rather than
/// reusing a snapshot taken at the top of the sweep, is what closes the
/// mid-sweep mint race: by the strict `claim → mint → visible-in-list` order,
/// any runner present in `runners` already had its cur/ claim written before it
/// could appear in the list, so a cur/ read taken now is guaranteed to observe
/// that claim. A snapshot from *before* `list_runners` can miss a claim that
/// lands between the snapshot and the list response, then delete the runner's
/// registration and strand the still-booting VM in "Registration not found".
///
/// `reaped_stale` is the set of stale-image VMs this sweep positively destroyed;
/// their names are dropped from the fresh live set so their now-offline runners
/// are still deleted this sweep even if `finalize_error` failed to move the cur/
/// file (a successful finalize already removed it, so the subtraction only bites
/// on that rare failure). An unreadable cur/ yields a `None` live set → reap
/// nothing, the same fail-safe every other reap decision uses on uncertainty.
async fn plan_runner_reaps_from_cur<'a>(
    cur_dir: &Path,
    runners: &'a [Runner],
    reaped_stale: &HashSet<String>,
) -> Vec<&'a Runner> {
    plan_runner_reaps_from_cur_inner(
        cur_dir,
        runners,
        reaped_stale,
        None::<std::future::Ready<()>>,
    )
    .await
}

/// Test-seam variant of `plan_runner_reaps_from_cur`. `between` (when `Some`)
/// fires exactly once, after the caller's `list_runners` has returned and before
/// this function reads cur/ — the window a concurrent mint must land in for the
/// race regression to bite. Production calls with `None`. Mirrors
/// `prune_archive_dir_inner`'s `between` seam.
async fn plan_runner_reaps_from_cur_inner<'a, F>(
    cur_dir: &Path,
    runners: &'a [Runner],
    reaped_stale: &HashSet<String>,
    between: Option<F>,
) -> Vec<&'a Runner>
where
    F: std::future::Future<Output = ()>,
{
    if let Some(hook) = between {
        hook.await;
    }
    let live: Option<HashSet<String>> = match live_vm_names_from_cur(cur_dir).await {
        Ok(mut set) => {
            for name in reaped_stale {
                set.remove(name);
            }
            Some(set)
        }
        Err(e) => {
            warn!(error = %e, "gc: cannot read cur/ live claim set for runner reap; reaping no runners this tick");
            None
        }
    };
    plan_runner_reaps(runners, live.as_ref())
}

async fn sweep_inner(config: &Config, gh: &GhClient, lima: &Lima) -> anyhow::Result<()> {
    let cur_dir = config.spool_dir.join("cur");

    expire_stale_cur(
        &cur_dir,
        &config.spool_dir.join("error"),
        config.job_max_runtime_secs,
    )
    .await?;

    // Prune finalized entries (done/ + error/) past the retention window so the
    // archive maildirs — which try_claim's replay check and the control UI both
    // scan — don't grow without bound. Runs every GC_INTERVAL_SECS, ample for a
    // multi-day window. Ordering vs expire_stale_cur is irrelevant: a claim it
    // just aged into error/ gets a fresh (now) mtime and won't be pruned for a
    // full retention window.
    prune_old_archives(
        &config.spool_dir.join("done"),
        &config.spool_dir.join("error"),
        config.archive_retention_secs,
    )
    .await?;

    // Prune captured guest serial-console logs past their (separate, longer)
    // retention window. Best-effort and independent of the archive prune above:
    // these live under state_dir, not the spool, and key off their own knob.
    prune_serial_logs(
        &config.state_dir.join("logs"),
        config.serial_log_retention_secs,
    )
    .await;

    // vm_name -> cur/ path for every live claim, or `None` when cur/ could not
    // be read this tick. Every reap decision below treats `None` as "unknown —
    // reap nothing": a transient unreadable cur/ must never be mistaken for an
    // empty live set, which would delete every managed VM and every idle runner
    // and fail their in-flight jobs. (The rest of this sweep likewise fails safe
    // on uncertainty.)
    //
    // Read cur/ BEFORE `list_instances`, deliberately — do NOT reorder these.
    // VM names are a deterministic function of the (never-reused) job id, so a
    // job re-minted after its previous claim was archived reuses the SAME
    // `gha-<hash>` name as its old, possibly-still-present VM. If we took the
    // inventory first and read cur/ after, a re-mint's fresh claim written in
    // that window would adopt the OLD orphan VM: plan_vm_reaps would treat the
    // orphan as live and — if its image is stale — finalize the fresh claim to
    // error/ and delete it, disrupting the re-mint. Reading cur/ first prevents
    // that: a claim written after this read cannot back a VM in the later
    // inventory. This ordering is race-free the other direction too — a VM only
    // appears in `list_instances` long after `try_claim` wrote its claim (claim
    // precedes `limactl start` precedes list-visibility by far more than the few
    // ms between this read and the inventory), so no freshly-minted VM is ever
    // seen here as an orphan. The runner pass has the opposite tradeoff — a large
    // read→list_runners gap (the whole VM-reap loop, 60s per stop/delete) and no
    // destructive claim finalize — so it re-reads cur/ AFTER its list; see
    // `plan_runner_reaps_from_cur`.
    let live_map: Option<HashMap<String, PathBuf>> = match live_vm_map_from_cur(&cur_dir).await {
        Ok(m) => Some(m),
        Err(e) => {
            warn!(error = %e, "gc: cannot read cur/ live claim set; reaping nothing this tick");
            None
        }
    };

    // The image the consumer's current LIMA_TEMPLATE boots. None when we can't
    // read/parse the staged template; in that case we skip stale-image reaping
    // entirely (we have nothing to compare against) rather than reap blindly.
    let current_image = current_template_image(&config.lima_template).await;

    let spool = Spool::new(config.spool_dir.clone());

    // Enumerate managed VMs. For a VM that still holds a live claim, read the
    // image it booted so plan_vm_reaps can classify it as stale-or-not; orphans
    // (no live claim, incl. every VM when live_map is None) skip the read since
    // they're deleted regardless of image.
    let managed: Vec<ManagedVm> = match lima.list_instances().await {
        Ok(instances) => {
            let mut managed = Vec::new();
            for (name, dir) in instances {
                if !is_managed_vm_name(&name) {
                    continue;
                }
                let image = if live_map.as_ref().is_some_and(|m| m.contains_key(&name)) {
                    let img = vm_booted_image(dir.as_deref()).await;
                    if img.is_none() {
                        warn!(vm = %name, "gc: cannot determine booted image; skipping stale-image check");
                    }
                    img
                } else {
                    None
                };
                managed.push(ManagedVm { name, image });
            }
            managed
        }
        Err(e) => {
            warn!(error = %e, "gc: limactl list failed");
            Vec::new()
        }
    };

    // Execute the VM reap plan. Track the stale VMs we actually destroyed so the
    // runner pass sees their now-offline runners as unbacked in THIS sweep.
    let mut reaped_stale: HashSet<String> = HashSet::new();
    for reap in plan_vm_reaps(&managed, live_map.as_ref(), current_image.as_ref()) {
        match reap {
            VmReap::Orphan { name } => {
                info!(vm = %name, "gc: orphan Lima VM, deleting");
                if let Err(e) = lima.stop(&name).await {
                    warn!(vm = %name, error = %e, "stop");
                }
                if let Err(e) = lima.delete(&name).await {
                    warn!(vm = %name, error = %e, "delete");
                }
            }
            VmReap::StaleImage {
                name,
                cur_path,
                vm_location,
            } => {
                let current_location = current_image
                    .as_ref()
                    .map(|c| sanitize_for_log(&c.location))
                    .unwrap_or_default();
                info!(
                    vm = %name,
                    image = %sanitize_for_log(&vm_location),
                    current = %current_location,
                    "gc: reaping stale-image VM (still claimed) and finalizing its claim to error/"
                );
                if let Err(e) = lima.stop(&name).await {
                    warn!(vm = %name, error = %e, "stop");
                }
                // Only tear down the claim/live state once the VM is *actually*
                // gone. A failed delete (limactl error/timeout) means the VM —
                // and its still-online, possibly-busy runner — may still be up.
                // Finalizing the claim and dropping it from the live set here
                // would make the runner-orphan pass treat that live runner as
                // unbacked and delete it. So on delete failure we leave both the
                // cur/ claim and the live entry intact and let the next sweep
                // retry the reap.
                if let Err(e) = lima.delete(&name).await {
                    warn!(vm = %sanitize_for_log(&name), error = %e, "gc: delete failed for stale-image VM; leaving claim and live entry for next sweep");
                    continue;
                }
                // Finalize the live claim to error/ so the runner-orphan pass
                // deletes the now-offline GitHub runner (and so expire_stale_cur
                // won't keep aging a claim for a VM we just destroyed).
                let reason = format!(
                    "gc: reaped stale-image VM ({} != {})",
                    sanitize_for_log(&vm_location),
                    current_location
                );
                if let Err(e) = spool.finalize_error(&cur_path, &reason).await {
                    warn!(vm = %name, error = %e, "gc: finalize_error for reaped stale-image VM");
                }
                // Mark this VM reaped so the runner pass drops it from the
                // effective live set: the claim is gone and the VM is destroyed,
                // so its runner must be deleted THIS sweep — before GitHub can
                // hand the dead runner freshly-queued work.
                reaped_stale.insert(name);
            }
        }
    }

    for repo_full in &config.allowed_repos {
        let Some((owner, repo)) = repo_full.split_once('/') else {
            warn!(repo = %sanitize_for_log(repo_full), "gc: allowed repo is not owner/name; skipping");
            continue;
        };
        match gh.list_runners(owner, repo, VM_NAME_PREFIX).await {
            Ok(runners) => {
                // Re-read cur/ HERE, after the list_runners response, so a runner
                // minted since the top-of-sweep snapshot is seen as backed rather
                // than reaped (the mid-sweep mint race). `reaped_stale` drops the
                // stale-image VMs we destroyed this sweep so their now-offline
                // runners are still deleted. `None` (unreadable cur/) -> reap no
                // runners, same fail-safe as the VM pass.
                for r in plan_runner_reaps_from_cur(&cur_dir, &runners, &reaped_stale).await {
                    info!(
                        runner = %r.name,
                        repo = %repo_full,
                        status = %r.status,
                        busy = r.busy,
                        "gc: removing orphan runner"
                    );
                    if let Err(e) = gh.delete_runner(owner, repo, r.id).await {
                        warn!(runner = %r.name, error = %e, "delete runner");
                    }
                }
            }
            Err(e) => {
                warn!(repo = %sanitize_for_log(repo_full), error = %e, "gc: list runners failed")
            }
        }
    }
    Ok(())
}

/// The correctness backstop. GitHub assigns a queued job to any online idle
/// runner whose labels are a superset of the job's, so a runner we mint for one
/// job can be handed an unrelated queued job. This pass treats GitHub's queue
/// as authoritative: for each allowed repo it lists still-`queued` jobs and
/// mints a runner for any that isn't already covered by a live cur/ entry or an
/// online runner — recovering stolen jobs, jobs whose mint failed, and jobs
/// whose webhook we never received. Synthetic cur/ records make each mint
/// cur/-backed so GC, teardown, and stale-expiry treat it like any other job.
#[allow(clippy::too_many_arguments)]
pub async fn reconcile(
    config: &Arc<Config>,
    gh: &Arc<GhClient>,
    lima: &Arc<Lima>,
    spool: &Arc<Spool>,
    permits: &Arc<Semaphore>,
    webhook_secret: &[u8],
    runner_labels: &HashSet<String>,
    paused: &tokio::sync::watch::Receiver<bool>,
) {
    if let Err(e) = reconcile_inner(
        config,
        gh,
        lima,
        spool,
        permits,
        webhook_secret,
        runner_labels,
        paused,
    )
    .await
    {
        warn!(error = %e, "reconcile error");
    }
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_inner(
    config: &Arc<Config>,
    gh: &Arc<GhClient>,
    lima: &Arc<Lima>,
    spool: &Arc<Spool>,
    permits: &Arc<Semaphore>,
    webhook_secret: &[u8],
    runner_labels: &HashSet<String>,
    paused: &tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let cur_dir = config.spool_dir.join("cur");
    // An unreadable cur/ means we can't tell which queued jobs are already
    // claimed. Skip this mint pass rather than reconcile against a bogus-empty
    // live set (which would attempt a redundant mint per queued job); the next
    // tick retries once cur/ is readable again.
    let live = live_vm_names_from_cur(&cur_dir).await?;

    for repo_full in &config.allowed_repos {
        // Re-check pause before each repo's network I/O. The control endpoint
        // promises a paused daemon claims no new work so operators can drain to
        // in_flight == 0; bail out of the whole pass if pause flipped since the
        // tick started.
        if *paused.borrow() {
            return Ok(());
        }
        let Some((owner, repo)) = repo_full.split_once('/') else {
            warn!(repo = %sanitize_for_log(repo_full), "reconcile: allowed repo is not owner/name; skipping");
            continue;
        };
        // Runners GitHub has for us, by name, that can actually pick up a
        // queued job (`runner_can_serve`: online and idle). Our own live mints
        // are cur/-backed (in `live`) anyway; this set only guards against an
        // idle orphan runner from a crashed daemon, costing at most one tick of
        // re-mint latency until GC reaps it. Offline and busy runners are
        // excluded: neither can take the job (a busy run-once runner is already
        // executing a — possibly stolen — job and exits after).
        let idle: HashSet<String> = match gh.list_runners(owner, repo, VM_NAME_PREFIX).await {
            Ok(rs) => rs
                .into_iter()
                .filter(|r| is_managed_vm_name(&r.name) && runner_can_serve(r))
                .map(|r| r.name)
                .collect(),
            Err(e) => {
                warn!(repo = %sanitize_for_log(repo_full), error = %e, "reconcile: list runners failed");
                continue;
            }
        };
        let queued = match gh.list_queued_jobs(owner, repo).await {
            Ok(q) => q,
            Err(e) => {
                warn!(repo = %sanitize_for_log(repo_full), error = %e, "reconcile: list queued jobs failed");
                continue;
            }
        };
        for job in queued {
            // Re-check pause right before any mint: list_runners/list_queued_jobs
            // above can take a while, and pause may have flipped during them. A
            // paused daemon must not spawn new work.
            if *paused.borrow() {
                return Ok(());
            }
            // Same label policy as the webhook path (prepare()).
            if let LabelVerdict::Reject(_) =
                classify_job_labels(&job.labels, &config.runner_label, runner_labels)
            {
                continue;
            }
            let vm = vm_name(job.id);
            // A live cur/ entry counts as coverage. Known bounded caveat: if
            // this job's runner was stolen and is now busy on another job,
            // cur/<id>.job is still live yet that runner can't serve this job.
            // We cannot add capacity here — vm_name is job-id-derived, so there
            // is exactly one runner name and one VM per job, and both the
            // synthetic claim and `limactl start` would collide. Recovery is
            // deferred, not lost: when the stolen runner finishes, spawn_job's
            // completion check sees this job still queued, frees the cur/ entry,
            // and the next pass re-mints — bounded by that runner's runtime. The
            // per-run `runs-on` label is the real lever to remove the shuffle.
            if !should_mint(&vm, &live, &idle) {
                continue;
            }
            // Concurrency gate: the shared semaphore (held by every in-flight
            // job) is the source of truth. Non-blocking so we never stall the
            // reconcile task; once full we stop this pass and pick up next tick.
            let permit = match Arc::clone(permits).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => return Ok(()),
            };
            match spool
                .write_synthetic_claim(&job, repo_full, webhook_secret)
                .await
            {
                Ok(Some(cur_path)) => {
                    info!(vm = %vm, repo = %repo_full, job_id = job.id, run_id = job.run_id,
                        "reconcile: minting runner for queued job with no runner");
                    spawn_job(
                        Arc::clone(spool),
                        Arc::clone(config),
                        Arc::clone(gh),
                        Arc::clone(lima),
                        build_event(repo_full, &job),
                        cur_path,
                        permit,
                    );
                }
                // Raced a concurrent webhook claim for the same id; nothing to do.
                Ok(None) => drop(permit),
                Err(e) => {
                    warn!(job_id = job.id, error = %e, "reconcile: write synthetic claim failed");
                    drop(permit);
                }
            }
        }
    }
    Ok(())
}

/// Mint iff no live cur/ entry and no idle runner already covers this VM name
/// (which equals the job id).
fn should_mint(vm: &str, live: &HashSet<String>, idle: &HashSet<String>) -> bool {
    !live.contains(vm) && !idle.contains(vm)
}

/// True iff a runner can still pick up a queued job: it must be online **and**
/// idle. A busy run-once JIT runner is already executing some (possibly stolen)
/// job and exits after it, so it can't take another; an offline runner is a
/// dead orphan. Counting either as coverage would wrongly suppress a re-mint
/// and stall recovery until the unrelated job exits or GC reaps the runner.
fn runner_can_serve(r: &crate::github::jit::Runner) -> bool {
    r.status == "online" && !r.busy
}

/// Build the in-memory event the worker needs from an API job. `repository.id`
/// is informational (the worker keys on full_name + job id); the synthetic
/// spool record carries the authoritative `repo_id` straight from the API.
fn build_event(full_name: &str, job: &JobStatus) -> WorkflowJob {
    WorkflowJob {
        action: "queued".to_string(),
        workflow_job: WorkflowJobInfo {
            id: job.id,
            run_id: job.run_id,
            run_attempt: job.run_attempt,
            // The API JobStatus carries no head branch/sha, and a reconciled
            // job should not drive cache warming anyway, so leave them absent.
            head_branch: None,
            head_sha: None,
            name: job.name.clone(),
            labels: job.labels.clone(),
        },
        repository: Repository {
            id: job.repo_id,
            full_name: full_name.to_string(),
        },
    }
}

async fn expire_stale_cur(
    cur_dir: &Path,
    error_dir: &Path,
    max_age_secs: u64,
) -> anyhow::Result<()> {
    let mut rd = tokio::fs::read_dir(cur_dir).await?;
    let now = std::time::SystemTime::now();
    while let Some(ent) = rd.next_entry().await? {
        let md = match ent.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = md.modified().unwrap_or(now);
        let age = now.duration_since(modified).unwrap_or_default();
        if age.as_secs() > max_age_secs {
            let name = ent.file_name();
            warn!(file = %sanitize_for_log(&name.to_string_lossy()), age_secs = age.as_secs(), "stale cur/ entry -> error/");
            let from = ent.path();
            let to = error_dir.join(&name);
            let err_path = error_dir.join(format!("{}.err", name.to_string_lossy()));
            let _ = tokio::fs::write(
                &err_path,
                format!(
                    "expired by gc: age {}s > {}s\n",
                    age.as_secs(),
                    max_age_secs
                ),
            )
            .await;
            match tokio::fs::rename(&from, &to).await {
                // rename preserves the claim-time mtime; stamp the archive to
                // now so the "completed" view reads expiry (= finish) time, and
                // a long-claimed job expired now isn't filtered out of the
                // recent-completions window.
                Ok(()) => stamp_mtime_now(&to),
                Err(e) => warn!(error = %e, "rename stale cur/ -> error/"),
            }
        }
    }
    Ok(())
}

/// Prune finalized spool entries older than `retention_secs` from `done/` and
/// `error/`.
///
/// `retention_secs == 0` disables pruning (keeps the archive forever) — an
/// explicit switch so a misconfigured non-zero age can't be the only thing
/// standing between the daemon and wiping the whole archive.
///
/// Each file is judged by its **own** mtime — the finalize-time `rename` +
/// `stamp_mtime_now` sets it to completion time — so a `<id>.job`, its
/// `<id>.job.err` sidecar, and any `<id>.job.<millis>.bak` are pruned
/// independently. They're written within milliseconds of each other, so against
/// a multi-day window they always fall on the same side, and independent
/// deletion also sweeps orphaned sidecars/baks.
///
/// Best-effort, like `expire_stale_cur`: a per-file failure is logged and
/// skipped, a missing dir is treated as empty — never fatal to the sweep.
async fn prune_old_archives(
    done_dir: &Path,
    error_dir: &Path,
    retention_secs: u64,
) -> anyhow::Result<()> {
    if retention_secs == 0 {
        return Ok(());
    }
    for dir in [done_dir, error_dir] {
        prune_archive_dir(dir, retention_secs).await;
    }
    Ok(())
}

/// Prune one archive dir in place. All failures are logged, never propagated; a
/// missing dir is treated as empty.
async fn prune_archive_dir(dir: &Path, retention_secs: u64) {
    prune_archive_dir_inner(dir, retention_secs, None::<std::future::Ready<()>>).await
}

/// Test-seam variant. `between` (when `Some`) fires exactly once, after the
/// first entry is judged expired by the directory-iteration stat and before the
/// archive-mutation lock is taken — the window a concurrent `finalize_*`
/// re-archive must hit. Production calls with `None`. Mirrors
/// `Spool::try_claim_inner`'s `between_checks` seam.
async fn prune_archive_dir_inner<F>(dir: &Path, retention_secs: u64, mut between: Option<F>)
where
    F: std::future::Future<Output = ()>,
{
    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "gc: archive dir unreadable during prune");
            return;
        }
    };
    let now = std::time::SystemTime::now();
    let mut removed: u64 = 0;
    let mut bytes_freed: u64 = 0;
    loop {
        let ent = match rd.next_entry().await {
            Ok(Some(ent)) => ent,
            Ok(None) => break,
            Err(e) => {
                warn!(dir = %dir.display(), error = %e, "gc: read_dir failed mid-prune; stopping dir");
                break;
            }
        };
        let md = match ent.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        // Only regular files: leave any subdir/symlink alone (checked before age
        // so a non-regular entry is never a deletion candidate regardless of mtime).
        if !md.is_file() {
            continue;
        }
        let modified = md.modified().unwrap_or(now);
        let age = now.duration_since(modified).unwrap_or_default();
        if age.as_secs() <= retention_secs {
            continue;
        }
        let name = ent.file_name();
        let path = ent.path();
        // Test seam: fire the injected hook in the exact window a concurrent
        // re-archive would race (expired decision made, lock not yet held).
        if let Some(hook) = between.take() {
            hook.await;
        }
        // This entry looked expired by the directory-iteration stat, but a
        // concurrent finalize_* could re-archive the same job id: `archive()`
        // moves the old marker aside to `.bak` and installs a fresh-mtime
        // done/<id>.job (or error/<id>.job) at this same path. Deleting by path
        // on the stale stat would then unlink that fresh marker, dropping the
        // replay guard and completion record for a job that just finished. There
        // is no portable atomic unlink-this-inode, so we serialize against
        // finalize via the process-global archive-mutation lock (sound because
        // deployment is singleton per SPOOL_DIR — finalize_* is the only other
        // writer). Held only around the recheck+unlink of an already-expired
        // candidate, so finalize is never blocked for the whole scan.
        let removed_entry = {
            let _guard = lock_archive_mutation().await;
            // Authoritative under the lock: no finalize can install a fresh
            // marker while we hold it. symlink_metadata keeps the no-follow view.
            let fresh = match tokio::fs::symlink_metadata(&path).await {
                Ok(m) => m,
                // Gone already (a prior finalize/sweep won); nothing to do.
                Err(_) => continue,
            };
            // A re-archive stamps the marker to ~now, so a now-fresh file means
            // finalize replaced it since the iteration stat: leave it.
            if !fresh.is_file() {
                continue;
            }
            let fresh_age = now
                .duration_since(fresh.modified().unwrap_or(now))
                .unwrap_or_default();
            if fresh_age.as_secs() <= retention_secs {
                continue;
            }
            match tokio::fs::remove_file(&path).await {
                Ok(()) => Some((fresh.len(), fresh_age.as_secs())),
                // Raced a sweep that removed it; not an error.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => {
                    warn!(file = %sanitize_for_log(&name.to_string_lossy()), error = %e, "gc: failed to prune archived entry");
                    None
                }
            }
        };
        if let Some((len, age_secs)) = removed_entry {
            removed += 1;
            bytes_freed += len;
            debug!(file = %sanitize_for_log(&name.to_string_lossy()), age_secs, "gc: pruned archived entry");
        }
    }
    if removed > 0 {
        info!(dir = %dir.display(), removed, bytes_freed, "gc: pruned old archive entries");
    }
}

/// Prune captured guest serial-console logs (`<logs_dir>/<vm>.serial.log`,
/// written by `runner::write_serial_evidence` when a job's VM shows a kernel
/// OOM) older than `retention_secs`. `0` disables pruning (keep forever),
/// mirroring `prune_old_archives`.
///
/// Unlike the archive prune this needs NO archive-mutation lock or
/// recheck-under-lock. That machinery exists because `finalize_*` can
/// re-archive the same `done/`/`error/` path mid-scan, installing a fresh-mtime
/// marker a delete-by-stale-stat would then drop. Serial logs cannot hit that
/// race: their sole writer writes each `<vm>.serial.log` at most once *ever* —
/// VM names derive from the globally-unique, never-reused GitHub job id — so no
/// concurrent re-write can race a delete at the same path. A plain age-gated
/// unlink is correct.
///
/// Scoped to the `.serial.log` suffix so anything else parked in `logs/` is left
/// alone. Best-effort like `prune_archive_dir`: a per-file failure is logged and
/// skipped, a missing dir treated as empty — never fatal to the sweep.
async fn prune_serial_logs(logs_dir: &Path, retention_secs: u64) {
    if retention_secs == 0 {
        return;
    }
    let mut rd = match tokio::fs::read_dir(logs_dir).await {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!(dir = %logs_dir.display(), error = %e, "gc: logs dir unreadable during prune");
            return;
        }
    };
    let now = std::time::SystemTime::now();
    let mut removed: u64 = 0;
    let mut bytes_freed: u64 = 0;
    loop {
        let ent = match rd.next_entry().await {
            Ok(Some(ent)) => ent,
            Ok(None) => break,
            Err(e) => {
                warn!(dir = %logs_dir.display(), error = %e, "gc: read_dir failed mid-prune; stopping dir");
                break;
            }
        };
        let name = ent.file_name();
        if !name.to_string_lossy().ends_with(".serial.log") {
            continue;
        }
        // DirEntry::metadata is lstat-like (does not follow symlinks), so a
        // symlink shows as non-regular here and is skipped — we never unlink
        // through one. Gate on is_file() before the age check.
        let md = match ent.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !md.is_file() {
            continue;
        }
        let age = now
            .duration_since(md.modified().unwrap_or(now))
            .unwrap_or_default();
        if age.as_secs() <= retention_secs {
            continue;
        }
        match tokio::fs::remove_file(ent.path()).await {
            Ok(()) => {
                removed += 1;
                bytes_freed += md.len();
            }
            // Raced a concurrent removal; not an error.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(file = %sanitize_for_log(&name.to_string_lossy()), error = %e, "gc: failed to prune serial log")
            }
        }
    }
    if removed > 0 {
        info!(dir = %logs_dir.display(), removed, bytes_freed, "gc: pruned old serial-console logs");
    }
}

/// Derive the expected vm_name for each cur/ file straight from its
/// filename. The filename is `<workflow_job_id>.job`, and vm_name is a
/// deterministic function of that id, so we don't need to read any bodies
/// here. The supervisor validates the filename ↔ envelope id match before
/// it ever lets a file get into cur/, so what's here is trustworthy.
async fn live_vm_names_from_cur(cur_dir: &Path) -> anyhow::Result<HashSet<String>> {
    Ok(live_vm_map_from_cur(cur_dir).await?.into_keys().collect())
}

/// Like `live_vm_names_from_cur`, but returns the cur/ path alongside each
/// derived `vm_name`. The stale-image reap needs the path so it can finalize a
/// reaped VM's claim to error/; the bare set view above is kept for callers
/// (reconcile) that only need membership.
async fn live_vm_map_from_cur(cur_dir: &Path) -> anyhow::Result<HashMap<String, PathBuf>> {
    let mut out = HashMap::new();
    // read_dir / next_entry failures stay HARD errors: a truncated enumeration
    // could UNDER-report live claims, and a missing claim is exactly what makes
    // the sweep delete a live VM/runner. Callers treat this Err as "reap
    // nothing this tick" rather than as an empty live set.
    let mut rd = tokio::fs::read_dir(cur_dir).await?;
    while let Some(ent) = rd.next_entry().await? {
        // The filename alone identifies the claim and its vm_name (the
        // supervisor validated the filename<->id match before the file entered
        // cur/), so a name that doesn't parse as `<id>.job` is simply not a
        // claim -> skip it, no stat needed.
        let name = ent.file_name();
        let Some(id) = name.to_str().and_then(parse_spool_filename) else {
            continue;
        };
        // file_type is only a best-effort filter for a stray non-file that
        // happens to be named like a claim (never happens in a healthy spool).
        // Skip ONLY entries we can positively confirm are non-regular; on a stat
        // error KEEP the claim — dropping one we can't stat would make the sweep
        // treat its live VM/runner as an orphan and delete it (fail-safe: an
        // unreadable-but-claim-named entry stays live).
        if let Ok(ft) = ent.file_type().await {
            if !ft.is_file() {
                continue;
            }
        }
        out.insert(vm_name(id), ent.path());
    }
    Ok(out)
}

/// Identity of a guest image as named by a Lima template/instance YAML's first
/// `images:` entry. We compare the **full normalized `location`** (the whole
/// `file://…`/path value, sans scheme + surrounding quotes) — guaranteed
/// present in both the consumer's template and each materialized
/// `<instance>/lima.yaml`, and distinct per build for our images (NixOS images
/// are uniquely timestamped paths; the Ubuntu interim template's location
/// carries a `release-YYYYMMDD` dir). The basename alone is insufficient: two
/// builds can share a filename (e.g. the checked-in
/// `ubuntu-24.04-server-cloudimg-arm64.img`) yet differ by directory/digest.
///
/// `digest` (the `sha256:…` line Lima writes alongside `location`) is captured
/// best-effort and only consulted when BOTH identities carry one, guarding
/// against a same-path rebuild. Verified against a real
/// `~/.lima/gha-*/lima.yaml`: both `location` and `digest` are present, so this
/// is realistic, but the comparison treats `digest` as optional so a future
/// Lima that omits it still classifies by `location`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageIdentity {
    /// The `location` value with any `scheme://` prefix and surrounding quotes
    /// stripped. The must-have field; identity is undefined without it.
    location: String,
    /// The `digest` value (e.g. `sha256:…`) if the image block carried one.
    digest: Option<String>,
}

/// The guest-image identity the consumer's current LIMA_TEMPLATE boots, e.g.
/// location `…/gha-guest-nixos-20260529-224941.raw`. Returns `None` (caller
/// skips stale-image reaping) if the template can't be read or has no parseable
/// `images:` `location:`. `config.lima_template` is the staged 0600 copy under
/// state_dir, so this reads bytes we control.
async fn current_template_image(template: &Path) -> Option<ImageIdentity> {
    let yaml = match tokio::fs::read_to_string(template).await {
        Ok(s) => s,
        Err(e) => {
            warn!(path = %template.display(), error = %e, "gc: read LIMA_TEMPLATE for stale-image check");
            return None;
        }
    };
    parse_image_identity(&yaml)
}

/// The guest-image identity a Lima instance was actually booted from, read
/// from `<instance_dir>/lima.yaml` (the realized config Lima writes per
/// instance). Returns `None` — caller skips, never reaps — if the dir is
/// unknown, the file is unreadable, or it has no parseable location.
async fn vm_booted_image(dir: Option<&Path>) -> Option<ImageIdentity> {
    let dir = dir?;
    let path = dir.join("lima.yaml");
    let yaml = match tokio::fs::read_to_string(&path).await {
        Ok(s) => s,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "gc: read instance lima.yaml for stale-image check");
            return None;
        }
    };
    parse_image_identity(&yaml)
}

/// Extract the identity of the first `images:` entry in a Lima
/// template/instance YAML: its full normalized `location` plus, if the same
/// block carries one, its `digest`. We deliberately do NOT pull in a YAML
/// parser: the codebase already parses limactl output by hand, and the shape we
/// need is a couple of well-known lines.
///
/// We must read the `location:` from WITHIN the top-level `images:` block, not
/// the first `location:` anywhere in the file: a valid Lima YAML can carry an
/// earlier `location:` outside `images:` (a `mounts:` entry, or Lima's default
/// `containerd.archives: - location: https://…nerdctl…`). Reading that would
/// compare the wrong value and either disable reaping or reap on an unrelated
/// change. So we first scan for the top-level `images:` key (a non-indented
/// `images:` line), then read the first image list item's `location:` and its
/// sibling `digest:` from inside that block, stopping at the next top-level
/// (non-indented) key so we never wander outside `images:`. Within the block we
/// take the first list item; our templates carry a single image item, so
/// first-item is correct. Lima writes `arch:` then `digest:` after `location:`
/// within one list item; a subsequent `- ` list-item dash or another
/// `location:` ends the first item, so we never borrow a later image's digest.
///
/// Pure and unit-tested; returns `None` if no usable `images:` `location:` is
/// found (fail safe — the caller skips, never reaps, what it can't classify).
fn parse_image_identity(yaml: &str) -> Option<ImageIdentity> {
    let mut lines = yaml.lines();
    // Phase 0: advance to the top-level `images:` key. A top-level key is a
    // non-indented line; `images:` nested under something else is not the block
    // we want, and a `location:` before `images:` (mounts, containerd.archives)
    // must be ignored.
    loop {
        let line = lines.next()?;
        if is_top_level_key(line, "images") {
            break;
        }
    }
    // Phase 1: within the `images:` block, find the first usable `location:`.
    // Stop if we hit the next top-level key first (an `images:` with no usable
    // list item — fail safe).
    let location = loop {
        let line = lines.next()?;
        if is_top_level_key_line(line) {
            return None;
        }
        let mut t = line.trim();
        if let Some(rest) = t.strip_prefix("- ") {
            t = rest.trim_start();
        }
        let Some(value) = t.strip_prefix("location:") else {
            continue;
        };
        if let Some(norm) = normalize_yaml_value(value) {
            break norm;
        }
        // A `location:` with an empty/unusable value is not a real image;
        // keep scanning for the next one within the block.
    };
    // Phase 2: read forward within the same image list item for a sibling
    // `digest:`. Stop at the next list-item dash, another `location:`, or the
    // next top-level key, any of which ends the first image item.
    let mut digest = None;
    for line in lines {
        if is_top_level_key_line(line) {
            break;
        }
        let t = line.trim();
        if t.starts_with("- ") || t.starts_with("location:") {
            break;
        }
        if let Some(value) = t.strip_prefix("digest:") {
            if let Some(norm) = normalize_yaml_value(value) {
                digest = Some(norm);
            }
            break;
        }
    }
    Some(ImageIdentity { location, digest })
}

/// True iff `line` is a non-indented (top-level) YAML mapping key — i.e. it has
/// no leading whitespace and isn't blank/a comment/a list item. Used to bound
/// the `images:` block so we never read a `location:`/`digest:` from a
/// different top-level section.
fn is_top_level_key_line(line: &str) -> bool {
    if line.is_empty() {
        return false;
    }
    let first = line.as_bytes()[0];
    // Indented (part of a block), blank, a list item, or a comment: not a
    // top-level key.
    !(first == b' ' || first == b'\t' || first == b'-' || first == b'#')
}

/// True iff `line` is exactly the top-level `<key>:` (optionally with a
/// trailing value), with no leading indentation.
fn is_top_level_key(line: &str, key: &str) -> bool {
    if !is_top_level_key_line(line) {
        return false;
    }
    let Some(rest) = line.strip_prefix(key) else {
        return false;
    };
    rest.starts_with(':')
}

/// Strip an inline YAML comment (a `#` that begins a comment) from a scalar
/// value, honoring quoting: a `#` inside a `"..."` or `'...'` span is part of
/// the value, while a `#` outside any quotes — or after the closing quote of a
/// quoted scalar — starts a comment and is dropped along with everything after
/// it. Trailing whitespace left behind by the strip is trimmed.
///
/// Lima realizes the per-instance `lima.yaml` without the template's inline
/// comments, so e.g. `location: "file:///img.raw" # pinned` must reduce to the
/// same scalar as the realized `location: "file:///img.raw"`; otherwise the
/// trailing `# pinned` would make a healthy VM look stale and get reaped.
fn strip_inline_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'#' => {
                    // A comment must be preceded by whitespace (or start the
                    // string) to count; YAML treats `a#b` as a literal. After a
                    // closing quote (i.e. not mid-token) `#` also starts a
                    // comment, and there the preceding char is the quote, not
                    // whitespace — but our values are always quoted-then-comment
                    // with a space, or bare-then-space-then-comment, so requiring
                    // a preceding space/quote/string-start is correct and avoids
                    // eating a `#` embedded in an unquoted path.
                    let prev_ok = i == 0 || matches!(bytes[i - 1], b' ' | b'\t' | b'"' | b'\'');
                    if prev_ok {
                        return value[..i].trim_end();
                    }
                }
                _ => {}
            },
        }
        i += 1;
    }
    value
}

/// Trim a YAML scalar value: strip any inline comment, then surrounding
/// whitespace, matching single or double quotes, and any `scheme://` prefix
/// (`file://`, `https://`, …) so `location` values compare by their underlying
/// path. Returns `None` for an empty result.
fn normalize_yaml_value(value: &str) -> Option<String> {
    let value = strip_inline_comment(value);
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value)
        .trim();
    if value.is_empty() {
        return None;
    }
    // Drop a `scheme://` prefix so two forms of the same path compare equal.
    let after_scheme = value.split("://").last().unwrap_or(value);
    if after_scheme.is_empty() {
        return None;
    }
    Some(after_scheme.to_string())
}

/// True iff a VM's booted image differs from the consumer's current image.
/// Pure; the caller has already ensured both are known (a `None` for either
/// means "can't classify" and is handled as skip upstream, never reap).
///
/// Identity is the full normalized `location`. The `digest` is a secondary
/// signal: when BOTH identities carry one we treat differing digests as stale
/// (catches a same-path rebuild); when either omits a digest we fall back to
/// location-only so a digest-less Lima never mass-reaps matching VMs.
fn is_stale_image(vm_image: &ImageIdentity, current_image: &ImageIdentity) -> bool {
    if vm_image.location != current_image.location {
        return true;
    }
    match (&vm_image.digest, &current_image.digest) {
        (Some(a), Some(b)) => a != b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::vm_name;

    #[test]
    fn is_managed_vm_name_accepts_generated_shape() {
        assert!(is_managed_vm_name(&vm_name(0)));
        assert!(is_managed_vm_name(&vm_name(42)));
        assert!(is_managed_vm_name(&vm_name(u64::MAX)));
        // The generator always pads to 16 hex chars.
        assert!(is_managed_vm_name("gha-0000000000000001"));
        assert!(is_managed_vm_name("gha-deadbeefcafebabe"));
    }

    #[test]
    fn should_mint_skips_cur_or_idle_coverage() {
        let vm = vm_name(42);
        let empty = HashSet::new();
        assert!(should_mint(&vm, &empty, &empty));
        let live: HashSet<String> = [vm.clone()].into_iter().collect();
        assert!(
            !should_mint(&vm, &live, &empty),
            "covered by a live cur/ entry"
        );
        let idle: HashSet<String> = [vm.clone()].into_iter().collect();
        assert!(
            !should_mint(&vm, &empty, &idle),
            "covered by an idle runner"
        );
    }

    #[test]
    fn runner_can_serve_requires_online_and_idle() {
        let mk = |status: &str, busy: bool| crate::github::jit::Runner {
            id: 1,
            name: vm_name(1),
            status: status.to_string(),
            busy,
        };
        assert!(runner_can_serve(&mk("online", false)), "online idle serves");
        assert!(
            !runner_can_serve(&mk("online", true)),
            "busy run-once runner can't take another job"
        );
        assert!(
            !runner_can_serve(&mk("offline", false)),
            "offline can't serve"
        );
        assert!(
            !runner_can_serve(&mk("offline", true)),
            "offline can't serve"
        );
    }

    #[test]
    fn build_event_carries_job_fields() {
        let job = JobStatus {
            id: 7,
            status: "queued".into(),
            run_id: 3,
            run_attempt: 2,
            name: "build".into(),
            labels: vec!["self-hosted".into(), "lima-nix".into()],
            repo_id: 99,
        };
        let ev = build_event("o/r", &job);
        assert_eq!(ev.workflow_job.id, 7);
        assert_eq!(ev.workflow_job.run_attempt, 2);
        assert_eq!(ev.workflow_job.labels, vec!["self-hosted", "lima-nix"]);
        assert_eq!(ev.repository.full_name, "o/r");
        assert_eq!(ev.repository.id, 99);
        // The VM name the worker will boot matches what live_vm_names_from_cur
        // derives for the synthetic cur/ record.
        assert_eq!(vm_name(ev.workflow_job.id), vm_name(7));
    }

    fn id(location: &str, digest: Option<&str>) -> ImageIdentity {
        ImageIdentity {
            location: location.to_string(),
            digest: digest.map(str::to_string),
        }
    }

    fn mk_runner(id: u64, name: String, status: &str, busy: bool) -> Runner {
        Runner {
            id,
            name,
            status: status.to_string(),
            busy,
        }
    }

    // ---- plan_vm_reaps (pure reap decision) ----

    #[test]
    fn plan_vm_reaps_none_live_reaps_nothing() {
        // The catastrophic regression: an unreadable cur/ (live = None) must reap
        // NOTHING, even with managed VMs present. Treating None as an empty live
        // set (the old unwrap_or_default bug) would orphan every VM here.
        let managed = vec![
            ManagedVm {
                name: vm_name(1),
                image: Some(id("/img/a.raw", None)),
            },
            ManagedVm {
                name: vm_name(2),
                image: None,
            },
        ];
        let current = id("/img/current.raw", None);
        assert!(
            plan_vm_reaps(&managed, None, Some(&current)).is_empty(),
            "None (unreadable cur/) must reap no VMs"
        );
    }

    #[test]
    fn plan_vm_reaps_orphans_vms_without_a_live_claim() {
        // A PRESENT-but-empty live set is the genuine "no claims" case: every
        // managed VM is an orphan. This is the behaviour None must NOT share.
        let live: HashMap<String, PathBuf> = HashMap::new();
        let managed = vec![ManagedVm {
            name: vm_name(1),
            image: None,
        }];
        assert_eq!(
            plan_vm_reaps(&managed, Some(&live), None),
            vec![VmReap::Orphan { name: vm_name(1) }]
        );
    }

    #[test]
    fn plan_vm_reaps_keeps_live_current_image_vm() {
        let path = PathBuf::from("/spool/cur/1.job");
        let live: HashMap<String, PathBuf> = [(vm_name(1), path)].into_iter().collect();
        let current = id("/img/current.raw", None);
        // Same image as current -> not stale -> kept.
        let managed = vec![ManagedVm {
            name: vm_name(1),
            image: Some(current.clone()),
        }];
        assert!(plan_vm_reaps(&managed, Some(&live), Some(&current)).is_empty());
    }

    #[test]
    fn plan_vm_reaps_reaps_live_but_stale_image_vm() {
        let path = PathBuf::from("/spool/cur/1.job");
        let live: HashMap<String, PathBuf> = [(vm_name(1), path.clone())].into_iter().collect();
        let current = id("/img/new.raw", None);
        let managed = vec![ManagedVm {
            name: vm_name(1),
            image: Some(id("/img/old.raw", None)),
        }];
        assert_eq!(
            plan_vm_reaps(&managed, Some(&live), Some(&current)),
            vec![VmReap::StaleImage {
                name: vm_name(1),
                cur_path: path,
                vm_location: "/img/old.raw".to_string(),
            }]
        );
    }

    #[test]
    fn plan_vm_reaps_keeps_claimed_vm_on_image_uncertainty() {
        let path = PathBuf::from("/spool/cur/1.job");
        let live: HashMap<String, PathBuf> = [(vm_name(1), path)].into_iter().collect();
        // Unreadable/unparsable booted image (None) -> never reaped.
        let managed = vec![ManagedVm {
            name: vm_name(1),
            image: None,
        }];
        let current = id("/img/new.raw", None);
        assert!(
            plan_vm_reaps(&managed, Some(&live), Some(&current)).is_empty(),
            "a claimed VM whose booted image we can't read is left alone"
        );
        // No current image to compare against -> never reaped either.
        let managed = vec![ManagedVm {
            name: vm_name(1),
            image: Some(id("/img/old.raw", None)),
        }];
        assert!(
            plan_vm_reaps(&managed, Some(&live), None).is_empty(),
            "with no current image there is nothing to call stale against"
        );
    }

    // ---- plan_runner_reaps (pure reap decision) ----

    #[test]
    fn plan_runner_reaps_none_live_reaps_nothing() {
        // Runner side of the catastrophic regression: unreadable cur/ (None)
        // must delete no runners, even idle unbacked ones.
        let runners = vec![mk_runner(1, vm_name(1), "offline", false)];
        assert!(
            plan_runner_reaps(&runners, None).is_empty(),
            "None (unreadable cur/) must delete no runners"
        );
    }

    #[test]
    fn plan_runner_reaps_deletes_unbacked_idle_or_offline() {
        let live: HashSet<String> = HashSet::new();
        let runners = vec![
            mk_runner(1, vm_name(1), "offline", false),
            mk_runner(2, vm_name(2), "online", false),
        ];
        let reaped: Vec<u64> = plan_runner_reaps(&runners, Some(&live))
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(
            reaped,
            vec![1, 2],
            "offline and idle-online are both orphans"
        );
    }

    #[test]
    fn plan_runner_reaps_keeps_backed_runner() {
        let live: HashSet<String> = [vm_name(1)].into_iter().collect();
        let runners = vec![mk_runner(1, vm_name(1), "offline", false)];
        assert!(
            plan_runner_reaps(&runners, Some(&live)).is_empty(),
            "a live-backed runner is never deleted"
        );
    }

    #[test]
    fn plan_runner_reaps_keeps_busy_online_runner() {
        let live: HashSet<String> = HashSet::new();
        // Unbacked but online+busy: executing a (possibly stolen) job; leave it.
        let runners = vec![mk_runner(1, vm_name(1), "online", true)];
        assert!(plan_runner_reaps(&runners, Some(&live)).is_empty());
    }

    #[test]
    fn plan_runner_reaps_ignores_unmanaged_names() {
        let live: HashSet<String> = HashSet::new();
        // Not our exact name shape -> never touched, even unbacked and idle.
        let runners = vec![mk_runner(1, "gha-runner-1".to_string(), "offline", false)];
        assert!(plan_runner_reaps(&runners, Some(&live)).is_empty());
    }

    // ---- plan_runner_reaps_from_cur (filesystem-backed; authoritative post-list read) ----

    /// Fresh tempdir with a `cur/` holding a `<id>.job` claim file for each id.
    /// The TempDir is returned so the caller keeps it alive (dropping it deletes
    /// the tree).
    async fn cur_with_claims(ids: &[u64]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let cur = dir.path().join("cur");
        tokio::fs::create_dir_all(&cur).await.unwrap();
        for id in ids {
            tokio::fs::write(cur.join(format!("{id}.job")), b"x")
                .await
                .unwrap();
        }
        (dir, cur)
    }

    /// The reported race: a runner whose claim is present in cur/ AT READ TIME is
    /// kept, even though it may have been minted after the top-of-sweep snapshot.
    /// Reading cur/ here — after list_runners — is what observes the claim; a
    /// stale snapshot from the top of the sweep would miss it and delete the
    /// still-booting runner's registration.
    #[tokio::test]
    async fn runner_reaps_from_cur_keeps_backed_runner() {
        let (_root, cur) = cur_with_claims(&[1]).await;
        let runners = vec![mk_runner(1, vm_name(1), "online", false)];
        let plan = plan_runner_reaps_from_cur(&cur, &runners, &HashSet::new()).await;
        assert!(
            plan.is_empty(),
            "a runner backed by a live cur/ claim must be kept"
        );
    }

    /// Faithful mid-sweep race regression via the `between` seam: cur/ is empty
    /// when the caller obtained `runners` (so the runner looks unbacked), then a
    /// mint lands — the hook writes the claim — before this function reads cur/.
    /// Because the read happens after the hook, the claim is observed and the
    /// runner is kept. This is exactly the window (list_runners returns → mint →
    /// cur/ read) the fix closes; a read taken before the mint deletes the
    /// still-booting runner.
    #[tokio::test]
    async fn runner_reaps_from_cur_honors_mint_after_list() {
        let (_root, cur) = cur_with_claims(&[]).await;
        let runners = vec![mk_runner(1, vm_name(1), "online", false)];
        let cur_h = cur.clone();
        let hook = async move {
            tokio::fs::write(cur_h.join("1.job"), b"x").await.unwrap();
        };
        let plan =
            plan_runner_reaps_from_cur_inner(&cur, &runners, &HashSet::new(), Some(hook)).await;
        assert!(
            plan.is_empty(),
            "a claim landing between list_runners and the cur/ read must protect the runner"
        );
    }

    /// Empty cur/ at read time → unbacked idle/offline runners are reaped, same
    /// as the pure planner. Confirms the fresh read doesn't accidentally protect
    /// genuinely orphaned runners.
    #[tokio::test]
    async fn runner_reaps_from_cur_reaps_unbacked() {
        let (_root, cur) = cur_with_claims(&[]).await;
        let runners = vec![
            mk_runner(1, vm_name(1), "offline", false),
            mk_runner(2, vm_name(2), "online", false),
        ];
        let mut ids: Vec<u64> = plan_runner_reaps_from_cur(&cur, &runners, &HashSet::new())
            .await
            .iter()
            .map(|r| r.id)
            .collect();
        ids.sort();
        assert_eq!(
            ids,
            vec![1, 2],
            "unbacked offline and idle-online runners are orphans"
        );
    }

    /// Unreadable cur/ (missing dir) → reap nothing, the same fail-safe every
    /// other reap decision uses on uncertainty. A transient FS error must never
    /// read as "no live claims" and delete every idle runner.
    #[tokio::test]
    async fn runner_reaps_from_cur_none_on_unreadable_reaps_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let runners = vec![mk_runner(1, vm_name(1), "offline", false)];
        let plan = plan_runner_reaps_from_cur(&missing, &runners, &HashSet::new()).await;
        assert!(plan.is_empty(), "unreadable cur/ must reap no runners");
    }

    /// A stale-image VM the sweep destroyed this tick is in `reaped_stale`; its
    /// now-offline runner must be reaped even though its claim is still in cur/
    /// (the finalize_error that would have removed it failed). Subtracting
    /// reaped_stale from the fresh read preserves the stale-image pass's
    /// this-sweep runner deletion.
    #[tokio::test]
    async fn runner_reaps_from_cur_reaped_stale_overrides_live_claim() {
        let (_root, cur) = cur_with_claims(&[1]).await;
        let runners = vec![mk_runner(1, vm_name(1), "offline", false)];
        let reaped: HashSet<String> = [vm_name(1)].into_iter().collect();
        let ids: Vec<u64> = plan_runner_reaps_from_cur(&cur, &runners, &reaped)
            .await
            .iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(
            ids,
            vec![1],
            "a reaped-stale VM's runner is deleted despite a lingering cur/ claim"
        );
    }

    // ---- plan_startup_claim_finalizes (pure startup finalize decision) ----

    /// Exhaustive over the per-claim decision space. A claim is always in
    /// `claims` (that's the set we iterate); orthogonally it can be present as a
    /// listed VM or not, and delete-failed or not — 4 combinations, each checked
    /// against the oracle. In production `delete_failed ⊆ present`, but the
    /// planner must be correct for any inputs, so present=false with
    /// delete_failed=true is exercised too: still skipped.
    #[test]
    fn plan_startup_claim_finalizes_single_claim_matrix() {
        let vm = vm_name(1);
        let path = PathBuf::from("/spool/cur/1.job");
        for present in [false, true] {
            for delete_failed in [false, true] {
                let claims: HashMap<String, PathBuf> =
                    [(vm.clone(), path.clone())].into_iter().collect();
                let present_set: HashSet<String> = if present {
                    [vm.clone()].into_iter().collect()
                } else {
                    HashSet::new()
                };
                let failed_set: HashSet<String> = if delete_failed {
                    [vm.clone()].into_iter().collect()
                } else {
                    HashSet::new()
                };

                let plan = plan_startup_claim_finalizes(&claims, &present_set, &failed_set);

                if delete_failed {
                    assert!(
                        plan.is_empty(),
                        "a claim whose VM delete failed must be left for the 6h expiry (present={present})"
                    );
                } else {
                    let want_reason = if present {
                        StartupFinalizeReason::ReapedVm
                    } else {
                        StartupFinalizeReason::NoVm
                    };
                    assert_eq!(
                        plan,
                        vec![StartupClaimFinalize {
                            cur_path: path.clone(),
                            reason: want_reason,
                        }],
                        "present={present} delete_failed={delete_failed}"
                    );
                }
            }
        }
    }

    /// Regression for the reported bug: a claim whose VM was never created
    /// (crash between try_claim and `limactl start`) is absent from `present`
    /// but must still be finalized — classified NoVm — so the reconciler
    /// re-mints within a tick instead of after the 6h stale-claim expiry.
    #[test]
    fn plan_startup_claim_finalizes_vm_less_claim_is_no_vm() {
        let vm = vm_name(7);
        let path = PathBuf::from("/spool/cur/7.job");
        let claims: HashMap<String, PathBuf> = [(vm, path.clone())].into_iter().collect();
        let plan = plan_startup_claim_finalizes(&claims, &HashSet::new(), &HashSet::new());
        assert_eq!(
            plan,
            vec![StartupClaimFinalize {
                cur_path: path,
                reason: StartupFinalizeReason::NoVm,
            }],
        );
    }

    /// Unreadable cur/ surfaces as an empty claims map (see the caller's
    /// `unwrap_or_else`); the planner must then finalize nothing, so no claim is
    /// touched and the 6h expiry stays the (unchanged) backstop.
    #[test]
    fn plan_startup_claim_finalizes_empty_claims_is_empty() {
        let present: HashSet<String> = [vm_name(1)].into_iter().collect();
        let delete_failed: HashSet<String> = HashSet::new();
        assert!(plan_startup_claim_finalizes(&HashMap::new(), &present, &delete_failed).is_empty());
    }

    /// Multi-claim oracle: the plan finalizes exactly `claims.keys() \
    /// delete_failed`, each with reason `ReapedVm` iff its VM is present. Built
    /// from a mixed fixture covering all three fates at once (deleted VM,
    /// VM-less, delete-failed), compared order-free since HashMap iteration order
    /// is unspecified.
    #[test]
    fn plan_startup_claim_finalizes_oracle_over_mixed_fixture() {
        let path = |id: u64| PathBuf::from(format!("/spool/cur/{id}.job"));
        // ids 1..=6, one fate each:
        //   1,2 -> present & deleted OK      => finalized ReapedVm
        //   3,4 -> absent (no VM)            => finalized NoVm
        //   5,6 -> present but delete failed => skipped
        let claims: HashMap<String, PathBuf> = (1..=6).map(|id| (vm_name(id), path(id))).collect();
        let present: HashSet<String> = [1, 2, 5, 6].into_iter().map(vm_name).collect();
        let delete_failed: HashSet<String> = [5, 6].into_iter().map(vm_name).collect();

        let got: HashMap<PathBuf, StartupFinalizeReason> =
            plan_startup_claim_finalizes(&claims, &present, &delete_failed)
                .into_iter()
                .map(|f| (f.cur_path, f.reason))
                .collect();
        let want: HashMap<PathBuf, StartupFinalizeReason> = [
            (path(1), StartupFinalizeReason::ReapedVm),
            (path(2), StartupFinalizeReason::ReapedVm),
            (path(3), StartupFinalizeReason::NoVm),
            (path(4), StartupFinalizeReason::NoVm),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            got, want,
            "finalize exactly claims\\delete_failed, ReapedVm iff present"
        );
    }

    // ---- live_vm_map_from_cur (filesystem-backed) ----

    #[tokio::test]
    async fn live_vm_map_from_cur_maps_job_files_and_skips_non_claims() {
        let dir = tempfile::tempdir().unwrap();
        let cur = dir.path().join("cur");
        tokio::fs::create_dir_all(&cur).await.unwrap();
        tokio::fs::write(cur.join("10.job"), b"x").await.unwrap();
        tokio::fs::write(cur.join("256.job"), b"x").await.unwrap();
        // Non-claim entries are ignored, not errors: wrong suffix, non-numeric
        // stem, and a subdir whose name DOES parse as a claim (filtered by the
        // is_file() check, not the name).
        tokio::fs::write(cur.join("notes.txt"), b"x").await.unwrap();
        tokio::fs::write(cur.join("bad.job"), b"x").await.unwrap();
        tokio::fs::create_dir_all(cur.join("999.job"))
            .await
            .unwrap();

        let map = live_vm_map_from_cur(&cur).await.unwrap();
        let mut names: Vec<String> = map.keys().cloned().collect();
        names.sort();
        let mut want = vec![vm_name(10), vm_name(256)];
        want.sort();
        assert_eq!(names, want, "only regular `<id>.job` files are claims");
        assert_eq!(map.get(&vm_name(10)), Some(&cur.join("10.job")));
    }

    #[tokio::test]
    async fn live_vm_map_from_cur_errs_on_unreadable_dir() {
        // The invariant sweep_inner's fail-safe relies on: an unreadable cur/
        // surfaces as Err, NEVER as an empty (Ok) map. sweep_inner turns that Err
        // into "reap nothing this tick" rather than "no live claims".
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert!(live_vm_map_from_cur(&missing).await.is_err());
    }

    #[test]
    fn parse_image_identity_handles_template_and_instance_shapes() {
        // List-item form Lima emits in both the prebuilt template and the
        // per-instance lima.yaml, with a file:// URL, arch, and digest. The
        // identity keeps the FULL path (not just the basename) and the digest.
        let yaml = "vmType: vz\nimages:\n  - location: \"file:///Users/ci/.local/share/gha-images/gha-guest-nixos-20260529-224941.raw\"\n    arch: aarch64\n    digest: \"sha256:a8575a8fe004f99732b215eab474b7dfe15ad3f4683dfdc4e8ed9103b61ed13c\"\n";
        assert_eq!(
            parse_image_identity(yaml),
            Some(id(
                "/Users/ci/.local/share/gha-images/gha-guest-nixos-20260529-224941.raw",
                Some("sha256:a8575a8fe004f99732b215eab474b7dfe15ad3f4683dfdc4e8ed9103b61ed13c")
            ))
        );
        // https:// URL (the base runner-aarch64.yaml form), with digest.
        let yaml = "images:\n  - location: \"https://cloud-images.ubuntu.com/releases/24.04/release-20260518/ubuntu-24.04-server-cloudimg-arm64.img\"\n    arch: aarch64\n    digest: \"sha256:6a61b967ba4a27dd1966f835a67643073ed55c2860ce3dc1cb0517282e6b8bec\"\n";
        assert_eq!(
            parse_image_identity(yaml),
            Some(id(
                "cloud-images.ubuntu.com/releases/24.04/release-20260518/ubuntu-24.04-server-cloudimg-arm64.img",
                Some("sha256:6a61b967ba4a27dd1966f835a67643073ed55c2860ce3dc1cb0517282e6b8bec")
            ))
        );
        // Single-quoted value, bare absolute path, no digest. The location
        // must live under `images:` to be classified.
        let yaml = "images:\n  - location: '/var/img/foo-20260101.qcow2'\n";
        assert_eq!(
            parse_image_identity(yaml),
            Some(id("/var/img/foo-20260101.qcow2", None))
        );
        // Unquoted value, no digest.
        let yaml = "images:\n  - location: file:///tmp/bar.raw\n";
        assert_eq!(parse_image_identity(yaml), Some(id("/tmp/bar.raw", None)));
    }

    #[test]
    fn parse_image_identity_takes_first_block_digest_only() {
        // With two image entries, the identity is the FIRST block's location
        // and only that block's digest — never the second image's digest.
        let yaml = "images:\n  - location: file:///tmp/a.raw\n    arch: aarch64\n    digest: \"sha256:aaaa\"\n  - location: file:///tmp/b.raw\n    digest: \"sha256:bbbb\"\n";
        assert_eq!(
            parse_image_identity(yaml),
            Some(id("/tmp/a.raw", Some("sha256:aaaa")))
        );
        // First image has no digest, second does: we must not borrow the
        // second image's digest for the first.
        let yaml = "images:\n  - location: file:///tmp/a.raw\n  - location: file:///tmp/b.raw\n    digest: \"sha256:bbbb\"\n";
        assert_eq!(parse_image_identity(yaml), Some(id("/tmp/a.raw", None)));
    }

    #[test]
    fn parse_image_identity_strips_inline_comments() {
        // Quoted location with a trailing `# pinned` comment, as a template
        // might carry. The realized lima.yaml has no comment, so the identity
        // must reduce to the same clean location (else a healthy VM looks
        // stale and is reaped). The digest comment is stripped too.
        let yaml = "images:\n  - location: \"file:///img.raw\" # pinned\n    digest: \"sha256:abc\" # frozen\n";
        assert_eq!(
            parse_image_identity(yaml),
            Some(id("/img.raw", Some("sha256:abc")))
        );
        // Unquoted bare location with a trailing comment.
        let yaml = "images:\n  - location: /img.raw # note\n";
        assert_eq!(parse_image_identity(yaml), Some(id("/img.raw", None)));
        // A `#` INSIDE a quoted value is part of the value, not a comment.
        let yaml = "images:\n  - location: \"file:///img#frag.raw\"\n";
        assert_eq!(parse_image_identity(yaml), Some(id("/img#frag.raw", None)));
        // A `#` inside an unquoted scalar (no preceding whitespace) is literal,
        // not a comment.
        let yaml = "images:\n  - location: /img#frag.raw\n";
        assert_eq!(parse_image_identity(yaml), Some(id("/img#frag.raw", None)));
    }

    #[test]
    fn strip_inline_comment_honors_quoting() {
        assert_eq!(strip_inline_comment("\"a#b\" # c"), "\"a#b\"");
        assert_eq!(strip_inline_comment(" /p/q # tail"), " /p/q");
        assert_eq!(strip_inline_comment("'a # b'"), "'a # b'");
        // `#` glued to a token with no leading space is literal.
        assert_eq!(strip_inline_comment("a#b"), "a#b");
        // Comment immediately after a closing quote (no space) still strips.
        assert_eq!(strip_inline_comment("\"x\"#c"), "\"x\"");
        // No comment at all is returned unchanged.
        assert_eq!(strip_inline_comment("plain"), "plain");
    }

    #[test]
    fn parse_image_identity_none_when_absent() {
        assert!(parse_image_identity("vmType: vz\ncpus: 4\n").is_none());
        assert!(parse_image_identity("").is_none());
        // A `location:` with an empty value is not a usable image.
        assert!(parse_image_identity("  - location: \"\"\n").is_none());
        // Must not match a key that merely contains "location" as a substring.
        assert!(parse_image_identity("relocation: yes\n").is_none());
        // A bare `location:` outside any `images:` block must be ignored: with
        // no `images:` key at all, there is nothing to classify.
        assert!(parse_image_identity("  - location: file:///tmp/mount.img\n").is_none());
    }

    #[test]
    fn parse_image_identity_ignores_location_before_images() {
        // Regression (Codex P2): a valid Lima YAML can carry a `location:`
        // BEFORE the top-level `images:` block — e.g. a `mounts:` entry. The
        // parser must skip past it and return the IMAGE's location/digest, not
        // the earlier mount location.
        let yaml = "mounts:\n  - location: \"/Users/ci/work\"\n    writable: true\nimages:\n  - location: \"file:///Users/ci/.local/share/gha-images/gha-guest-nixos-20260529-224941.raw\"\n    arch: aarch64\n    digest: \"sha256:imageimage\"\n";
        assert_eq!(
            parse_image_identity(yaml),
            Some(id(
                "/Users/ci/.local/share/gha-images/gha-guest-nixos-20260529-224941.raw",
                Some("sha256:imageimage")
            )),
            "must take the images: location, not the earlier mounts: one"
        );

        // Lima's default `containerd.archives:` carries a `location:` (the
        // nerdctl tarball URL) that, in a real merged lima.yaml, can appear
        // before `images:`. Must not be mistaken for the guest image.
        let yaml = "containerd:\n  system: false\n  archives:\n    - location: https://github.com/containerd/nerdctl/releases/download/v1.0.0/nerdctl-full-1.0.0-linux-arm64.tar.gz\n      arch: aarch64\n      digest: sha256:nerdctlnerdctl\nimages:\n  - location: file:///tmp/realguest.raw\n    digest: \"sha256:realguest\"\n";
        assert_eq!(
            parse_image_identity(yaml),
            Some(id("/tmp/realguest.raw", Some("sha256:realguest"))),
            "must skip containerd.archives location and take the images: one"
        );

        // The mount's digest-less form must not leak the mount location even
        // when the image block itself carries no digest.
        let yaml =
            "mounts:\n  - location: /Users/ci/work\nimages:\n  - location: file:///tmp/guest.raw\n";
        assert_eq!(parse_image_identity(yaml), Some(id("/tmp/guest.raw", None)));
    }

    #[test]
    fn is_stale_image_compares_full_location() {
        // Same location -> not stale (the common steady-state case).
        assert!(!is_stale_image(
            &id(
                "/Users/ci/.local/share/gha-images/gha-guest-nixos-20260529-224941.raw",
                None
            ),
            &id(
                "/Users/ci/.local/share/gha-images/gha-guest-nixos-20260529-224941.raw",
                None
            ),
        ));
        // Different location -> stale (operator rebuilt + restarted; NixOS
        // images are uniquely timestamped paths).
        assert!(is_stale_image(
            &id(
                "/Users/ci/.local/share/gha-images/gha-guest-nixos-20260101-000000.raw",
                None
            ),
            &id(
                "/Users/ci/.local/share/gha-images/gha-guest-nixos-20260529-224941.raw",
                None
            ),
        ));
    }

    #[test]
    fn is_stale_image_same_basename_different_dir_is_stale() {
        // Regression for the Ubuntu interim template: the filename is constant
        // (`ubuntu-24.04-server-cloudimg-arm64.img`) but the `release-YYYYMMDD`
        // directory changes per upstream rebuild. Basename-only comparison
        // (the old bug) would call these IDENTICAL and never reap the
        // superseded VM; full-location comparison correctly calls them STALE.
        let old = id(
            "cloud-images.ubuntu.com/releases/24.04/release-20260101/ubuntu-24.04-server-cloudimg-arm64.img",
            None,
        );
        let new = id(
            "cloud-images.ubuntu.com/releases/24.04/release-20260518/ubuntu-24.04-server-cloudimg-arm64.img",
            None,
        );
        assert!(
            is_stale_image(&old, &new),
            "same filename, different release dir must be STALE"
        );
        // Identical locations (same dir, same filename) are the same image.
        assert!(!is_stale_image(&new, &new));
    }

    #[test]
    fn is_stale_image_digest_distinguishes_same_path_rebuild() {
        let path = "/Users/ci/.local/share/gha-images/runner-aarch64-prebuilt.qcow2";
        // Same path, differing digests (a same-path rebuild) -> stale.
        assert!(is_stale_image(
            &id(path, Some("sha256:oldoldold")),
            &id(path, Some("sha256:newnewnew")),
        ));
        // Same path, same digest -> not stale.
        assert!(!is_stale_image(
            &id(path, Some("sha256:samesame")),
            &id(path, Some("sha256:samesame")),
        ));
        // Same path, digest missing on one side -> fall back to location only
        // (not stale), so a digest-less Lima never mass-reaps matching VMs.
        assert!(!is_stale_image(
            &id(path, None),
            &id(path, Some("sha256:newnewnew")),
        ));
        assert!(!is_stale_image(
            &id(path, Some("sha256:oldoldold")),
            &id(path, None),
        ));
    }

    #[test]
    fn is_managed_vm_name_rejects_other_prefix_users() {
        // Common shapes we must not flatten: hand-named, label-suffixed,
        // uppercase hex, too-short, too-long, non-hex characters.
        assert!(!is_managed_vm_name("gha"));
        assert!(!is_managed_vm_name("gha-"));
        assert!(!is_managed_vm_name("gha-test"));
        assert!(!is_managed_vm_name("gha-runner-1"));
        assert!(!is_managed_vm_name("gha-DEADBEEFCAFEBABE"));
        assert!(!is_managed_vm_name("gha-0000000000000001-suffix"));
        assert!(!is_managed_vm_name("gha-0000000000000")); // 15
        assert!(!is_managed_vm_name("gha-00000000000000000")); // 17
        assert!(!is_managed_vm_name("gha-zzzzzzzzzzzzzzzz"));
        assert!(!is_managed_vm_name("other-0000000000000001"));
    }

    /// A stale cur/ entry expired into error/ must carry an expiry-time mtime,
    /// not the preserved claim-time one — otherwise a long-claimed job expired
    /// now would be filtered out of the control UI's recent-completions window.
    #[tokio::test]
    async fn expire_stale_cur_stamps_archive_mtime_to_now() {
        let dir = tempfile::tempdir().unwrap();
        let cur = dir.path().join("cur");
        let err = dir.path().join("error");
        tokio::fs::create_dir_all(&cur).await.unwrap();
        tokio::fs::create_dir_all(&err).await.unwrap();
        let job = cur.join("60.job");
        tokio::fs::write(&job, b"x").await.unwrap();
        // Backdate well past the max age so it's expired.
        let backdate = std::time::SystemTime::now() - std::time::Duration::from_secs(10_000);
        std::fs::File::open(&job)
            .unwrap()
            .set_modified(backdate)
            .unwrap();

        let before = std::time::SystemTime::now();
        expire_stale_cur(&cur, &err, 3600).await.unwrap();

        let archived = err.join("60.job");
        assert!(
            archived.exists(),
            "stale entry should be archived to error/"
        );
        let m = std::fs::metadata(&archived).unwrap().modified().unwrap();
        assert!(
            m >= before
                .checked_sub(std::time::Duration::from_secs(2))
                .unwrap(),
            "expired archive mtime must be ~expiry time, not the backdated claim time; got {m:?}"
        );
    }

    // ---- prune_old_archives (filesystem-backed) ----

    const TWO_DAYS: u64 = 2 * 24 * 60 * 60;

    /// Backdate a file's mtime by `age_secs`, matching how the other fs tests
    /// here simulate aged entries (std `File::set_modified`, no extra crate).
    fn backdate(path: &Path, age_secs: u64) {
        let t = std::time::SystemTime::now() - std::time::Duration::from_secs(age_secs);
        std::fs::File::open(path).unwrap().set_modified(t).unwrap();
    }

    /// Fresh tempdir with `done/` + `error/`. The TempDir is returned so the
    /// caller keeps it alive (dropping it deletes the tree).
    async fn archive_dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let done = dir.path().join("done");
        let error = dir.path().join("error");
        tokio::fs::create_dir_all(&done).await.unwrap();
        tokio::fs::create_dir_all(&error).await.unwrap();
        (dir, done, error)
    }

    #[tokio::test]
    async fn prune_removes_old_and_keeps_fresh() {
        let (_root, done, error) = archive_dirs().await;
        let old_done = done.join("1.job");
        let old_err = error.join("2.job");
        let fresh = done.join("3.job");
        for p in [&old_done, &old_err, &fresh] {
            tokio::fs::write(p, b"{}").await.unwrap();
        }
        backdate(&old_done, TWO_DAYS + 3600);
        backdate(&old_err, TWO_DAYS + 3600);
        // `fresh` keeps its ~now mtime.

        prune_old_archives(&done, &error, TWO_DAYS).await.unwrap();

        assert!(!old_done.exists(), "old done/ entry should be pruned");
        assert!(!old_err.exists(), "old error/ entry should be pruned");
        assert!(fresh.exists(), "within-window entry should be kept");
    }

    #[tokio::test]
    async fn prune_removes_error_sidecars_and_baks() {
        let (_root, done, error) = archive_dirs().await;
        let job = error.join("7.job");
        let sidecar = error.join("7.job.err");
        let bak = error.join("7.job.1700000000000.bak");
        for p in [&job, &sidecar, &bak] {
            tokio::fs::write(p, b"x").await.unwrap();
            backdate(p, TWO_DAYS + 3600);
        }

        prune_old_archives(&done, &error, TWO_DAYS).await.unwrap();

        assert!(!job.exists(), ".job pruned by its own mtime");
        assert!(
            !sidecar.exists(),
            ".job.err sidecar pruned by its own mtime"
        );
        assert!(!bak.exists(), ".bak pruned by its own mtime");
    }

    #[tokio::test]
    async fn prune_disabled_when_retention_zero() {
        let (_root, done, error) = archive_dirs().await;
        let ancient = done.join("1.job");
        tokio::fs::write(&ancient, b"{}").await.unwrap();
        backdate(&ancient, 3650 * 24 * 60 * 60);

        prune_old_archives(&done, &error, 0).await.unwrap();

        assert!(
            ancient.exists(),
            "retention_secs == 0 must disable pruning entirely"
        );
    }

    #[tokio::test]
    async fn prune_tolerates_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        // Neither archive dir is created.
        let done = dir.path().join("done");
        let error = dir.path().join("error");
        // Must not panic or return Err.
        prune_old_archives(&done, &error, TWO_DAYS).await.unwrap();
    }

    #[tokio::test]
    async fn prune_skips_non_regular() {
        let (_root, done, error) = archive_dirs().await;
        // A subdir in error/ must be left alone even if old. `is_file()` gates
        // before the age check, so it's never a candidate; backdating it (best
        // effort — opening a dir for set_modified isn't portable) just makes the
        // "old" case explicit.
        let subdir = error.join("old.subdir");
        tokio::fs::create_dir_all(&subdir).await.unwrap();
        let t = std::time::SystemTime::now() - std::time::Duration::from_secs(TWO_DAYS + 3600);
        let _ = std::fs::File::open(&subdir).and_then(|f| f.set_modified(t));

        prune_old_archives(&done, &error, TWO_DAYS).await.unwrap();

        assert!(subdir.exists(), "non-regular entries must be skipped");
    }

    // ---- prune_serial_logs (filesystem-backed) ----

    #[tokio::test]
    async fn prune_serial_logs_removes_old_keeps_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        tokio::fs::create_dir_all(&logs).await.unwrap();
        let old = logs.join("gha-0000000000000001.serial.log");
        let fresh = logs.join("gha-0000000000000002.serial.log");
        for p in [&old, &fresh] {
            tokio::fs::write(p, b"console").await.unwrap();
        }
        backdate(&old, TWO_DAYS + 3600);
        // `fresh` keeps its ~now mtime; window is 1 day so `old` (2d+) is past it.

        prune_serial_logs(&logs, 24 * 60 * 60).await;

        assert!(!old.exists(), "old serial log should be pruned");
        assert!(fresh.exists(), "within-window serial log should be kept");
    }

    #[tokio::test]
    async fn prune_serial_logs_disabled_when_zero() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        tokio::fs::create_dir_all(&logs).await.unwrap();
        let ancient = logs.join("gha-0000000000000003.serial.log");
        tokio::fs::write(&ancient, b"x").await.unwrap();
        backdate(&ancient, 3650 * 24 * 60 * 60);

        prune_serial_logs(&logs, 0).await;

        assert!(
            ancient.exists(),
            "retention_secs == 0 must disable serial-log pruning entirely"
        );
    }

    #[tokio::test]
    async fn prune_serial_logs_tolerates_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        // logs/ is never created; must not panic.
        prune_serial_logs(&dir.path().join("logs"), TWO_DAYS).await;
    }

    #[tokio::test]
    async fn prune_serial_logs_skips_unrelated_and_non_regular() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        tokio::fs::create_dir_all(&logs).await.unwrap();
        // An old file without the .serial.log suffix must be left alone.
        let unrelated = logs.join("notes.txt");
        tokio::fs::write(&unrelated, b"keep me").await.unwrap();
        backdate(&unrelated, TWO_DAYS + 3600);
        // An old subdir that happens to end in .serial.log must be left alone
        // (is_file() gates before the age check).
        let subdir = logs.join("weird.serial.log");
        tokio::fs::create_dir_all(&subdir).await.unwrap();

        prune_serial_logs(&logs, TWO_DAYS).await;

        assert!(
            unrelated.exists(),
            "non-.serial.log entries must be skipped"
        );
        assert!(subdir.exists(), "non-regular entries must be skipped");
    }

    #[tokio::test]
    async fn prune_keeps_marker_rearchived_during_scan() {
        let (_root, done, _error) = archive_dirs().await;
        // An expired canonical marker — e.g. a stolen completion archived earlier.
        let marker = done.join("5.job");
        tokio::fs::write(&marker, b"old").await.unwrap();
        backdate(&marker, TWO_DAYS + 3600);

        // The hook stands in for a concurrent finalize_* re-archiving the same id
        // in the race window (expired decision made, lock not yet held): move the
        // expired marker aside to a .bak and install a fresh-mtime marker, exactly
        // as archive() + stamp_mtime_now do. The locked recheck must then observe
        // it as fresh and refuse to delete it. Without the recheck (deleting by
        // the stale iteration stat) this would unlink the just-finished job's
        // marker, dropping its replay guard and completion record.
        let marker_h = marker.clone();
        let done_h = done.clone();
        let hook = async move {
            let bak = done_h.join("5.job.1700000000000.bak");
            tokio::fs::rename(&marker_h, &bak).await.unwrap();
            tokio::fs::write(&marker_h, b"fresh").await.unwrap();
        };

        prune_archive_dir_inner(&done, TWO_DAYS, Some(hook)).await;

        assert!(
            marker.exists(),
            "a marker re-archived during the scan must survive the prune"
        );
        assert_eq!(
            tokio::fs::read(&marker).await.unwrap(),
            b"fresh",
            "the surviving marker must be the freshly re-archived one"
        );
    }
}
