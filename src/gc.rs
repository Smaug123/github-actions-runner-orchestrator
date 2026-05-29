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
use tracing::{error, info, warn};

use crate::config::Config;
use crate::github::event::{Repository, WorkflowJob, WorkflowJobInfo};
use crate::github::jit::{GhClient, JobStatus};
use crate::lima::Lima;
use crate::runner::vm_name;
use crate::spool::{parse_spool_filename, sanitize_for_log, Spool};
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
fn is_managed_vm_name(name: &str) -> bool {
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

/// Startup reap: stop + delete EVERY pre-existing managed (`gha-<16hex>`) VM
/// and finalize each one's cur/ claim to error/.
///
/// A freshly-started consumer cannot re-adopt an in-flight job's `limactl
/// shell` session (the supervisor that owned it is gone), so every
/// pre-existing claim is unmanageable: the VM would linger until
/// JOB_MAX_RUNTIME_SECS while its still-online runner steals freshly-queued
/// jobs. This is safe under the documented pause -> drain -> restart
/// procedure: after a clean drain there are no managed VMs, so this is a
/// no-op; after a crash it cleans up the wreckage.
///
/// MUST run before the supervisor begins claiming/launching jobs, so it can
/// never reap a VM the new consumer just started (it deletes by `gha-<16hex>`
/// shape, and a just-launched job would match). The runner-orphan branch of
/// the periodic sweep deletes the now-offline GitHub runners whose claims we
/// finalize here.
pub async fn reap_all_managed_vms_at_startup(config: &Config, lima: &Lima) {
    let cur_dir = config.spool_dir.join("cur");
    let live_map = live_vm_map_from_cur(&cur_dir).await.unwrap_or_default();
    let spool = Spool::new(config.spool_dir.clone());

    let instances = match lima.list_instances().await {
        Ok(i) => i,
        Err(e) => {
            warn!(error = %e, "startup reap: limactl list failed; skipping");
            return;
        }
    };
    for (name, _dir) in instances {
        if !is_managed_vm_name(&name) {
            continue;
        }
        info!(vm = %name, "startup: reaping pre-existing managed VM (fresh consumer cannot re-adopt)");
        if let Err(e) = lima.stop(&name).await {
            warn!(vm = %name, error = %e, "startup reap: stop");
        }
        // Only archive the claim once the VM is *actually* gone. A failed delete
        // (limactl error/timeout, VM still present) means the VM — and its
        // possibly-live runner — may still be up, so we must NOT finalize its
        // cur/ claim to error/: doing so would make the runner-orphan branch
        // treat a live runner as unbacked.
        //
        // Unlike the stale-image SWEEP path (which re-runs every
        // GC_INTERVAL_SECS and naturally re-attempts a still-present VM), this
        // startup reap is one-shot. Worse, a pre-existing orphan booted from the
        // CURRENT image that we fail to delete here would never be re-reaped by
        // the periodic sweep — it's current-image with a live cur/ claim, so it
        // looks like a healthy in-flight job — and would linger until the 6h
        // JOB_MAX_RUNTIME_SECS stale-claim expiry. So give the delete a bounded
        // retry with a short fixed backoff before giving up.
        if let Err(e) = delete_with_retry(lima, &name).await {
            error!(
                vm = %sanitize_for_log(&name),
                error = %e,
                "startup reap: delete failed after retries; leaving cur/ claim intact (will only be cleaned by the 6h stale-claim expiry)"
            );
            continue;
        }
        if let Some(cur_path) = live_map.get(&name) {
            if let Err(e) = spool
                .finalize_error(
                    cur_path,
                    "startup: reaped orphan VM (fresh consumer cannot re-adopt)",
                )
                .await
            {
                warn!(vm = %name, error = %e, "startup reap: finalize_error");
            }
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

async fn sweep_inner(config: &Config, gh: &GhClient, lima: &Lima) -> anyhow::Result<()> {
    let cur_dir = config.spool_dir.join("cur");

    expire_stale_cur(
        &cur_dir,
        &config.spool_dir.join("error"),
        config.job_max_runtime_secs,
    )
    .await?;

    // vm_name -> cur/ path for every live claim. The orphan branch consults
    // the key set; the stale-image branch needs the path so it can finalize a
    // reaped VM's claim to error/.
    let live_map = live_vm_map_from_cur(&cur_dir).await.unwrap_or_default();
    // Mutable: the stale-image reap below removes each VM it destroys so the
    // runner-cleanup loop treats the now-offline runner as unbacked and deletes
    // it in this same sweep (otherwise GitHub could hand the dead runner queued
    // work for a whole extra sweep).
    let mut live: HashSet<String> = live_map.keys().cloned().collect();

    // The image the consumer's current LIMA_TEMPLATE boots. None when we can't
    // read/parse the staged template; in that case we skip stale-image reaping
    // entirely (we have nothing to compare against) rather than reap blindly.
    let current_image = current_template_image(&config.lima_template).await;

    let spool = Spool::new(config.spool_dir.clone());

    match lima.list_instances().await {
        Ok(instances) => {
            for (name, dir) in instances {
                if !is_managed_vm_name(&name) {
                    continue;
                }
                // 1. No live claim at all -> classic orphan; stop + delete.
                if !live.contains(&name) {
                    info!(vm = %name, "gc: orphan Lima VM, deleting");
                    if let Err(e) = lima.stop(&name).await {
                        warn!(vm = %name, error = %e, "stop");
                    }
                    if let Err(e) = lima.delete(&name).await {
                        warn!(vm = %name, error = %e, "delete");
                    }
                    continue;
                }
                // 2. Claimed and live, but possibly booted from a superseded
                //    image. Reap iff we can positively classify it as stale;
                //    skip on any uncertainty (no current image, unreadable
                //    lima.yaml, unparsable location).
                let Some(current) = current_image.as_ref() else {
                    continue;
                };
                let Some(vm_image) = vm_booted_image(dir.as_deref()).await else {
                    warn!(vm = %name, "gc: cannot determine booted image; skipping stale-image check");
                    continue;
                };
                if !is_stale_image(&vm_image, current) {
                    continue;
                }
                info!(
                    vm = %name,
                    image = %sanitize_for_log(&vm_image.location),
                    current = %sanitize_for_log(&current.location),
                    "gc: reaping stale-image VM (still claimed) and finalizing its claim to error/"
                );
                if let Err(e) = lima.stop(&name).await {
                    warn!(vm = %name, error = %e, "stop");
                }
                // Only tear down the claim/live state once the VM is *actually*
                // gone. A failed delete (limactl error/timeout) means the VM —
                // and its still-online, possibly-busy runner — may still be up.
                // Archiving the claim and dropping it from `live` here would make
                // the runner-orphan branch below treat that live runner as
                // unbacked and delete it. So on delete failure we leave both the
                // cur/ claim and the live entry intact and let the next sweep
                // retry the reap.
                if let Err(e) = lima.delete(&name).await {
                    warn!(vm = %sanitize_for_log(&name), error = %e, "gc: delete failed for stale-image VM; leaving claim and live entry for next sweep");
                    continue;
                }
                // Finalize the live claim to error/ so the runner-orphan
                // branch below deletes the now-offline GitHub runner (and so
                // expire_stale_cur won't keep aging a claim for a VM we just
                // destroyed).
                if let Some(cur_path) = live_map.get(&name) {
                    let reason = format!(
                        "gc: reaped stale-image VM ({} != {})",
                        sanitize_for_log(&vm_image.location),
                        sanitize_for_log(&current.location)
                    );
                    if let Err(e) = spool.finalize_error(cur_path, &reason).await {
                        warn!(vm = %name, error = %e, "gc: finalize_error for reaped stale-image VM");
                    }
                }
                // Drop this VM from the live set: the claim is no longer in cur/
                // and the VM is gone, so the runner-cleanup loop below must see
                // the runner as unbacked and delete it in THIS sweep — before
                // GitHub can assign the dead runner freshly-queued work.
                live.remove(&name);
            }
        }
        Err(e) => warn!(error = %e, "gc: limactl list failed"),
    }

    for repo_full in &config.allowed_repos {
        let Some((owner, repo)) = repo_full.split_once('/') else {
            warn!(repo = %sanitize_for_log(repo_full), "gc: allowed repo is not owner/name; skipping");
            continue;
        };
        match gh.list_runners(owner, repo, VM_NAME_PREFIX).await {
            Ok(runners) => {
                for r in runners {
                    // Restrict deletion to the exact shape this factory mints.
                    // The repo may host runners from other tooling that happens
                    // to share the gha- prefix; we must never delete those.
                    if !is_managed_vm_name(&r.name) {
                        continue;
                    }
                    let backed_by_vm = live.contains(&r.name);
                    let dead = r.status == "offline" || !r.busy;
                    if !backed_by_vm && dead {
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
    let live = live_vm_names_from_cur(&cur_dir).await.unwrap_or_default();

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
            if let Err(e) = tokio::fs::rename(&from, &to).await {
                warn!(error = %e, "rename stale cur/ -> error/");
            }
        }
    }
    Ok(())
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
    let mut rd = tokio::fs::read_dir(cur_dir).await?;
    while let Some(ent) = rd.next_entry().await? {
        let Ok(ft) = ent.file_type().await else {
            continue;
        };
        if !ft.is_file() {
            continue;
        }
        let Some(s) = ent.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if let Some(id) = parse_spool_filename(&s) {
            out.insert(vm_name(id), ent.path());
        }
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
}
