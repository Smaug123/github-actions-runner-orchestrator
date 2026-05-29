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
//   * any GH runner with our `gha-` prefix that isn't backed by a live cur/
//     file and is offline (or simply not busy) is DELETEd via API.
//
// `live` is built by reading each cur/ file's body and computing the same
// vm_name the supervisor would: signed (repo, workflow_job.id) → SHA-256.
// We never derive a vm_name from envelope/header data; using only signed
// fields means a replay produces the same name we already know about.
//
// SINGLETON DEPLOYMENT REQUIRED PER (account, set of allowed repos).
//
// The runner branch below treats *this* process's cur/ as the single
// source of truth for what `gha-<16hex>` runners should exist on each
// allowed repo. Two consumers covering the same repo with separate
// SPOOL_DIRs would each see the other's freshly-minted (online, not yet
// busy) runners as orphans and delete them in the window between mint
// and job pickup — a self-inflicted denial of service.
//
// Safe configurations:
//   * one process per repo (or per disjoint set of repos);
//   * multiple processes sharing the same SPOOL_DIR (and so the same
//     cur/), because every consumer sees every claim;
//   * separate consumers covering *disjoint* repo sets.
//
// Unsafe: separate consumers covering the same repo with separate
// SPOOL_DIRs. There's no in-band check for this — the repo runner list
// doesn't carry "which consumer minted me" — so the launchd plist /
// deployment harness is the right place to enforce singleton. A future
// option is namespacing runner names per consumer (e.g.
// `gha-<consumer-id>-<jobid>`) and restricting GC to that namespace.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::config::Config;
use crate::github::event::{Repository, WorkflowJob, WorkflowJobInfo};
use crate::github::jit::{GhClient, JobStatus};
use crate::lima::Lima;
use crate::runner::vm_name;
use crate::spool::{parse_spool_filename, sanitize_for_log, Spool};
use crate::supervisor::{classify_job_labels, spawn_job, LabelVerdict};

const VM_NAME_PREFIX: &str = "gha-";

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

async fn sweep_inner(config: &Config, gh: &GhClient, lima: &Lima) -> anyhow::Result<()> {
    let cur_dir = config.spool_dir.join("cur");

    expire_stale_cur(
        &cur_dir,
        &config.spool_dir.join("error"),
        config.job_max_runtime_secs,
    )
    .await?;

    let live = live_vm_names_from_cur(&cur_dir).await.unwrap_or_default();

    match lima.list_names().await {
        Ok(names) => {
            for name in names {
                if !is_managed_vm_name(&name) {
                    continue;
                }
                if !live.contains(&name) {
                    info!(vm = %name, "gc: orphan Lima VM, deleting");
                    if let Err(e) = lima.stop(&name).await {
                        warn!(vm = %name, error = %e, "stop");
                    }
                    if let Err(e) = lima.delete(&name).await {
                        warn!(vm = %name, error = %e, "delete");
                    }
                }
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
    let mut out = HashSet::new();
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
            out.insert(vm_name(id));
        }
    }
    Ok(out)
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
