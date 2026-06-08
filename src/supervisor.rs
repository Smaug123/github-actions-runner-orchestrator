// The supervisor is the dispatch loop.
//
//   * a spool watcher pushes filenames from new/ down a channel,
//   * the dispatcher validates each one before doing anything privileged:
//       - filename parses as `<workflow_job_id>.job`,
//       - file passes size and file-type caps,
//       - envelope schema is 1 or 2,
//       - HMAC matches the body using our shared webhook secret,
//       - envelope.workflow_job_id matches the filename's id,
//       - envelope.repo is in our allowlist,
//       - envelope's signed fields (repo_id, repo, action,
//         workflow_job_id) all match the parsed body,
//       - event is workflow_job, action is queued, labels include our
//         gate label and are a subset of our advertised set,
//   * only then does it acquire a permit and spawn a worker,
//   * a GC task runs on an interval and at startup.
//
// SIGINT handling lives in main(); when ctrl_c fires the runtime is torn
// down. In-flight VMs survive (they're separate Lima processes); the next
// startup's GC sweep cleans them up via the stale-cur/ logic and Lima list.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::github::event::WorkflowJob;
use crate::github::jit::GhClient;
use crate::lima::Lima;
use crate::runner::{run_job, Job};
use crate::spool::{
    parse_spool_filename, read_spool_file, sanitize_for_log, verify_signature, Envelope, Spool,
};

pub struct Runtime {
    pub config: Arc<Config>,
    pub gh: Arc<GhClient>,
    pub lima: Arc<Lima>,
    pub webhook_secret: Arc<Zeroizing<Vec<u8>>>,
    pub allowed_repos: Arc<HashSet<String>>,
    pub runner_labels: Arc<HashSet<String>>,
}

pub async fn run(rt: Runtime) -> Result<()> {
    let Runtime {
        config,
        gh,
        lima,
        webhook_secret,
        allowed_repos,
        runner_labels,
    } = rt;
    let spool = Arc::new(Spool::new(config.spool_dir.clone()));
    let permits = Arc::new(Semaphore::new(config.max_concurrency));

    // Optional signing-cache warmer, built only when CACHE_WARM_ENABLED. Its
    // paths/flags were already validated at startup (`validate_cache_warm`), so a
    // construction failure here is a genuine misconfiguration (e.g. an unreadable
    // cache pubkey) and should fail startup rather than silently never warm.
    let warmer = if config.cache_warm_enabled {
        Some(Arc::new(
            crate::warm::Warmer::new(Arc::clone(&gh), Arc::clone(&allowed_repos), &config)
                .context("build cache warmer")?,
        ))
    } else {
        None
    };

    // Pause gate: while true the dispatch loop stops claiming new jobs (they
    // wait in new/); in-flight jobs and the GC keep running. Flipped by the
    // optional loopback control server. Held open here so the receiver never
    // sees the sender dropped when the control server is disabled.
    let (pause_tx, mut pause_rx) = tokio::sync::watch::channel(false);
    if let Some(addr) = config.control_socket_addr()? {
        // Bind here, not inside the task, so a failure (e.g. port in use) fails
        // startup rather than silently leaving no control endpoint.
        let listener = crate::control::bind(addr).await?;
        // VM-snapshot poller: publishes the daemon's own view of its managed
        // Lima VMs so the control UI reads a cached snapshot instead of spawning
        // limactl per request. Only runs while the control server is enabled.
        let (vm_tx, vm_rx) =
            tokio::sync::watch::channel(Arc::new(crate::control::VmSnapshot::default()));
        {
            let lima = Arc::clone(&lima);
            tokio::spawn(async move {
                crate::control::poll_vm_snapshots(lima, vm_tx).await;
            });
        }
        let state = crate::control::ControlState {
            pause: pause_tx.clone(),
            permits: Arc::clone(&permits),
            max_concurrency: config.max_concurrency,
            spool: Arc::clone(&spool),
            webhook_secret: Arc::clone(&webhook_secret),
            allowed_repos: Arc::clone(&allowed_repos),
            runner_labels: Arc::clone(&runner_labels),
            runner_label: config.runner_label.clone(),
            vms: vm_rx,
        };
        tokio::spawn(async move {
            if let Err(e) = crate::control::serve(listener, state).await {
                error!(error = %format!("{e:#}"), "control server exited");
            }
        });
        info!(%addr, "control server listening");
    }

    crate::gc::sweep(&config, &gh, &lima).await;

    let (tx, mut rx) = mpsc::channel::<String>(256);
    let watch_root = spool.new_dir();
    let watcher = tokio::spawn(async move {
        if let Err(e) = crate::spool::watch(watch_root, tx).await {
            error!(error = %e, "spool watcher exited");
        }
    });

    {
        let config = Arc::clone(&config);
        let gh = Arc::clone(&gh);
        let lima = Arc::clone(&lima);
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(config.gc_interval_secs));
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            t.tick().await; // first tick fires immediately; we already swept above
            loop {
                t.tick().await;
                crate::gc::sweep(&config, &gh, &lima).await;
            }
        });
    }

    // Queued-job reconciler: the correctness backstop. GitHub's runner matching
    // is label-fungible, so a runner we mint for one job can be handed an
    // unrelated queued job; this pass re-mints from GitHub's authoritative
    // queue for any still-queued job that lacks a runner. Separate (faster)
    // cadence from GC so a stolen job recovers promptly without running VM
    // cleanup every minute. Skips while paused so a clean drain still works.
    if config.reconcile_enabled {
        let config = Arc::clone(&config);
        let gh = Arc::clone(&gh);
        let lima = Arc::clone(&lima);
        let spool = Arc::clone(&spool);
        let permits = Arc::clone(&permits);
        let webhook_secret = Arc::clone(&webhook_secret);
        let runner_labels = Arc::clone(&runner_labels);
        let pause_rx = pause_tx.subscribe();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(config.reconcile_interval_secs));
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                t.tick().await;
                if *pause_rx.borrow() {
                    continue;
                }
                // reconcile re-checks `pause_rx` before each repo's I/O and
                // before each mint, so a pause landing mid-pass can't spawn work.
                crate::gc::reconcile(
                    &config,
                    &gh,
                    &lima,
                    &spool,
                    &permits,
                    &webhook_secret,
                    &runner_labels,
                    &pause_rx,
                )
                .await;
            }
        });
    }

    'dispatch: while let Some(name) = rx.recv().await {
        // Acquire a permit while honoring pause. Two rules:
        //
        //  - Acquire the permit BEFORE claiming. The cur/ directory is ground
        //    truth for in-flight jobs: GC ages cur/ entries from the claim's
        //    mtime (gc.rs::expire_stale_cur) and JIT runners are minted assuming
        //    the cur/ entry outlives the job. Claiming first then blocking for a
        //    permit could let GC move the cur/ entry to error/ under us, leaving
        //    a runner with no backing spool record. (If the channel backs up,
        //    the watcher's periodic rescan replays surviving new/ entries.)
        //
        //  - Don't claim — or pin a permit — while paused, so a clean drain can
        //    reach in_flight == 0. Re-check pause AFTER the (possibly long)
        //    acquire, since it may flip while we wait for capacity; otherwise a
        //    freed permit would let one more job through after pause.
        let permit = loop {
            // Returns immediately when not paused; errors only if pause_tx is
            // dropped, which never happens while it lives in this scope.
            let _ = pause_rx.wait_for(|paused| !*paused).await;
            let permit = match Arc::clone(&permits).acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    error!("semaphore closed; bailing out of dispatch");
                    break 'dispatch;
                }
            };
            if *pause_rx.borrow() {
                // Paused while we waited for capacity: release and re-wait so we
                // neither claim during pause nor pin a permit that would keep
                // in_flight above 0.
                drop(permit);
                continue;
            }
            break permit;
        };
        match prepare(
            &spool,
            &name,
            &config,
            &webhook_secret,
            &allowed_repos,
            &runner_labels,
        )
        .await
        {
            Prepared::Run {
                cur_path,
                delivery,
                event,
            } => {
                // delivery is the unauthenticated X-GitHub-Delivery from the
                // envelope; workflow_job.name and repository.full_name are
                // authenticated but author-controlled. Sanitize all three so
                // a maliciously-named workflow or a forged envelope can't
                // smuggle control characters into structured log output.
                info!(
                    vm = %crate::runner::vm_name_for_event(&event),
                    delivery = %sanitize_for_log(&delivery),
                    repo = %sanitize_for_log(&event.repository.full_name),
                    job = %sanitize_for_log(&event.workflow_job.name),
                    run_id = event.workflow_job.run_id,
                    run_attempt = event.workflow_job.run_attempt,
                    job_id = event.workflow_job.id,
                    "claiming job"
                );
                // Best-effort signing-cache warm when this job is the live tip of
                // its repo's default branch. Cheap + fire-and-forget: it spawns
                // its own task and never blocks the dispatch loop or affects the
                // job. `&event` is borrowed before `spawn_job` consumes it below.
                if let Some(warmer) = &warmer {
                    warmer.maybe_trigger(&event);
                }
                spawn_job(
                    Arc::clone(&spool),
                    Arc::clone(&config),
                    Arc::clone(&gh),
                    Arc::clone(&lima),
                    event,
                    cur_path,
                    permit,
                );
            }
            Prepared::Drop { cur_path, reason } => {
                info!(file = %sanitize_for_log(&name), reason = %sanitize_for_log(&reason), "dropping (not for us)");
                if let Err(e) = spool.finalize_done(&cur_path).await {
                    warn!(error = %e, "finalize_done failed");
                }
            }
            Prepared::Reject { cur_path, reason } => {
                warn!(file = %sanitize_for_log(&name), reason = %sanitize_for_log(&reason), "rejecting -> error/");
                if let Err(e) = spool.finalize_error(&cur_path, &reason).await {
                    warn!(error = %e, "finalize_error failed");
                }
            }
            Prepared::Skip => {}
        }
    }

    let _ = watcher.await;
    Ok(())
}

enum Prepared {
    /// Validated and ready to run. `delivery` is the unauthenticated
    /// X-GitHub-Delivery header, carried through purely for log correlation
    /// against GitHub's webhook delivery dashboard.
    Run {
        cur_path: std::path::PathBuf,
        delivery: String,
        event: WorkflowJob,
    },
    /// Authentic queue entry, but not for us (wrong event, wrong label, etc.).
    /// Archive to done/.
    Drop {
        cur_path: std::path::PathBuf,
        reason: String,
    },
    /// Failed validation (bad HMAC, oversize, malformed, mismatched fields).
    /// Move to error/ for forensic inspection.
    Reject {
        cur_path: std::path::PathBuf,
        reason: String,
    },
    /// Nothing to do here; we never owned the file (claim race, malformed
    /// filename, etc.). The supervisor moves on.
    Skip,
}

async fn prepare(
    spool: &Spool,
    name: &str,
    config: &Config,
    secret: &[u8],
    allowed_repos: &HashSet<String>,
    runner_labels: &HashSet<String>,
) -> Prepared {
    // 1. Validate the filename shape before any privileged action. A name
    //    that doesn't parse is either junk left in new/ or a probe; ignore.
    let Some(filename_job_id) = parse_spool_filename(name) else {
        return Prepared::Skip;
    };

    // 2. Claim. Lost the race? Move on.
    let cur_path = match spool.try_claim(name).await {
        Ok(Some(p)) => p,
        Ok(None) => return Prepared::Skip,
        Err(e) => {
            warn!(file = %sanitize_for_log(name), error = %e, "try_claim failed; will retry on next scan");
            return Prepared::Skip;
        }
    };

    // 3. Reject non-canonical filename aliases (e.g. `00042.job` for id 42).
    //    `parse_spool_filename` accepts any decimal that fits a u64, but the
    //    spooler only ever writes the canonical `{id}.job`. Anything else is
    //    a forgery from a same-uid writer trying to manufacture a duplicate
    //    queue entry under a name we wouldn't dedupe against. Reject (not
    //    Skip) so the file moves to error/ and stops being rescanned.
    let canonical = format!("{filename_job_id}.job");
    if name != canonical {
        return Prepared::Reject {
            cur_path,
            reason: format!(
                "non-canonical filename {:?} for id {filename_job_id} (expected {canonical})",
                sanitize_for_log(name)
            ),
        };
    }

    // 4. Read with size cap.
    let (env, body_bytes) = match read_spool_file(&cur_path).await {
        Ok(eb) => eb,
        Err(e) => {
            return Prepared::Reject {
                cur_path,
                reason: format!("read/parse spool file: {e:#}"),
            };
        }
    };

    // 4. Validate the read envelope/body and classify. Shared with the control
    //    endpoint's queued listing so both apply identical checks (no drift):
    //    only an entry that would actually Run is shown as queued.
    match classify_validated_entry(
        filename_job_id,
        &env,
        &body_bytes,
        secret,
        allowed_repos,
        &config.runner_label,
        runner_labels,
    ) {
        EntryVerdict::Run(event) => Prepared::Run {
            cur_path,
            delivery: env.delivery,
            event,
        },
        EntryVerdict::Drop(reason) => Prepared::Drop { cur_path, reason },
        EntryVerdict::Reject(reason) => Prepared::Reject { cur_path, reason },
    }
}

/// Verdict for a spool entry that has already been read into `(envelope, body)`
/// — the post-read half of `prepare()`, factored out so the control endpoint's
/// queued listing applies the very same checks before displaying a row.
pub(crate) enum EntryVerdict {
    /// Authentic, for us, and queued: would be claimed and run.
    Run(WorkflowJob),
    /// Authentic but not for us (wrong event/action/labels) — would be archived
    /// to done/ on dispatch.
    Drop(String),
    /// Failed validation (bad HMAC, mismatch, malformed) — would go to error/.
    Reject(String),
}

/// Validate a read spool entry exactly as `prepare()` does after the claim+read:
/// HMAC + schema + filename↔envelope id + repo allowlist (`validate_envelope`),
/// then the envelope↔body cross-checks, `action == queued`, and the shared label
/// policy. Pure (no I/O), so the control listing can reuse it on a `new/` entry
/// without claiming. `filename_job_id` is the id parsed from the filename; the
/// caller is responsible for the canonical-filename check (it needs the raw
/// name, which this function doesn't take).
#[allow(clippy::too_many_arguments)]
pub(crate) fn classify_validated_entry(
    filename_job_id: u64,
    env: &Envelope,
    body_bytes: &[u8],
    secret: &[u8],
    allowed_repos: &HashSet<String>,
    runner_label: &str,
    runner_labels: &HashSet<String>,
) -> EntryVerdict {
    if let Some(reason) = validate_envelope(env, body_bytes, secret, allowed_repos, filename_job_id)
    {
        return EntryVerdict::Reject(reason);
    }
    if env.event != "workflow_job" {
        return EntryVerdict::Drop(format!("event={}", env.event));
    }
    let event: WorkflowJob = match serde_json::from_slice(body_bytes) {
        Ok(v) => v,
        Err(e) => return EntryVerdict::Reject(format!("workflow_job decode: {e}")),
    };
    // Cross-check every signed envelope field against the body it came from.
    // The HMAC already authenticates the body; this is the spool's faithful-
    // copy check — if the envelope and body disagree we don't know which to
    // trust, so we bail.
    if event.repository.id != env.repo_id {
        return EntryVerdict::Reject(format!(
            "envelope.repo_id={} != body.repository.id={}",
            env.repo_id, event.repository.id
        ));
    }
    if event.repository.full_name != env.repo {
        return EntryVerdict::Reject(format!(
            "envelope.repo={} != body.repository.full_name={}",
            env.repo, event.repository.full_name
        ));
    }
    if event.workflow_job.id != env.workflow_job_id {
        return EntryVerdict::Reject(format!(
            "envelope.workflow_job_id={} != body.workflow_job.id={}",
            env.workflow_job_id, event.workflow_job.id
        ));
    }
    if event.action != env.action {
        return EntryVerdict::Reject(format!(
            "envelope.action={} != body.action={}",
            env.action, event.action
        ));
    }
    if event.action != "queued" {
        return EntryVerdict::Drop(format!("action={}", event.action));
    }
    // Shared label policy: the gate label must be present and every requested
    // label must be in the advertised set — the boundary that stops a workflow
    // file from minting a runner labeled `prod`, `gpu`, or other policy-bearing
    // names we didn't intend to advertise. The reconciler applies the same
    // predicate to API-discovered jobs. A miss is a Drop (some other factory
    // might handle it); promote to Reject in operator policies that care.
    match classify_job_labels(&event.workflow_job.labels, runner_label, runner_labels) {
        LabelVerdict::Accept => EntryVerdict::Run(event),
        LabelVerdict::Reject(reason) => EntryVerdict::Drop(reason),
    }
}

/// Verdict of the shared label policy.
pub(crate) enum LabelVerdict {
    Accept,
    /// Not for us: the gate label is missing, or a requested label is outside
    /// the advertised set. The string is a log-ready reason.
    Reject(String),
}

/// The label policy shared by `prepare()` (spool path) and the reconciler (API
/// path): the gate label must be present, and every requested label must be in
/// the advertised set. Pulling it out of `prepare()` keeps the policy in one
/// place even though the reconciler validates authenticated API data rather
/// than spool data (so it legitimately does not route through `prepare()`).
pub(crate) fn classify_job_labels(
    labels: &[String],
    runner_label: &str,
    runner_labels: &HashSet<String>,
) -> LabelVerdict {
    if !labels.iter().any(|l| l == runner_label) {
        return LabelVerdict::Reject(format!("labels {labels:?} do not include {runner_label}"));
    }
    if let Some(unknown) = labels.iter().find(|l| !runner_labels.contains(l.as_str())) {
        return LabelVerdict::Reject(format!("label {unknown:?} not in advertised set"));
    }
    LabelVerdict::Accept
}

/// What to do with a finished runner's spool entry, decided from the job's
/// authoritative GitHub status.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompletionAction {
    /// The job left the queue (ran somewhere, including ran-and-failed), or its
    /// status is unknown/unreadable. Finalize to done/.
    Done,
    /// The job is still queued: our runner ran some *other* job (GitHub's
    /// label matching is fungible). The webhook is spent regardless, so we
    /// still finalize to done/; the reconciler re-mints from authoritative
    /// state. Distinguished only for logging.
    Steal,
}

/// Map a GitHub job status (`None` = 404 / unknown) to a completion action.
/// Only an explicit `queued` is a steal; everything else (including unknown)
/// fails safe toward Done so we never double-run — the reconciler is the
/// non-lossy backstop for a job that really is still queued.
pub(crate) fn completion_action(status: Option<&str>) -> CompletionAction {
    match status {
        Some("queued") => CompletionAction::Steal,
        _ => CompletionAction::Done,
    }
}

async fn completion_action_via_api(
    gh: &GhClient,
    owner_repo: &str,
    job_id: u64,
) -> CompletionAction {
    let Some((owner, repo)) = owner_repo.split_once('/') else {
        return CompletionAction::Done;
    };
    match gh.job_status(owner, repo, job_id).await {
        Ok(opt) => completion_action(opt.as_ref().map(|s| s.status.as_str())),
        Err(e) => {
            warn!(job_id, error = %format!("{e:#}"), "job status check failed; finalizing done (reconciler is the backstop)");
            CompletionAction::Done
        }
    }
}

/// Spawn the per-job worker: run the job in a VM, then finalize its spool
/// entry. Shared by the webhook dispatch path and the reconciler. The caller
/// must hand over an owned permit; it is released when the job finishes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_job(
    spool: Arc<Spool>,
    config: Arc<Config>,
    gh: Arc<GhClient>,
    lima: Arc<Lima>,
    event: WorkflowJob,
    cur_path: std::path::PathBuf,
    permit: OwnedSemaphorePermit,
) {
    let vm_for_log = crate::runner::vm_name_for_event(&event);
    let owner_repo = event.repository.full_name.clone();
    let our_job_id = event.workflow_job.id;
    let completion_check = config.job_completion_check;
    tokio::spawn(async move {
        let _permit = permit;
        let cur_path = cur_path;
        let job = Job { event };
        match run_job(job, Arc::clone(&config), Arc::clone(&gh), lima).await {
            Ok(()) => {
                let action = if completion_check {
                    completion_action_via_api(&gh, &owner_repo, our_job_id).await
                } else {
                    CompletionAction::Done
                };
                match action {
                    CompletionAction::Done => info!(vm = %vm_for_log, "job ok"),
                    // Finalizing here means "this webhook delivery is fully
                    // processed" (a runner was minted and ran a job), NOT "our
                    // job left the queue" — it may still be queued, and the
                    // reconciler re-mints it. done/ (not error/) because
                    // nothing went wrong.
                    CompletionAction::Steal => warn!(
                        vm = %vm_for_log,
                        job_id = our_job_id,
                        "runner finished but our job is still queued (stolen by another job); reconciler will re-mint"
                    ),
                }
                if let Err(e) = spool.finalize_done(&cur_path).await {
                    error!(error = %e, "finalize_done failed");
                }
            }
            Err(e) => {
                error!(vm = %vm_for_log, error = %format!("{e:#}"), "job failed");
                if let Err(fe) = spool.finalize_error(&cur_path, &format!("{e:#}")).await {
                    error!(error = %fe, "finalize_error failed");
                }
            }
        }
    });
}

fn validate_envelope(
    env: &Envelope,
    body: &[u8],
    secret: &[u8],
    allowed_repos: &HashSet<String>,
    filename_job_id: u64,
) -> Option<String> {
    if !(1..=2).contains(&env.schema) {
        return Some(format!("schema={} (expected 1 or 2)", env.schema));
    }
    if !verify_signature(&env.signature, body, secret) {
        return Some("hmac signature mismatch".to_string());
    }
    if env.workflow_job_id != filename_job_id {
        return Some(format!(
            "filename workflow_job_id {filename_job_id} != envelope.workflow_job_id {}",
            env.workflow_job_id
        ));
    }
    if !allowed_repos.contains(&env.repo) {
        return Some(format!("repo {} not in allowlist", env.repo));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use tokio::fs;

    fn sign(secret: &[u8], body: &[u8]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    /// Minimal Config for tests. Most fields are required by clap but unread
    /// by prepare(); only `runner_label` is consulted on the validation path.
    fn test_config() -> Config {
        Config::try_parse_from([
            "test",
            "--spool-dir=/tmp",
            "--state-dir=/tmp",
            "--app-id=1",
            "--app-private-key-file=/tmp/key",
            "--org=o",
            "--lima-template=/tmp/lima.yaml",
            "--limactl-path=/usr/bin/true",
            "--allowed-repos=o/r",
        ])
        .unwrap()
    }

    const DELIVERY: &str = "72d3162e-cc78-11e3-81ab-4c9367dc0958";
    const JOB_ID: u64 = 9001;
    const FILENAME: &str = "9001.job";

    /// Build a schema-1 envelope with the given action / repo / job id / sig.
    /// Any other interesting field can be patched into the resulting String
    /// by the caller (e.g. for the `schema_mismatch` test).
    fn envelope(action: &str, repo_id: u64, repo: &str, job_id: u64, signature: &str) -> String {
        format!(
            r#"{{"schema":1,"event":"workflow_job","delivery":"{DELIVERY}","repo_id":{repo_id},"repo":"{repo}","action":"{action}","workflow_job_id":{job_id},"received_at_ms":1,"signature":"{signature}"}}"#
        )
    }

    /// Build a workflow_job body with the given action / repo / job id / labels.
    fn body(action: &str, repo_id: u64, full_name: &str, job_id: u64, labels: &[&str]) -> Vec<u8> {
        let labels_json: Vec<serde_json::Value> =
            labels.iter().map(|l| serde_json::json!(l)).collect();
        serde_json::to_vec(&serde_json::json!({
            "action": action,
            "workflow_job": { "id": job_id, "run_id": 2, "name": "n", "labels": labels_json },
            "repository": { "id": repo_id, "full_name": full_name }
        }))
        .unwrap()
    }

    async fn write_claim(root: &std::path::Path, name: &str, env: &str, body: &[u8]) {
        for sub in ["new", "cur", "done", "error"] {
            fs::create_dir_all(root.join(sub)).await.unwrap();
        }
        let path = root.join("new").join(name);
        let mut bytes = env.as_bytes().to_vec();
        bytes.push(b'\n');
        bytes.extend_from_slice(body);
        fs::write(&path, &bytes).await.unwrap();
    }

    fn allowed(repos: &[&str]) -> HashSet<String> {
        repos.iter().map(|s| s.to_string()).collect()
    }

    fn test_labels() -> HashSet<String> {
        ["self-hosted", "lima-nix"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    #[tokio::test]
    async fn good_workflow_job_returns_run() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let body = body("queued", 42, "o/r", JOB_ID, &["self-hosted", "lima-nix"]);
        let sig = sign(b"k", &body);
        let env = envelope("queued", 42, "o/r", JOB_ID, &sig);
        write_claim(&root, FILENAME, &env, &body).await;
        let spool = Spool::new(root);
        match prepare(
            &spool,
            FILENAME,
            &test_config(),
            b"k",
            &allowed(&["o/r"]),
            &test_labels(),
        )
        .await
        {
            Prepared::Run {
                delivery, event, ..
            } => {
                assert_eq!(delivery, DELIVERY);
                assert_eq!(event.repository.full_name, "o/r");
                assert_eq!(event.workflow_job.id, JOB_ID);
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn bad_hmac_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let body = body("queued", 42, "o/r", JOB_ID, &["self-hosted", "lima-nix"]);
        let sig = sign(b"WRONG", &body); // signed with a different key
        let env = envelope("queued", 42, "o/r", JOB_ID, &sig);
        write_claim(&root, FILENAME, &env, &body).await;
        let spool = Spool::new(root);
        let p = prepare(
            &spool,
            FILENAME,
            &test_config(),
            b"k",
            &allowed(&["o/r"]),
            &test_labels(),
        )
        .await;
        assert!(matches!(p, Prepared::Reject { ref reason, .. } if reason.contains("hmac")));
    }

    #[tokio::test]
    async fn envelope_body_repo_mismatch_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        // Body says other/repo, envelope says o/r — HMAC still passes
        // because the spool faithfully signed the body, but the envelope's
        // copy was tampered with.
        let body = body(
            "queued",
            42,
            "other/repo",
            JOB_ID,
            &["self-hosted", "lima-nix"],
        );
        let sig = sign(b"k", &body);
        let env = envelope("queued", 42, "o/r", JOB_ID, &sig);
        write_claim(&root, FILENAME, &env, &body).await;
        let spool = Spool::new(root);
        let p = prepare(
            &spool,
            FILENAME,
            &test_config(),
            b"k",
            &allowed(&["o/r"]),
            &test_labels(),
        )
        .await;
        assert!(
            matches!(p, Prepared::Reject { ref reason, .. } if reason.contains("envelope.repo"))
        );
    }

    #[tokio::test]
    async fn envelope_body_repo_id_mismatch_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let body = body("queued", 999, "o/r", JOB_ID, &["self-hosted", "lima-nix"]);
        let sig = sign(b"k", &body);
        let env = envelope("queued", 42, "o/r", JOB_ID, &sig);
        write_claim(&root, FILENAME, &env, &body).await;
        let spool = Spool::new(root);
        let p = prepare(
            &spool,
            FILENAME,
            &test_config(),
            b"k",
            &allowed(&["o/r"]),
            &test_labels(),
        )
        .await;
        assert!(matches!(p, Prepared::Reject { ref reason, .. } if reason.contains("repo_id")));
    }

    #[tokio::test]
    async fn repo_not_allowlisted_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let body = body("queued", 42, "o/r", JOB_ID, &["self-hosted", "lima-nix"]);
        let sig = sign(b"k", &body);
        let env = envelope("queued", 42, "o/r", JOB_ID, &sig);
        write_claim(&root, FILENAME, &env, &body).await;
        let spool = Spool::new(root);
        let p = prepare(
            &spool,
            FILENAME,
            &test_config(),
            b"k",
            &allowed(&["x/y"]),
            &test_labels(),
        )
        .await;
        assert!(matches!(p, Prepared::Reject { ref reason, .. } if reason.contains("allowlist")));
    }

    #[tokio::test]
    async fn filename_envelope_job_id_mismatch_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        // Filename names 9001 but envelope says 9002. Either the spool got
        // confused or someone renamed the file; either way, refuse.
        let body = body("queued", 42, "o/r", 9002, &["self-hosted", "lima-nix"]);
        let sig = sign(b"k", &body);
        let env = envelope("queued", 42, "o/r", 9002, &sig);
        write_claim(&root, "9001.job", &env, &body).await;
        let spool = Spool::new(root);
        let p = prepare(
            &spool,
            "9001.job",
            &test_config(),
            b"k",
            &allowed(&["o/r"]),
            &test_labels(),
        )
        .await;
        assert!(
            matches!(p, Prepared::Reject { ref reason, .. } if reason.contains("filename workflow_job_id"))
        );
    }

    #[tokio::test]
    async fn envelope_body_job_id_mismatch_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        // Envelope's id matches filename, but body disagrees.
        let body = body("queued", 42, "o/r", 7777, &["self-hosted", "lima-nix"]);
        let sig = sign(b"k", &body);
        let env = envelope("queued", 42, "o/r", JOB_ID, &sig);
        write_claim(&root, FILENAME, &env, &body).await;
        let spool = Spool::new(root);
        let p = prepare(
            &spool,
            FILENAME,
            &test_config(),
            b"k",
            &allowed(&["o/r"]),
            &test_labels(),
        )
        .await;
        assert!(
            matches!(p, Prepared::Reject { ref reason, .. } if reason.contains("workflow_job.id"))
        );
    }

    #[tokio::test]
    async fn malformed_filename_is_skip() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        for sub in ["new", "cur", "done", "error"] {
            fs::create_dir_all(root.join(sub)).await.unwrap();
        }
        let spool = Spool::new(root);
        let p = prepare(
            &spool,
            "garbage",
            &test_config(),
            b"k",
            &allowed(&["o/r"]),
            &test_labels(),
        )
        .await;
        assert!(matches!(p, Prepared::Skip));
    }

    #[tokio::test]
    async fn workflow_label_outside_allowlist_drops() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let body = body(
            "queued",
            42,
            "o/r",
            JOB_ID,
            &["self-hosted", "lima-nix", "prod"],
        );
        let sig = sign(b"k", &body);
        let env = envelope("queued", 42, "o/r", JOB_ID, &sig);
        write_claim(&root, FILENAME, &env, &body).await;
        let spool = Spool::new(root);
        let p = prepare(
            &spool,
            FILENAME,
            &test_config(),
            b"k",
            &allowed(&["o/r"]),
            &test_labels(),
        )
        .await;
        assert!(matches!(p, Prepared::Drop { ref reason, .. } if reason.contains("prod")));
    }

    #[tokio::test]
    async fn label_miss_drops() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let body = body(
            "queued",
            42,
            "o/r",
            JOB_ID,
            &["self-hosted", "ubuntu-latest"],
        );
        let sig = sign(b"k", &body);
        let env = envelope("queued", 42, "o/r", JOB_ID, &sig);
        write_claim(&root, FILENAME, &env, &body).await;
        let spool = Spool::new(root);
        let p = prepare(
            &spool,
            FILENAME,
            &test_config(),
            b"k",
            &allowed(&["o/r"]),
            &test_labels(),
        )
        .await;
        assert!(matches!(p, Prepared::Drop { ref reason, .. } if reason.contains("lima-nix")));
    }

    #[tokio::test]
    async fn non_canonical_filename_rejects() {
        // A same-uid writer drops `09001.job` (leading zero) carrying a
        // body whose workflow_job.id is 9001. parse_spool_filename accepts
        // the leading zero, and the cross-field checks would all pass,
        // but the spooler never produces non-canonical names — refuse.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let body = body("queued", 42, "o/r", JOB_ID, &["self-hosted", "lima-nix"]);
        let sig = sign(b"k", &body);
        let env = envelope("queued", 42, "o/r", JOB_ID, &sig);
        write_claim(&root, "09001.job", &env, &body).await;
        let spool = Spool::new(root);
        let p = prepare(
            &spool,
            "09001.job",
            &test_config(),
            b"k",
            &allowed(&["o/r"]),
            &test_labels(),
        )
        .await;
        assert!(
            matches!(p, Prepared::Reject { ref reason, .. } if reason.contains("non-canonical")),
            "expected Reject for non-canonical filename, got {p:?}"
        );
    }

    #[tokio::test]
    async fn schema_mismatch_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let body = body("queued", 42, "o/r", JOB_ID, &["self-hosted", "lima-nix"]);
        let sig = sign(b"k", &body);
        // Hand-build an envelope with the wrong schema.
        let env = format!(
            r#"{{"schema":99,"event":"workflow_job","delivery":"{DELIVERY}","repo_id":42,"repo":"o/r","action":"queued","workflow_job_id":{JOB_ID},"received_at_ms":1,"signature":"{sig}"}}"#
        );
        write_claim(&root, FILENAME, &env, &body).await;
        let spool = Spool::new(root);
        let p = prepare(
            &spool,
            FILENAME,
            &test_config(),
            b"k",
            &allowed(&["o/r"]),
            &test_labels(),
        )
        .await;
        assert!(matches!(p, Prepared::Reject { ref reason, .. } if reason.contains("schema")));
    }

    #[test]
    fn classify_job_labels_accepts_gate_and_subset() {
        let v = classify_job_labels(
            &["self-hosted".into(), "lima-nix".into()],
            "lima-nix",
            &test_labels(),
        );
        assert!(matches!(v, LabelVerdict::Accept));
    }

    #[test]
    fn classify_job_labels_drops_missing_gate() {
        let v = classify_job_labels(&["self-hosted".into()], "lima-nix", &test_labels());
        assert!(matches!(v, LabelVerdict::Reject(ref r) if r.contains("lima-nix")));
    }

    #[test]
    fn classify_job_labels_drops_unknown_label() {
        let v = classify_job_labels(
            &["self-hosted".into(), "lima-nix".into(), "prod".into()],
            "lima-nix",
            &test_labels(),
        );
        assert!(matches!(v, LabelVerdict::Reject(ref r) if r.contains("prod")));
    }

    #[test]
    fn completion_action_maps_status() {
        assert_eq!(completion_action(Some("queued")), CompletionAction::Steal);
        assert_eq!(
            completion_action(Some("in_progress")),
            CompletionAction::Done
        );
        // ran-and-failed: the job left the queue, so Done (not a steal).
        assert_eq!(completion_action(Some("completed")), CompletionAction::Done);
        // 404 / unknown: fail safe toward Done.
        assert_eq!(completion_action(None), CompletionAction::Done);
    }

    impl std::fmt::Debug for Prepared {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Prepared::Run { .. } => write!(f, "Run"),
                Prepared::Drop { reason, .. } => write!(f, "Drop({reason})"),
                Prepared::Reject { reason, .. } => write!(f, "Reject({reason})"),
                Prepared::Skip => write!(f, "Skip"),
            }
        }
    }
}
