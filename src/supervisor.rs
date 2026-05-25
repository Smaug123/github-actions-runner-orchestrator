// The supervisor is the dispatch loop.
//
//   * a spool watcher pushes filenames from new/ down a channel,
//   * the dispatcher validates each one before doing anything privileged:
//       - filename parses as `<workflow_job_id>.job`,
//       - file passes size and file-type caps,
//       - envelope schema is 1,
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

use anyhow::Result;
use tokio::sync::{mpsc, Semaphore};
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

    while let Some(name) = rx.recv().await {
        // Acquire the concurrency permit BEFORE trying to claim the file.
        //
        // The cur/ directory is treated by the rest of the system as
        // ground truth for in-flight jobs: GC ages cur/ entries from the
        // claim's mtime (gc.rs::expire_stale_cur), and JIT runners are
        // minted on the assumption that the cur/ entry will survive at
        // least until the job finishes. If we claimed first and then
        // blocked waiting for a permit, a long enough wait would let GC
        // move the cur/ entry to error/ underneath us — and we'd later
        // mint a JIT runner with no spool record backing it.
        //
        // Acquiring the permit first means cur/ only ever contains jobs
        // we are actively prepared to run. If the channel backs up while
        // we hold permits open during validation, the watcher's periodic
        // rescan will replay the surviving new/ entries once a permit
        // frees up.
        let permit = match Arc::clone(&permits).acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                error!("semaphore closed; bailing out of dispatch");
                break;
            }
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
                let vm_name = crate::runner::vm_name_for_event(&event);
                // delivery is the unauthenticated X-GitHub-Delivery from the
                // envelope; workflow_job.name and repository.full_name are
                // authenticated but author-controlled. Sanitize all three so
                // a maliciously-named workflow or a forged envelope can't
                // smuggle control characters into structured log output.
                info!(
                    vm = %vm_name,
                    delivery = %sanitize_for_log(&delivery),
                    repo = %sanitize_for_log(&event.repository.full_name),
                    job = %sanitize_for_log(&event.workflow_job.name),
                    run_id = event.workflow_job.run_id,
                    job_id = event.workflow_job.id,
                    "claiming job"
                );
                let spool2 = Arc::clone(&spool);
                let config2 = Arc::clone(&config);
                let gh2 = Arc::clone(&gh);
                let lima2 = Arc::clone(&lima);
                tokio::spawn(async move {
                    let _permit = permit;
                    let cur_path = cur_path;
                    let vm_for_log = vm_name.clone();
                    let job = Job { event };
                    match run_job(job, config2, gh2, lima2).await {
                        Ok(()) => {
                            info!(vm = %vm_for_log, "job ok");
                            if let Err(e) = spool2.finalize_done(&cur_path).await {
                                error!(error = %e, "finalize_done failed");
                            }
                        }
                        Err(e) => {
                            error!(vm = %vm_for_log, error = %format!("{e:#}"), "job failed");
                            if let Err(fe) =
                                spool2.finalize_error(&cur_path, &format!("{e:#}")).await
                            {
                                error!(error = %fe, "finalize_error failed");
                            }
                        }
                    }
                });
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

    if let Some(reason) =
        validate_envelope(&env, &body_bytes, secret, allowed_repos, filename_job_id)
    {
        return Prepared::Reject { cur_path, reason };
    }

    // 4. We want only workflow_job events with action=queued and our label.
    if env.event != "workflow_job" {
        return Prepared::Drop {
            cur_path,
            reason: format!("event={}", env.event),
        };
    }
    let event: WorkflowJob = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => {
            return Prepared::Reject {
                cur_path,
                reason: format!("workflow_job decode: {e}"),
            };
        }
    };
    // Cross-check every signed envelope field against the body it came from.
    // The HMAC already authenticates the body; this is the spool's faithful-
    // copy check — if the envelope and body disagree we don't know which to
    // trust, so we bail.
    if event.repository.id != env.repo_id {
        return Prepared::Reject {
            cur_path,
            reason: format!(
                "envelope.repo_id={} != body.repository.id={}",
                env.repo_id, event.repository.id
            ),
        };
    }
    if event.repository.full_name != env.repo {
        return Prepared::Reject {
            cur_path,
            reason: format!(
                "envelope.repo={} != body.repository.full_name={}",
                env.repo, event.repository.full_name
            ),
        };
    }
    if event.workflow_job.id != env.workflow_job_id {
        return Prepared::Reject {
            cur_path,
            reason: format!(
                "envelope.workflow_job_id={} != body.workflow_job.id={}",
                env.workflow_job_id, event.workflow_job.id
            ),
        };
    }
    if event.action != env.action {
        return Prepared::Reject {
            cur_path,
            reason: format!(
                "envelope.action={} != body.action={}",
                env.action, event.action
            ),
        };
    }
    if event.action != "queued" {
        return Prepared::Drop {
            cur_path,
            reason: format!("action={}", event.action),
        };
    }
    if !event
        .workflow_job
        .labels
        .iter()
        .any(|l| l == &config.runner_label)
    {
        return Prepared::Drop {
            cur_path,
            reason: format!(
                "labels {:?} do not include {}",
                event.workflow_job.labels, config.runner_label
            ),
        };
    }
    // Every workflow-requested label must be in our advertised set. This is
    // the boundary that stops a workflow file from minting a runner labeled
    // `prod`, `gpu`, or other policy-bearing names we didn't intend to
    // advertise. A miss is a Drop (some other factory might handle it) but
    // if you'd rather log loudly, it's worth promoting to Reject in operator
    // policies that care.
    if let Some(unknown) = event
        .workflow_job
        .labels
        .iter()
        .find(|l| !runner_labels.contains(l.as_str()))
    {
        return Prepared::Drop {
            cur_path,
            reason: format!(
                "label {:?} not in advertised set {:?}",
                unknown, config.runner_labels
            ),
        };
    }
    Prepared::Run {
        cur_path,
        delivery: env.delivery,
        event,
    }
}

fn validate_envelope(
    env: &Envelope,
    body: &[u8],
    secret: &[u8],
    allowed_repos: &HashSet<String>,
    filename_job_id: u64,
) -> Option<String> {
    if env.schema != 1 {
        return Some(format!("schema={} (expected 1)", env.schema));
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
