// gh-actions-consumer: drain a gh-webhook-spool queue and run each
// workflow_job we own in a one-shot Lima VM.
//
// The supervisor is the heart of this binary; main just parses config,
// validates credential file modes, builds the GitHub client, does a
// startup self-check that we can list runners on an allowed repo (proving
// the App installation token and repo admin rights work), and hands off.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

mod config;
mod control;
mod gc;
mod github;
mod lima;
mod runner;
mod spool;
mod supervisor;
mod warm;

#[tokio::main]
async fn main() -> Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let mut config = config::Config::parse();
    config.validate()?;
    // The whole credential/ownership model assumes a dedicated unprivileged
    // user — `require_owned_by_us` compares against geteuid, and the in-VM
    // `sudo gha-run-once` would otherwise be invoked by host root. Refuse
    // uid 0 outright so a misconfigured launchd plist fails loudly rather
    // than silently widening the host blast radius.
    // SAFETY: geteuid is always safe.
    if unsafe { libc::geteuid() } == 0 {
        anyhow::bail!(
            "refusing to run as uid 0; create a dedicated unprivileged user for this daemon"
        );
    }
    config.ensure_paths()?;

    // Refuse to run unless the App's private key is owned by us and 0600,
    // matching the posture ssh takes for ~/.ssh/id_rsa. read_private_file
    // does the open + fstat + read on a single fd so the bytes we hand to
    // jsonwebtoken are the same ones we just validated — no TOCTOU window
    // between stat and read.
    let pem = config::read_private_file(&config.app_private_key_file)
        .context("read GH App private key file")?;
    let auth = github::installation::AppAuth {
        app_id: config.app_id,
        pem: Arc::new(pem),
    };
    let config = Arc::new(config);

    let webhook_secret = Arc::new(config.load_webhook_secret()?);
    let allowed_repos = Arc::new(config.allowed_repos_set());
    let runner_labels = Arc::new(config.runner_labels_set());
    let lima = Arc::new(lima::Lima::new(config.limactl_path.clone()));

    let http = reqwest::Client::builder()
        .user_agent(concat!("gh-actions-consumer/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(config.api_timeout_secs))
        .build()?;

    let installations = Arc::new(github::installation::Installations::new(
        config.api_url.clone(),
        http.clone(),
        auth,
    ));
    let gh = Arc::new(github::jit::GhClient::new(
        config.api_url.clone(),
        http,
        config.org.clone(),
        installations,
    ));

    // Startup self-check: prove the App installation token works and we hold
    // repo admin rights by listing runners on every allowed repo. GC and
    // teardown operate per repo, so a typo or missing App access on any one of
    // them must fail loudly here rather than as recurring runtime errors.
    for repo in &config.allowed_repos {
        let (owner, name) = repo
            .split_once('/')
            .with_context(|| format!("GH_ALLOWED_REPOS entry {repo:?} is not owner/name"))?;
        gh.list_runners(owner, name, "gha-")
            .await
            .with_context(|| format!("startup self-check: listing runners on {repo}"))?;
        // Both the reconciler and the completion check (spawn_job's job_status
        // call) read workflow runs/jobs, which need the App's `Actions: read`
        // permission — a different scope from the runner-admin rights proven
        // above. Probe it whenever either feature is on so a missing permission
        // fails loudly at startup rather than as recurring runtime 403s.
        if config.reconcile_enabled || config.job_completion_check {
            gh.list_queued_jobs(owner, name).await.with_context(|| {
                format!(
                    "startup self-check: listing queued jobs on {repo} (RECONCILE_ENABLED / \
                     JOB_COMPLETION_CHECK require the App's `Actions: read` permission)"
                )
            })?;
        }
    }
    tracing::info!(
        account = %config.org,
        label = %config.runner_label,
        runner_labels = ?config.runner_labels,
        spool = %config.spool_dir.display(),
        max_concurrency = config.max_concurrency,
        allowed_repos = ?allowed_repos.iter().collect::<Vec<_>>(),
        limactl = %config.limactl_path.display(),
        "ready",
    );

    // Reap every pre-existing managed VM before the supervisor can claim or
    // launch any job. A fresh consumer cannot re-adopt an in-flight VM's runner
    // session, so each lingering VM only oversubscribes the host and steals
    // freshly-queued jobs under a possibly-superseded image. Ordering is
    // load-bearing: this must precede supervisor::run (and the VMs it boots) so
    // it never deletes a VM the new consumer just started. After a clean
    // pause->drain->restart there are none and this is a no-op.
    gc::reap_all_managed_vms_at_startup(&config, &lima).await;

    let runtime = supervisor::Runtime {
        config: Arc::clone(&config),
        gh: Arc::clone(&gh),
        lima,
        webhook_secret,
        allowed_repos,
        runner_labels,
    };
    // The supervisor owns shutdown handling: SIGTERM (or the first Ctrl+C)
    // pauses new claims and drains in-flight VMs before exiting cleanly, a
    // second Ctrl+C forces immediate teardown. It returns Ok on any clean or
    // forced shutdown and Err only on genuine failure.
    supervisor::run(runtime).await
}
