// gh-actions-consumer: drain a gh-webhook-spool queue and run each
// workflow_job we own in a one-shot Lima VM.
//
// The supervisor is the heart of this binary; main just parses config,
// validates credential file modes, builds the GitHub client, does a
// startup self-check that we can reach the App's runner-groups endpoint,
// and hands off.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

mod config;
mod gc;
mod github;
mod lima;
mod runner;
mod spool;
mod supervisor;

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
        config.runner_group.clone(),
        installations,
    ));

    let group_id = gh
        .runner_group_id()
        .await
        .context("startup self-check: looking up runner group")?;
    tracing::info!(
        org = %config.org,
        runner_group = %config.runner_group,
        runner_group_id = group_id,
        label = %config.runner_label,
        runner_labels = ?config.runner_labels,
        spool = %config.spool_dir.display(),
        max_concurrency = config.max_concurrency,
        allowed_repos = ?allowed_repos.iter().collect::<Vec<_>>(),
        limactl = %config.limactl_path.display(),
        "ready",
    );

    let runtime = supervisor::Runtime {
        config: Arc::clone(&config),
        gh: Arc::clone(&gh),
        lima,
        webhook_secret,
        allowed_repos,
        runner_labels,
    };
    tokio::select! {
        r = supervisor::run(runtime) => r?,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("SIGINT; exiting (in-flight VMs left for next-start GC)");
        }
    }
    Ok(())
}
