// Runner management, all repository-scoped.
//
// JIT configs are minted with the repo-scoped endpoint so a registered runner
// can only execute jobs from the repo we intended. Discovery (list) and
// cleanup (delete) are likewise repo-scoped: a personal account has no org
// runner groups, and runners registered against a repo live in that repo's
// default group (id 1). The runner-group concept is gone entirely.

use std::sync::Arc;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::installation::Installations;

/// Repository runners always belong to the repo's default runner group, whose
/// id is 1. The repo-scoped generate-jitconfig endpoint still requires the
/// field, so we send the only value that's valid at repo scope.
const REPO_DEFAULT_RUNNER_GROUP_ID: u64 = 1;

#[derive(Serialize)]
struct GenerateJitConfigBody {
    name: String,
    runner_group_id: u64,
    labels: Vec<String>,
    work_folder: String,
}

#[derive(Debug, Deserialize)]
pub struct JitConfigResp {
    pub runner: JitRunner,
    pub encoded_jit_config: String,
}

#[derive(Debug, Deserialize)]
pub struct JitRunner {
    pub id: u64,
    #[allow(dead_code)]
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct Runner {
    pub id: u64,
    pub name: String,
    pub status: String,
    pub busy: bool,
}

#[derive(Deserialize)]
struct RunnersResp {
    runners: Vec<Runner>,
}

pub struct GhClient {
    api: String,
    http: Client,
    account: String,
    installations: Arc<Installations>,
}

impl GhClient {
    pub fn new(
        api: String,
        http: Client,
        account: String,
        installations: Arc<Installations>,
    ) -> Self {
        Self {
            api,
            http,
            account,
            installations,
        }
    }

    async fn token(&self) -> Result<String> {
        self.installations.token(&self.account).await
    }

    /// Mint a JIT runner config bound to a specific repository. A runner
    /// registered with this config can only execute jobs from {owner}/{repo},
    /// so a workflow_job from one allowlisted repo can never capture a runner
    /// minted for another.
    pub async fn generate_jit_config(
        &self,
        owner: &str,
        repo: &str,
        name: &str,
        labels: &[&str],
    ) -> Result<JitConfigResp> {
        let tok = self.token().await?;
        let url = format!(
            "{}/repos/{}/{}/actions/runners/generate-jitconfig",
            self.api, owner, repo
        );
        let body = GenerateJitConfigBody {
            name: name.to_string(),
            runner_group_id: REPO_DEFAULT_RUNNER_GROUP_ID,
            labels: labels.iter().map(|s| s.to_string()).collect(),
            work_folder: "_work".to_string(),
        };
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&tok)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&body)
            .send()
            .await
            .context("POST generate-jitconfig")?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "generate-jitconfig: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(resp.json().await?)
    }

    /// Return all runners registered on {owner}/{repo} whose name starts with
    /// `prefix`.
    pub async fn list_runners(&self, owner: &str, repo: &str, prefix: &str) -> Result<Vec<Runner>> {
        let tok = self.token().await?;
        let mut out = Vec::new();
        let mut page = 1u32;
        loop {
            let url = format!(
                "{}/repos/{}/{}/actions/runners?per_page=100&page={}",
                self.api, owner, repo, page
            );
            let resp = self
                .http
                .get(&url)
                .bearer_auth(&tok)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .send()
                .await
                .context("GET runners")?;
            if !resp.status().is_success() {
                anyhow::bail!(
                    "list runners {}/{}: {} {}",
                    owner,
                    repo,
                    resp.status(),
                    resp.text().await.unwrap_or_default()
                );
            }
            let body: RunnersResp = resp.json().await?;
            let n = body.runners.len();
            for r in body.runners {
                if r.name.starts_with(prefix) {
                    out.push(r);
                }
            }
            if n < 100 {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    pub async fn delete_runner(&self, owner: &str, repo: &str, runner_id: u64) -> Result<()> {
        let tok = self.token().await?;
        let url = format!(
            "{}/repos/{}/{}/actions/runners/{}",
            self.api, owner, repo, runner_id
        );
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&tok)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await
            .context("DELETE runner")?;
        let s = resp.status();
        // 404 is a benign race: someone (e.g. a re-run of the runner) already
        // deregistered it. Treat as success.
        if !s.is_success() && s.as_u16() != 404 {
            anyhow::bail!(
                "delete runner {}/{} {}: {} {}",
                owner,
                repo,
                runner_id,
                s,
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }
}
