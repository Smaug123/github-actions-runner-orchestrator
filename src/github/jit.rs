// Runner management. Org-level for discovery and GC (the App's view of all
// our runners lives at org scope), but JIT configs are minted with the
// repo-scoped endpoint so a registered runner can only execute jobs from
// the repo we intended. The runner group still gates which repos may use us;
// repo-scoped minting is the per-runner guarantee on top of that.

use std::sync::Arc;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;

use super::installation::Installations;

#[derive(Deserialize)]
struct RunnerGroup {
    id: u64,
    name: String,
}

#[derive(Deserialize)]
struct RunnerGroupsResp {
    runner_groups: Vec<RunnerGroup>,
}

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
    org: String,
    group_name: String,
    installations: Arc<Installations>,
    group_id: OnceCell<u64>,
}

impl GhClient {
    pub fn new(
        api: String,
        http: Client,
        org: String,
        group_name: String,
        installations: Arc<Installations>,
    ) -> Self {
        Self {
            api,
            http,
            org,
            group_name,
            installations,
            group_id: OnceCell::new(),
        }
    }

    async fn token(&self) -> Result<String> {
        self.installations.token(&self.org).await
    }

    pub async fn runner_group_id(&self) -> Result<u64> {
        let id = self
            .group_id
            .get_or_try_init(|| async {
                let tok = self.token().await?;
                let url = format!("{}/orgs/{}/actions/runner-groups", self.api, self.org);
                let resp = self
                    .http
                    .get(&url)
                    .bearer_auth(&tok)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .send()
                    .await
                    .context("GET runner-groups")?;
                if !resp.status().is_success() {
                    anyhow::bail!(
                        "list runner-groups: {} {}",
                        resp.status(),
                        resp.text().await.unwrap_or_default()
                    );
                }
                let body: RunnerGroupsResp = resp.json().await?;
                body.runner_groups
                    .iter()
                    .find(|g| g.name == self.group_name)
                    .map(|g| g.id)
                    .with_context(|| {
                        format!(
                            "no runner group named {} in org {}",
                            self.group_name, self.org
                        )
                    })
            })
            .await?;
        Ok(*id)
    }

    /// Mint a JIT runner config bound to a specific repository. A runner
    /// registered with this config can only execute jobs from {owner}/{repo}
    /// even if the underlying runner group permits other repos, so a
    /// workflow_job from one allowlisted repo can never capture a runner
    /// minted for another.
    pub async fn generate_jit_config(
        &self,
        owner: &str,
        repo: &str,
        name: &str,
        labels: &[&str],
    ) -> Result<JitConfigResp> {
        let tok = self.token().await?;
        let group_id = self.runner_group_id().await?;
        let url = format!(
            "{}/repos/{}/{}/actions/runners/generate-jitconfig",
            self.api, owner, repo
        );
        let body = GenerateJitConfigBody {
            name: name.to_string(),
            runner_group_id: group_id,
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

    /// Return all runners in the org whose name starts with `prefix`.
    pub async fn list_runners(&self, prefix: &str) -> Result<Vec<Runner>> {
        let tok = self.token().await?;
        let mut out = Vec::new();
        let mut page = 1u32;
        loop {
            let url = format!(
                "{}/orgs/{}/actions/runners?per_page=100&page={}",
                self.api, self.org, page
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
                    "list runners: {} {}",
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

    pub async fn delete_runner(&self, runner_id: u64) -> Result<()> {
        let tok = self.token().await?;
        let url = format!(
            "{}/orgs/{}/actions/runners/{}",
            self.api, self.org, runner_id
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
                "delete runner {}: {} {}",
                runner_id,
                s,
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }
}
