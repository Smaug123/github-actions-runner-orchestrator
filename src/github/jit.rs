// Runner management, all repository-scoped.
//
// JIT configs are minted with the repo-scoped endpoint so a registered runner
// can only execute jobs from the repo we intended. Discovery (list) and
// cleanup (delete) are likewise repo-scoped: a personal account has no org
// runner groups, and runners registered against a repo live in that repo's
// default group (id 1). The runner-group concept is gone entirely.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::installation::{Installations, ScopedPermissions};

/// How long a repo's default branch is cached. It changes rarely, and the
/// warmer reads it on every candidate job, so a coarse TTL keeps us off the API
/// without risking a meaningfully stale answer.
const DEFAULT_BRANCH_TTL: Duration = Duration::from_secs(60 * 60);

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

/// A workflow_job as returned by the Actions jobs API. Used by the reconciler
/// to discover still-`queued` jobs and by the completion check to learn
/// whether a specific job has left the queue. `repo_id` is not part of the
/// jobs payload; `list_queued_jobs` stamps it from the parent run so callers
/// can build a faithful spool record.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct JobStatus {
    pub id: u64,
    pub status: String,
    #[serde(default)]
    pub run_id: u64,
    #[serde(default)]
    pub run_attempt: u64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub repo_id: u64,
}

#[derive(Deserialize)]
struct RunsResp {
    workflow_runs: Vec<WorkflowRun>,
}

#[derive(Deserialize)]
struct WorkflowRun {
    id: u64,
    repository: RunRepo,
}

#[derive(Deserialize)]
struct RunRepo {
    id: u64,
}

#[derive(Deserialize)]
struct RunJobsResp {
    jobs: Vec<JobStatus>,
}

/// `GET /repos/{owner}/{repo}` — only the default branch is of interest.
#[derive(Deserialize)]
struct RepoInfo {
    default_branch: String,
}

/// `GET /repos/{owner}/{repo}/branches/{branch}` — only the tip commit sha.
#[derive(Deserialize)]
struct BranchInfo {
    commit: BranchCommit,
}

#[derive(Deserialize)]
struct BranchCommit {
    sha: String,
}

struct CachedDefaultBranch {
    branch: String,
    // Wall-clock, not monotonic: a monotonic `Instant` freezes while the host
    // sleeps, so the entry would live for its whole TTL of *awake* time rather
    // than wall-clock time. Unlike the installation-token cache there is no
    // refresh margin — a stale branch name is benign (it's cross-checked
    // against the job's head_sha downstream), so we serve right up to expiry.
    valid_until: SystemTime,
}

impl CachedDefaultBranch {
    /// Still serveable iff its TTL hasn't elapsed in wall-clock time at `now`.
    /// Pure so the expiry check is unit-testable without a real clock.
    fn is_fresh_at(&self, now: SystemTime) -> bool {
        self.valid_until > now
    }
}

pub struct GhClient {
    api: String,
    http: Client,
    account: String,
    installations: Arc<Installations>,
    /// Per-repo default-branch cache (keyed `owner/repo`). Bounded by the
    /// allowlist the warmer queries; entries refresh on read past their TTL.
    default_branch_cache: Mutex<HashMap<String, CachedDefaultBranch>>,
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
            default_branch_cache: Mutex::new(HashMap::new()),
        }
    }

    async fn token(&self) -> Result<String> {
        self.installations.token(&self.account).await
    }

    /// Send an installation-token-authenticated request, retrying **once** if
    /// the cached token has gone stale.
    ///
    /// `build` produces the request afresh on each attempt — method + url (+
    /// body) only; this attaches the standard GitHub headers and the bearer
    /// token, so `build` must set neither. A 401 on the first attempt means the
    /// cached installation token is stale (revoked, permissions changed,
    /// installation suspended, or expired): we drop it (`invalidate`), re-mint,
    /// and retry the same request once. A second 401 is a real error the caller
    /// surfaces via its own status check.
    ///
    /// A failure to *mint* a token surfaces as `Err` from `token()` before any
    /// `Response` exists, so it never reaches the 401 path — minting is
    /// JWT-authed against the App key, where a 401 means bad credentials and a
    /// retry would be futile.
    async fn send_authed<F>(&self, ctx: &'static str, build: F) -> Result<reqwest::Response>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        fn stamp(rb: reqwest::RequestBuilder, tok: &str) -> reqwest::RequestBuilder {
            rb.header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .bearer_auth(tok)
        }
        let tok = self.token().await?;
        let resp = stamp(build(), &tok).send().await.context(ctx)?;
        if resp.status().as_u16() != 401 {
            return Ok(resp);
        }
        self.installations.invalidate(&tok).await;
        let tok = self.token().await?;
        stamp(build(), &tok).send().await.context(ctx)
    }

    /// Mint a token scoped to a single repository carrying only
    /// `contents: read`, for the cache warmer's private-flake fetch. Never
    /// cached; the caller writes it to a `0600` netrc and drops it after the
    /// build. Deliberately *not* the broad installation `token()`.
    #[allow(dead_code)] // consumed by the cache warmer (a later slice)
    pub async fn contents_read_token(&self, repo_id: u64) -> Result<String> {
        let perms = ScopedPermissions {
            contents: Some("read"),
        };
        self.installations
            .scoped_token(&self.account, &[repo_id], &perms)
            .await
    }

    /// The repository's default branch (e.g. `main`). Cached per-repo with a
    /// TTL — it changes rarely and the warmer reads it on every candidate job.
    /// Uses the installation token (`Metadata: read`, always granted).
    #[allow(dead_code)] // consumed by the cache warmer (a later slice)
    pub async fn default_branch(&self, owner: &str, repo: &str) -> Result<String> {
        let key = format!("{}/{}", owner, repo);
        {
            let cache = self.default_branch_cache.lock().await;
            if let Some(c) = cache.get(&key) {
                if c.is_fresh_at(SystemTime::now()) {
                    return Ok(c.branch.clone());
                }
            }
        }
        let url = format!("{}/repos/{}/{}", self.api, owner, repo);
        let resp = self
            .send_authed("GET /repos/{owner}/{repo}", || self.http.get(&url))
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "default_branch {}/{}: {} {}",
                owner,
                repo,
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        let body: RepoInfo = resp.json().await?;
        {
            let mut cache = self.default_branch_cache.lock().await;
            cache.insert(
                key,
                CachedDefaultBranch {
                    branch: body.default_branch.clone(),
                    valid_until: SystemTime::now() + DEFAULT_BRANCH_TTL,
                },
            );
        }
        Ok(body.default_branch)
    }

    /// The current tip commit sha of `branch`. The warmer compares this against
    /// the triggering job's `head_sha`, warming only a build that is still the
    /// live default-branch tip. `branch` is a live API value (not always
    /// `main`) and may contain URL-reserved characters, so it is
    /// percent-encoded into the path segment. Uses the installation token.
    #[allow(dead_code)] // consumed by the cache warmer (a later slice)
    pub async fn branch_tip(&self, owner: &str, repo: &str, branch: &str) -> Result<String> {
        let url = format!(
            "{}/repos/{}/{}/branches/{}",
            self.api,
            owner,
            repo,
            encode_path_segment(branch)
        );
        let resp = self
            .send_authed("GET /repos/{owner}/{repo}/branches/{branch}", || {
                self.http.get(&url)
            })
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "branch_tip {}/{} {}: {} {}",
                owner,
                repo,
                branch,
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        let body: BranchInfo = resp.json().await?;
        Ok(body.commit.sha)
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
            .send_authed("POST generate-jitconfig", || {
                self.http.post(&url).json(&body)
            })
            .await?;
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
        let mut out = Vec::new();
        let mut page = 1u32;
        loop {
            let url = format!(
                "{}/repos/{}/{}/actions/runners?per_page=100&page={}",
                self.api, owner, repo, page
            );
            let resp = self
                .send_authed("GET runners", || self.http.get(&url))
                .await?;
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

    /// Status of a single registered runner by id. `Ok(None)` on 404 — the
    /// runner is unknown to GitHub: an ephemeral runner whose JIT registration
    /// was reaped after its job went to a peer (or was cancelled) shows up this
    /// way, as does one not yet created. The dispatch watchdog uses this to tell
    /// a runner that is working (`busy`) or merely waiting (`online`, idle) from
    /// one whose registration is gone (offline or 404). Repo-scoped; uses the
    /// same self-hosted-runners read scope as `list_runners`/`delete_runner`.
    pub async fn runner_status(
        &self,
        owner: &str,
        repo: &str,
        runner_id: u64,
    ) -> Result<Option<Runner>> {
        let url = format!(
            "{}/repos/{}/{}/actions/runners/{}",
            self.api, owner, repo, runner_id
        );
        let resp = self
            .send_authed("GET runner", || self.http.get(&url))
            .await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "runner_status {}/{} {}: {} {}",
                owner,
                repo,
                runner_id,
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(Some(resp.json().await?))
    }

    pub async fn delete_runner(&self, owner: &str, repo: &str, runner_id: u64) -> Result<()> {
        let url = format!(
            "{}/repos/{}/{}/actions/runners/{}",
            self.api, owner, repo, runner_id
        );
        let resp = self
            .send_authed("DELETE runner", || self.http.delete(&url))
            .await?;
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

    /// Authoritative status of a single workflow_job. Returns `None` on 404
    /// (the job id is unknown to GitHub), which the completion check treats as
    /// "no longer queued". Requires the App's `Actions: read` permission.
    pub async fn job_status(
        &self,
        owner: &str,
        repo: &str,
        job_id: u64,
    ) -> Result<Option<JobStatus>> {
        let url = format!(
            "{}/repos/{}/{}/actions/jobs/{}",
            self.api, owner, repo, job_id
        );
        let resp = self.send_authed("GET job", || self.http.get(&url)).await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!(
                "job_status {}/{} {}: {} {}",
                owner,
                repo,
                job_id,
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(Some(resp.json().await?))
    }

    /// Every workflow_job in {owner}/{repo} currently in state `queued`.
    ///
    /// GitHub has no repo-wide jobs-by-status endpoint, so we enumerate active
    /// runs and expand their jobs. We scan only `queued` and `in_progress`
    /// runs: a job that is assignable to a runner is itself in state `queued`,
    /// and a run holding a queued job is therefore `queued` (nothing started)
    /// or `in_progress` (some jobs running, others — e.g. `needs:` dependents —
    /// just became eligible). Runs in `waiting`/`pending`/`requested` hold no
    /// runner-assignable jobs yet; when one becomes queued the run moves into a
    /// status we scan, so we don't miss it. Requires `Actions: read`.
    pub async fn list_queued_jobs(&self, owner: &str, repo: &str) -> Result<Vec<JobStatus>> {
        let mut out: Vec<JobStatus> = Vec::new();
        for status in ["queued", "in_progress"] {
            let mut page = 1u32;
            loop {
                let url = format!(
                    "{}/repos/{}/{}/actions/runs?status={}&per_page=100&page={}",
                    self.api, owner, repo, status, page
                );
                let resp = self.send_authed("GET runs", || self.http.get(&url)).await?;
                if !resp.status().is_success() {
                    anyhow::bail!(
                        "list runs {}/{} status={}: {} {}",
                        owner,
                        repo,
                        status,
                        resp.status(),
                        resp.text().await.unwrap_or_default()
                    );
                }
                let body: RunsResp = resp.json().await?;
                let n = body.workflow_runs.len();
                for run in body.workflow_runs {
                    for mut job in self.list_run_jobs(owner, repo, run.id).await? {
                        if job.status == "queued" {
                            job.repo_id = run.repository.id;
                            out.push(job);
                        }
                    }
                }
                if n < 100 {
                    break;
                }
                page += 1;
            }
        }
        // A run can surface under both status queries in the window where it
        // flips queued -> in_progress; dedup so we never mint twice for one job.
        out.sort_by_key(|j| j.id);
        out.dedup_by_key(|j| j.id);
        Ok(out)
    }

    /// All jobs for a single run (any status). Pagination mirrors
    /// `list_runners`. Each page is fetched through `send_authed`, so the
    /// cached installation token is reused (a lock + clone, not a network mint)
    /// and a mid-pagination 401 recovers instead of poisoning the rest.
    async fn list_run_jobs(&self, owner: &str, repo: &str, run_id: u64) -> Result<Vec<JobStatus>> {
        let mut out = Vec::new();
        let mut page = 1u32;
        loop {
            let url = format!(
                "{}/repos/{}/{}/actions/runs/{}/jobs?per_page=100&page={}",
                self.api, owner, repo, run_id, page
            );
            let resp = self
                .send_authed("GET run jobs", || self.http.get(&url))
                .await?;
            if !resp.status().is_success() {
                anyhow::bail!(
                    "list run jobs {}/{} run={}: {} {}",
                    owner,
                    repo,
                    run_id,
                    resp.status(),
                    resp.text().await.unwrap_or_default()
                );
            }
            let body: RunJobsResp = resp.json().await?;
            let n = body.jobs.len();
            out.extend(body.jobs);
            if n < 100 {
                break;
            }
            page += 1;
        }
        Ok(out)
    }
}

/// Percent-encode one URL path segment per RFC 3986: pass through only the
/// "unreserved" characters (`A-Z a-z 0-9 - . _ ~`) and `%XX`-escape every other
/// byte. Branch names arrive as live API values and can legitimately contain
/// `/`, `#`, `?`, `&`, `%` (`release/1.0`, `feat#42`); interpolated raw they
/// would split the path, open a query string, or otherwise corrupt the request
/// URL. Encoding everything non-unreserved keeps the value inside one segment.
/// (Also reused by the cache warmer for the flakeref `?ref=` query value — the
/// unreserved-only encoding is valid there too.)
pub(crate) fn encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            // write! to a String is infallible.
            _ => {
                let _ = write!(out, "%{:02X}", b);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed wall-clock instant well clear of the epoch to anchor TTL maths.
    fn base() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn default_branch_fresh_before_ttl() {
        let t = base();
        let c = CachedDefaultBranch {
            branch: "main".into(),
            valid_until: t + DEFAULT_BRANCH_TTL,
        };
        assert!(c.is_fresh_at(t));
    }

    #[test]
    fn default_branch_stale_after_wall_clock_advances_past_ttl() {
        // Regression for the sleep-freeze bug: an entry cached at T lives until
        // T+TTL of wall time. If the host sleeps and wakes past that, it must
        // read as stale. A monotonic clock froze during sleep, so the entry
        // survived its whole TTL of *awake* time instead.
        let cached = base();
        let c = CachedDefaultBranch {
            branch: "main".into(),
            valid_until: cached + DEFAULT_BRANCH_TTL,
        };
        let woke = cached + DEFAULT_BRANCH_TTL + Duration::from_secs(60);
        assert!(!c.is_fresh_at(woke));
    }

    #[test]
    fn parses_single_job_status() {
        let json = r#"{
            "id": 4242,
            "run_id": 99,
            "run_attempt": 2,
            "status": "in_progress",
            "conclusion": null,
            "name": "build",
            "labels": ["self-hosted", "lima-nix"]
        }"#;
        let j: JobStatus = serde_json::from_str(json).unwrap();
        assert_eq!(j.id, 4242);
        assert_eq!(j.run_id, 99);
        assert_eq!(j.run_attempt, 2);
        assert_eq!(j.status, "in_progress");
        assert_eq!(j.labels, vec!["self-hosted", "lima-nix"]);
        // repo_id is not in the payload; defaults to 0 until stamped.
        assert_eq!(j.repo_id, 0);
    }

    #[test]
    fn parses_job_status_with_missing_optionals() {
        // A trimmed payload (no run_attempt/labels) must still decode.
        let j: JobStatus = serde_json::from_str(r#"{"id":1,"status":"queued"}"#).unwrap();
        assert_eq!(j.id, 1);
        assert_eq!(j.status, "queued");
        assert_eq!(j.run_attempt, 0);
        assert!(j.labels.is_empty());
    }

    #[test]
    fn parses_runs_list_with_repo_id() {
        let json = r#"{
            "total_count": 1,
            "workflow_runs": [
                {"id": 555, "status": "queued", "repository": {"id": 7, "full_name": "o/r"}}
            ]
        }"#;
        let r: RunsResp = serde_json::from_str(json).unwrap();
        assert_eq!(r.workflow_runs.len(), 1);
        assert_eq!(r.workflow_runs[0].id, 555);
        assert_eq!(r.workflow_runs[0].repository.id, 7);
    }

    #[test]
    fn parses_repo_default_branch() {
        let r: RepoInfo =
            serde_json::from_str(r#"{"id":1,"default_branch":"trunk","private":true}"#).unwrap();
        assert_eq!(r.default_branch, "trunk");
    }

    #[test]
    fn parses_branch_tip_sha() {
        let json = r#"{
            "name": "main",
            "commit": {"sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "url": "..."},
            "protected": false
        }"#;
        let b: BranchInfo = serde_json::from_str(json).unwrap();
        assert_eq!(b.commit.sha, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    }

    #[test]
    fn percent_encodes_reserved_branch_chars() {
        // A slashed branch must stay one path segment.
        assert_eq!(encode_path_segment("release/1.0"), "release%2F1.0");
        // Other URL-reserved characters that git refs allow.
        assert_eq!(encode_path_segment("feat#42"), "feat%2342");
        assert_eq!(encode_path_segment("a&b"), "a%26b");
        // Unreserved characters pass through untouched.
        assert_eq!(encode_path_segment("main"), "main");
        assert_eq!(encode_path_segment("dependabot-_.~"), "dependabot-_.~");
    }

    #[test]
    fn parses_run_jobs_and_filters_queued() {
        let json = r#"{
            "total_count": 2,
            "jobs": [
                {"id": 1, "status": "queued", "labels": ["self-hosted","lima-nix"]},
                {"id": 2, "status": "completed", "labels": ["self-hosted","lima-nix"]}
            ]
        }"#;
        let r: RunJobsResp = serde_json::from_str(json).unwrap();
        let queued: Vec<u64> = r
            .jobs
            .into_iter()
            .filter(|j| j.status == "queued")
            .map(|j| j.id)
            .collect();
        assert_eq!(queued, vec![1]);
    }

    // ---- 401 invalidate-and-retry, end to end against a fake GitHub ----
    //
    // These exercise the real wiring — token mint, request, 401, cache
    // invalidation, re-mint, retry — that no unit test can stand in for.

    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex as StdMutex;
    use tokio::net::TcpListener;
    use zeroize::Zeroizing;

    #[derive(Clone)]
    struct Fake {
        /// How many installation tokens have been minted. Each mint returns a
        /// distinct `tok-N` so tests can prove the retry used a *fresh* token.
        mints: Arc<AtomicU64>,
        /// How many times the runners endpoint was hit.
        runner_hits: Arc<AtomicU64>,
        /// The `Authorization` header seen on each runners request, in order.
        auths: Arc<StdMutex<Vec<String>>>,
        /// If true, the runners endpoint 401s on *every* request; otherwise
        /// only the first, to model a single stale-token episode.
        always_401: bool,
    }

    async fn fake_installation() -> Json<serde_json::Value> {
        Json(serde_json::json!({ "id": 42 }))
    }

    async fn fake_mint(State(f): State<Fake>) -> Json<serde_json::Value> {
        let n = f.mints.fetch_add(1, Ordering::SeqCst) + 1;
        Json(serde_json::json!({
            "token": format!("tok-{n}"),
            "expires_at": "2099-01-01T00:00:00Z",
        }))
    }

    async fn fake_runners(
        State(f): State<Fake>,
        headers: HeaderMap,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        f.auths.lock().unwrap().push(auth);
        let hit = f.runner_hits.fetch_add(1, Ordering::SeqCst);
        if f.always_401 || hit == 0 {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "message": "Bad credentials" })),
            )
        } else {
            (StatusCode::OK, Json(serde_json::json!({ "runners": [] })))
        }
    }

    async fn spawn_fake(f: Fake) -> String {
        let router = Router::new()
            .route("/users/:account/installation", get(fake_installation))
            .route("/app/installations/:id/access_tokens", post(fake_mint))
            .route("/repos/:owner/:repo/actions/runners", get(fake_runners))
            .with_state(f);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{addr}")
    }

    fn client(base: &str) -> GhClient {
        let auth = super::super::installation::AppAuth {
            app_id: 42,
            pem: Arc::new(Zeroizing::new(super::super::app_jwt::TEST_PEM.to_vec())),
        };
        let http = reqwest::Client::new();
        let inst = Arc::new(Installations::new(base.to_string(), http.clone(), auth));
        GhClient::new(base.to_string(), http, "octocat".to_string(), inst)
    }

    fn fake(always_401: bool) -> Fake {
        Fake {
            mints: Arc::new(AtomicU64::new(0)),
            runner_hits: Arc::new(AtomicU64::new(0)),
            auths: Arc::new(StdMutex::new(Vec::new())),
            always_401,
        }
    }

    #[tokio::test]
    async fn retries_once_on_401_with_a_freshly_minted_token() {
        let f = fake(false);
        let base = spawn_fake(f.clone()).await;
        let c = client(&base);

        let runners = c.list_runners("octocat", "hello-world", "runner-").await;
        assert!(runners.is_ok(), "retry should recover: {runners:?}");
        assert!(runners.unwrap().is_empty());

        // One mint for the initial (stale) token, one after invalidation.
        assert_eq!(f.mints.load(Ordering::SeqCst), 2);
        let auths = f.auths.lock().unwrap();
        assert_eq!(auths.as_slice(), ["Bearer tok-1", "Bearer tok-2"]);
    }

    #[tokio::test]
    async fn reuses_cached_token_after_recovery() {
        let f = fake(false);
        let base = spawn_fake(f.clone()).await;
        let c = client(&base);

        // First call mints tok-1, 401s, invalidates, re-mints tok-2, succeeds.
        c.list_runners("octocat", "hello-world", "runner-")
            .await
            .unwrap();
        // Second call must reuse the cached tok-2 — no 401, so no new mint.
        c.list_runners("octocat", "hello-world", "runner-")
            .await
            .unwrap();

        assert_eq!(f.mints.load(Ordering::SeqCst), 2, "second call re-minted");
    }

    #[tokio::test]
    async fn bounded_retry_surfaces_a_persistent_401() {
        let f = fake(true);
        let base = spawn_fake(f.clone()).await;
        let c = client(&base);

        let res = c.list_runners("octocat", "hello-world", "runner-").await;
        assert!(res.is_err(), "a persistent 401 must surface as an error");
        // Exactly one retry: initial mint + one re-mint, and two requests. No
        // unbounded loop.
        assert_eq!(f.mints.load(Ordering::SeqCst), 2);
        assert_eq!(f.runner_hits.load(Ordering::SeqCst), 2);
    }
}
