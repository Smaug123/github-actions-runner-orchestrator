//! Automatic signing-cache warmer (Phase 3c).
//!
//! When a workflow_job we run lands on a repo's default-branch *tip*, the
//! warmer rebuilds that flake on the host (the nix-daemon offloads the compile
//! to the trusted linux-builder) and copies the signed closure into the Mac
//! cache, so the next guest VM substitutes it instead of recompiling. It is
//! best-effort and fire-and-forget: every failure is logged at debug and never
//! touches the job that triggered it.
//!
//! This slice is the *decision* path — parse the candidate, coalesce the burst
//! of events one push emits, cap concurrency, and confirm the job really is the
//! live default-branch tip. The hardened build+sign (`run_warm`) is a stub here
//! and lands in the next slice, so the module is not yet wired into the
//! dispatch loop.
#![allow(dead_code)] // wired into the supervisor in a later slice

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tracing::debug;

use crate::config::Config;
use crate::github::event::WorkflowJob;
use crate::github::jit::{encode_path_segment, GhClient};

/// A default-branch-tip warm we have decided is worth attempting: the cheap,
/// synchronous pre-checks in `parse_candidate` have already passed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WarmCandidate {
    owner: String,
    repo: String,
    head_branch: String,
    head_sha: String,
}

/// Coalesce key: `(owner, repo, head_branch, head_sha)`. `head_branch` is part
/// of the key on purpose — coalescing happens *before* the default-branch
/// check, so a same-sha event on a non-default branch (e.g. the same commit
/// also being a feature/PR tip) must not record an entry that then suppresses
/// the real default-branch warm. Keying on the branch too keeps those events
/// distinct while still collapsing the many events one default-branch push
/// emits (all sharing `(owner, repo, default_branch, sha)`).
type CoalesceKey = (String, String, String, String);

impl WarmCandidate {
    fn coalesce_key(&self) -> CoalesceKey {
        (
            self.owner.clone(),
            self.repo.clone(),
            self.head_branch.clone(),
            self.head_sha.clone(),
        )
    }
}

/// Singleflight + recent-done guard. One push emits many `workflow_job` events
/// for the same tip, so collapse them to a single warm within `ttl`.
struct Coalescer {
    seen: Mutex<HashMap<CoalesceKey, Instant>>,
    ttl: Duration,
}

impl Coalescer {
    fn new(ttl: Duration) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Record `key` at `now` and return whether the caller should proceed.
    /// Returns false when a still-fresh entry exists (another warm for this tip
    /// is in flight or recently finished). Expired entries are pruned each call
    /// so the map can't grow without bound. A zero `ttl` disables coalescing
    /// (every call proceeds and the map stays empty).
    fn check_and_mark(&self, key: CoalesceKey, now: Instant) -> bool {
        let mut seen = self.seen.lock().expect("coalescer mutex poisoned");
        seen.retain(|_, t| now.saturating_duration_since(*t) < self.ttl);
        if seen.contains_key(&key) {
            return false;
        }
        seen.insert(key, now);
        true
    }
}

pub struct Warmer {
    gh: Arc<GhClient>,
    allowed_repos: Arc<HashSet<String>>,
    coalescer: Coalescer,
    sem: Semaphore,
}

impl Warmer {
    pub fn new(gh: Arc<GhClient>, allowed_repos: Arc<HashSet<String>>, config: &Config) -> Self {
        Self {
            gh,
            allowed_repos,
            coalescer: Coalescer::new(Duration::from_secs(config.warm_coalesce_ttl_secs)),
            // WARM_MAX_CONCURRENCY is validated >= 1 at startup; max(1) is a
            // defensive belt so a zero could never deadlock every warm.
            sem: Semaphore::new(config.warm_max_concurrency.max(1)),
        }
    }

    /// Cheap, synchronous entry point called from the dispatch loop for every
    /// job we run. Runs the no-network pre-checks and, if the job could be a
    /// default-branch-tip build, spawns a detached task to confirm and warm.
    /// Never blocks the caller and never returns an error.
    pub fn maybe_trigger(self: &Arc<Self>, event: &WorkflowJob) {
        let Some(cand) = parse_candidate(event, &self.allowed_repos) else {
            return;
        };
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.run_candidate(cand).await;
        });
    }

    async fn run_candidate(&self, cand: WarmCandidate) {
        // Cap concurrent warms; drop rather than queue so a burst can't pile up
        // unbounded behind the cap. A capacity drop is *retryable* — it records
        // nothing in the coalescer, so a later event for this tip (after a slot
        // frees) can still warm it.
        let Ok(_permit) = self.sem.try_acquire() else {
            debug!(
                owner = %cand.owner, repo = %cand.repo,
                "cache-warm: concurrency saturated; dropping"
            );
            return;
        };
        // Warm only a job that is the *current* tip of the repo's default
        // branch. default_branch is cached; both calls are best-effort and a
        // failure just skips this warm (again recording nothing, so a transient
        // lookup error doesn't suppress a retry).
        let default_branch = match self.gh.default_branch(&cand.owner, &cand.repo).await {
            Ok(b) => b,
            Err(e) => {
                debug!(
                    owner = %cand.owner, repo = %cand.repo, error = %format!("{e:#}"),
                    "cache-warm: default_branch lookup failed"
                );
                return;
            }
        };
        // Cheap filter before the second API call: a default-branch-tip build
        // necessarily ran against the default branch.
        if cand.head_branch != default_branch {
            debug!(
                owner = %cand.owner, repo = %cand.repo,
                head_branch = %cand.head_branch, default_branch = %default_branch,
                "cache-warm: job is not on the default branch"
            );
            return;
        }
        let tip = match self
            .gh
            .branch_tip(&cand.owner, &cand.repo, &default_branch)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                debug!(
                    owner = %cand.owner, repo = %cand.repo, error = %format!("{e:#}"),
                    "cache-warm: branch_tip lookup failed"
                );
                return;
            }
        };
        // The authoritative gate: the job's commit must still be the live tip.
        // A non-tip/stale commit just skips — we err toward not warming.
        if !tip.eq_ignore_ascii_case(&cand.head_sha) {
            debug!(
                owner = %cand.owner, repo = %cand.repo,
                head_sha = %cand.head_sha, tip = %tip,
                "cache-warm: job sha is not the default-branch tip"
            );
            return;
        }
        // Only now that we have a confirmed default-branch tip and a slot do we
        // record it: the burst of events one push emits collapses to one warm
        // (the atomic mark dedups any that pass concurrently), and the same tip
        // won't re-warm within the TTL. Marking here — not at entry — is what
        // keeps the drop/lookup-failure/non-tip paths above retryable.
        if !self
            .coalescer
            .check_and_mark(cand.coalesce_key(), Instant::now())
        {
            debug!(
                owner = %cand.owner, repo = %cand.repo, sha = %cand.head_sha,
                "cache-warm: coalesced (already warmed or in flight)"
            );
            return;
        }
        self.run_warm(&cand, &default_branch).await;
    }

    /// Build the flake at the default-branch tip and copy the signed closure
    /// into the Mac cache.
    ///
    /// STUB: the hardened token mint / netrc / private nix.conf / build / sign
    /// lands in the next slice. For now we only log the flakeref we would warm.
    async fn run_warm(&self, cand: &WarmCandidate, branch: &str) {
        let flakeref = build_flakeref(&cand.owner, &cand.repo, branch, &cand.head_sha);
        debug!(
            flakeref = %flakeref,
            "cache-warm: would warm (run_warm stub; build+sign lands in the next slice)"
        );
    }
}

/// Run the cheap, synchronous pre-checks and, if they pass, return the
/// candidate to warm. Returns None (skip silently) whenever the job can't be a
/// default-branch-tip build we own: head fields absent, sha malformed, repo not
/// allowlisted, or full_name not `owner/name`.
fn parse_candidate(event: &WorkflowJob, allowed: &HashSet<String>) -> Option<WarmCandidate> {
    let job = &event.workflow_job;
    let head_branch = job.head_branch.clone()?;
    let head_sha = job.head_sha.clone()?;
    if !is_commit_sha(&head_sha) {
        return None;
    }
    // The dispatch loop only calls us for already-allowlisted Run events, but
    // re-check by name (defence in depth) before we act on the repo at all.
    let full_name = &event.repository.full_name;
    if !allowed.contains(full_name) {
        return None;
    }
    let (owner, repo) = full_name.split_once('/')?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(WarmCandidate {
        owner: owner.to_string(),
        repo: repo.to_string(),
        head_branch,
        head_sha,
    })
}

/// A git commit id: exactly 40 hex digits. Asserted before the sha enters a
/// `?rev=` flakeref query (a threat-model requirement).
fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The flakeref the warmer fetches: the private repo at the default-branch tip,
/// pinned by both `ref` (the branch) and `rev` (the exact commit). The branch
/// is a live API value that can carry URL-reserved characters, so it is
/// percent-encoded into the query value (the unreserved-only encoding is valid
/// in a query too); the sha is validated 40-hex by the caller. The auth token
/// never rides this URL — it goes in a 0600 netrc (the next slice).
fn build_flakeref(owner: &str, repo: &str, branch: &str, sha: &str) -> String {
    format!(
        "git+https://github.com/{}/{}?ref={}&rev={}",
        owner,
        repo,
        encode_path_segment(branch),
        sha,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::event::{Repository, WorkflowJob, WorkflowJobInfo};

    fn event(full_name: &str, head_branch: Option<&str>, head_sha: Option<&str>) -> WorkflowJob {
        WorkflowJob {
            action: "queued".to_string(),
            workflow_job: WorkflowJobInfo {
                id: 1,
                run_id: 2,
                run_attempt: 0,
                head_branch: head_branch.map(String::from),
                head_sha: head_sha.map(String::from),
                name: "build".to_string(),
                labels: vec!["self-hosted".to_string()],
            },
            repository: Repository {
                id: 7,
                full_name: full_name.to_string(),
            },
        }
    }

    fn allowed(repos: &[&str]) -> HashSet<String> {
        repos.iter().map(|s| s.to_string()).collect()
    }

    const SHA: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    #[test]
    fn parse_candidate_accepts_a_well_formed_event() {
        let cand = parse_candidate(&event("o/r", Some("main"), Some(SHA)), &allowed(&["o/r"]))
            .expect("well-formed allowlisted event should parse");
        assert_eq!(cand.owner, "o");
        assert_eq!(cand.repo, "r");
        assert_eq!(cand.head_branch, "main");
        assert_eq!(cand.head_sha, SHA);
    }

    #[test]
    fn parse_candidate_rejects_missing_head_fields() {
        let a = allowed(&["o/r"]);
        assert!(parse_candidate(&event("o/r", None, Some(SHA)), &a).is_none());
        assert!(parse_candidate(&event("o/r", Some("main"), None), &a).is_none());
    }

    #[test]
    fn parse_candidate_rejects_malformed_sha() {
        let a = allowed(&["o/r"]);
        assert!(parse_candidate(&event("o/r", Some("main"), Some("deadbeef")), &a).is_none());
        assert!(parse_candidate(&event("o/r", Some("main"), Some(&"z".repeat(40))), &a).is_none());
    }

    #[test]
    fn parse_candidate_rejects_repo_outside_allowlist() {
        assert!(
            parse_candidate(&event("o/r", Some("main"), Some(SHA)), &allowed(&["x/y"])).is_none()
        );
    }

    #[test]
    fn parse_candidate_rejects_non_owner_name_full_name() {
        let a = allowed(&["weird"]);
        assert!(parse_candidate(&event("weird", Some("main"), Some(SHA)), &a).is_none());
    }

    #[test]
    fn is_commit_sha_checks_length_and_hex() {
        assert!(is_commit_sha(SHA));
        assert!(is_commit_sha(&"A".repeat(40))); // uppercase hex is fine
        assert!(!is_commit_sha(&"a".repeat(39)));
        assert!(!is_commit_sha(&"a".repeat(41)));
        assert!(!is_commit_sha(&"g".repeat(40)));
        assert!(!is_commit_sha(""));
    }

    #[test]
    fn build_flakeref_pins_ref_and_rev_and_encodes_branch() {
        assert_eq!(
            build_flakeref("o", "r", "main", SHA),
            format!("git+https://github.com/o/r?ref=main&rev={SHA}")
        );
        // A slashed branch must not split the path or query.
        assert_eq!(
            build_flakeref("o", "r", "release/1.0", SHA),
            format!("git+https://github.com/o/r?ref=release%2F1.0&rev={SHA}")
        );
    }

    fn key(owner: &str, repo: &str, branch: &str, sha: &str) -> CoalesceKey {
        (
            owner.to_string(),
            repo.to_string(),
            branch.to_string(),
            sha.to_string(),
        )
    }

    #[test]
    fn coalescer_dedups_within_ttl_and_reopens_after() {
        let c = Coalescer::new(Duration::from_secs(60));
        let k = key("o", "r", "main", SHA);
        let t0 = Instant::now();
        assert!(c.check_and_mark(k.clone(), t0), "first warm proceeds");
        assert!(
            !c.check_and_mark(k.clone(), t0),
            "a second event for the same tip is coalesced"
        );
        // A different tip sha is independent.
        assert!(
            c.check_and_mark(key("o", "r", "main", &"f".repeat(40)), t0),
            "a different sha proceeds"
        );
        // Past the TTL the same tip may warm again.
        let later = t0 + Duration::from_secs(61);
        assert!(c.check_and_mark(k, later), "expired entry reopens");
    }

    #[test]
    fn coalescer_keys_on_branch_so_same_sha_other_branch_does_not_suppress() {
        // A non-default-branch event for SHA X (seen first) must not suppress
        // the later default-branch warm for the same commit.
        let c = Coalescer::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(c.check_and_mark(key("o", "r", "feature", SHA), t0));
        assert!(
            c.check_and_mark(key("o", "r", "main", SHA), t0),
            "same sha on the default branch must still proceed"
        );
    }

    #[test]
    fn coalescer_zero_ttl_disables_coalescing() {
        let c = Coalescer::new(Duration::from_secs(0));
        let k = key("o", "r", "main", SHA);
        let t0 = Instant::now();
        assert!(c.check_and_mark(k.clone(), t0));
        assert!(c.check_and_mark(k, t0), "zero TTL never coalesces");
    }
}
