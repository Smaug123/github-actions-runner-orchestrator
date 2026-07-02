//! Automatic signing-cache warmer (Phase 3c).
//!
//! When a workflow_job we run lands on a repo's default-branch *tip*, the
//! warmer rebuilds that flake on the host (the nix-daemon offloads the compile
//! to the trusted linux-builder) and copies the signed closure into the Mac
//! cache, so the next guest VM substitutes it instead of recompiling. It is
//! best-effort and fire-and-forget: every failure is logged at debug and never
//! touches the job that triggered it.
//!
//! This covers both the *decision* path — parse the candidate, coalesce the
//! burst of events one push emits, cap concurrency, and confirm the job really
//! is the live default-branch tip — and the hardened build+sign (`run_warm`):
//! an untrusted private flake is ingested under a scrubbed env, a private
//! nix.conf, a full-closure aarch64-linux check, and IFD disabled, then the
//! signed closure is copied into the Mac cache. `supervisor::run` builds one
//! `Warmer` when `CACHE_WARM_ENABLED` and calls `maybe_trigger` from its
//! `Prepared::Run` arm for every job it claims.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tracing::debug;

use crate::config::Config;
use crate::github::event::WorkflowJob;
use crate::github::jit::{encode_path_segment, GhClient};

/// The well-known cache.nixos.org public key. Pinned into the warmer's private
/// nix.conf alongside the Mac cache key so the hardened build can still verify
/// upstream-signed paths regardless of the host/daemon config.
const CACHE_NIXOS_ORG_KEY: &str = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";

/// The flake attributes we warm, in order. Both are forced to aarch64-linux;
/// warm-cache.sh additionally asserts the resolved derivation's system.
const WARM_TARGETS: [&str; 2] = [
    "devShells.aarch64-linux.default",
    "packages.aarch64-linux.default",
];

/// jq filter (run with `-e`) over `nix derivation show --recursive` JSON: true
/// iff *every* derivation in the closure is host-build-safe — `aarch64-linux`
/// (offloaded to the linux-builder) or `builtin` (Nix's internal hash-checked
/// fetchers, which run no attacker builder). Any other `.system` — notably the
/// host's own `aarch64-darwin` — yields false, so the warmer refuses to build.
const CLOSURE_SYSTEM_FILTER: &str =
    r#"all(.[]; .system == "aarch64-linux" or .system == "builtin")"#;

/// Monotonic per-attempt counter, mixed into each warm's scratch-dir name so
/// two overlapping warms of the same tip never share a directory.
static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(0);

/// A default-branch-tip warm we have decided is worth attempting: the cheap,
/// synchronous pre-checks in `parse_candidate` have already passed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WarmCandidate {
    owner: String,
    repo: String,
    /// Authenticated `repository.id` from the event, used to mint the
    /// down-scoped contents:read token. Authorized-by-name (the repo was
    /// allowlist-checked) and paired with `owner`/`repo` in the same
    /// faithful-copy-checked body.
    repo_id: u64,
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

    /// Drop `key` so the next `check_and_mark` for it proceeds immediately, but
    /// ONLY if the stored mark is still the one inserted at `marked`. Used when a
    /// marked warm failed *before* doing any build work, so a transient blip
    /// doesn't suppress retries of the same tip for the whole TTL.
    ///
    /// The `marked` guard matters because a slow pre-build failure can outlive
    /// `ttl`: by the time we clear, another event may have expired our entry and
    /// inserted its own (a newer in-flight warm). Removing unconditionally would
    /// delete that newer mark and let a third event start a duplicate warm. Two
    /// inserts for the same key are always >ttl apart (a within-ttl second event
    /// is coalesced, not inserted), so their `Instant`s never collide and the
    /// equality check unambiguously identifies our own mark.
    fn clear(&self, key: &CoalesceKey, marked: Instant) {
        let mut seen = self.seen.lock().expect("coalescer mutex poisoned");
        if seen.get(key) == Some(&marked) {
            seen.remove(key);
        }
    }
}

pub struct Warmer {
    gh: Arc<GhClient>,
    allowed_repos: Arc<HashSet<String>>,
    coalescer: Coalescer,
    sem: Semaphore,
    /// Canonical `nix` binary (validated under /nix/store). Its directory is
    /// pinned onto the child PATH, so `nix-store` (a sibling symlink) resolves
    /// there too.
    nix_bin: PathBuf,
    /// The two mac-cache scripts the warmer drives (validated trusted at startup).
    warm_flake_inputs_sh: PathBuf,
    warm_cache_sh: PathBuf,
    /// The real cache base + key name, passed to the scripts as GHA_CACHE_DIR /
    /// GHA_CACHE_KEY_NAME so the scrubbed HOME can't relocate them.
    cache_base: PathBuf,
    key_name: String,
    /// Holds `jq`; pinned onto the child PATH.
    tools_dir: PathBuf,
    /// Per-process private scratch lives under `<state_dir>/warm/`.
    state_dir: PathBuf,
    /// Pinned `substituters` / `trusted-public-keys` for the hardened build,
    /// resolved once at startup (the latter may be read from the cache pubkey).
    substituters: String,
    trusted_public_keys: String,
    /// Hard per-child timeout.
    timeout: Duration,
}

impl Warmer {
    /// Build the warmer from validated config. Fails only if a required path is
    /// somehow absent (it isn't post-`validate_cache_warm`) or the cache public
    /// key can't be read to pin `trusted-public-keys`.
    pub fn new(
        gh: Arc<GhClient>,
        allowed_repos: Arc<HashSet<String>>,
        config: &Config,
    ) -> Result<Self> {
        let require = |opt: &Option<PathBuf>, name: &str| -> Result<PathBuf> {
            opt.clone()
                .ok_or_else(|| anyhow::anyhow!("{name} is required when CACHE_WARM_ENABLED"))
        };
        let nix_bin = require(&config.nix_bin, "NIX_BIN")?;
        let mac_cache_dir = require(&config.mac_cache_dir, "MAC_CACHE_DIR")?;
        let cache_base = require(&config.warm_cache_base, "WARM_CACHE_BASE")?;
        let tools_dir = require(&config.warm_tools_dir, "WARM_TOOLS_DIR")?;

        let pubkey = cache_base
            .join("keys")
            .join(format!("{}.public", config.warm_cache_key_name));
        let trusted_public_keys =
            resolve_trusted_public_keys(&config.warm_trusted_public_keys, &pubkey)?;

        Ok(Self {
            gh,
            allowed_repos,
            coalescer: Coalescer::new(Duration::from_secs(config.warm_coalesce_ttl_secs)),
            // WARM_MAX_CONCURRENCY is validated >= 1 at startup; max(1) is a
            // defensive belt so a zero could never deadlock every warm.
            sem: Semaphore::new(config.warm_max_concurrency.max(1)),
            nix_bin,
            warm_flake_inputs_sh: mac_cache_dir.join("warm-flake-inputs.sh"),
            warm_cache_sh: mac_cache_dir.join("warm-cache.sh"),
            cache_base,
            key_name: config.warm_cache_key_name.clone(),
            tools_dir,
            state_dir: config.state_dir.clone(),
            substituters: config.warm_substituters.clone(),
            trusted_public_keys,
            // WARM_TIMEOUT_SECS is validated >= 1 at startup; max(1) is defensive.
            timeout: Duration::from_secs(config.warm_timeout_secs.max(1)),
        })
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
        let marked = Instant::now();
        if !self.coalescer.check_and_mark(cand.coalesce_key(), marked) {
            debug!(
                owner = %cand.owner, repo = %cand.repo, sha = %cand.head_sha,
                "cache-warm: coalesced (already warmed or in flight)"
            );
            return;
        }
        if !self.run_warm(&cand, &default_branch).await {
            // A pre-build transient failure (contents-token mint or workdir
            // setup) left nothing warmed. Drop *our* mark so a later event for
            // this same tip retries — matching the retryability of the drop/
            // lookup/non-tip paths above — instead of suppressing it for the
            // whole TTL. Passing `marked` ensures we only clear our own mark, not
            // a newer in-flight warm that replaced it if we ran past the TTL. A
            // failure *during* the build keeps the mark, so a persistently
            // failing build isn't re-attempted on every event.
            self.coalescer.clear(&cand.coalesce_key(), marked);
        }
    }

    /// Build the flake at the default-branch tip and copy the signed closure
    /// into the Mac cache. Best-effort throughout: each step is independent, and
    /// any failure is logged at debug and never propagates.
    ///
    /// Trust model: this ingests an *untrusted* private flake and emits
    /// *trusted signed* bytes, so every child runs with a scrubbed env, a pinned
    /// PATH of trusted dirs only, and a private nix.conf that pins
    /// substituters/trusted-keys + `accept-flake-config = false` +
    /// `require-sigs = true` + `allow-import-from-derivation = false` — a
    /// malicious `flake.nix` must not steer the build to substitute and re-sign
    /// attacker-prebuilt outputs, nor run host-side build code. The latter has
    /// two vectors, both closed before any host build can happen: IFD (an
    /// eval-time build, blocked by the config/argv pin) and a host-system
    /// *input* derivation smuggled into an otherwise-aarch64-linux target
    /// (rejected by the full-closure system check below, per target).
    /// Returns `true` once it reaches the build phase (whatever the per-target
    /// build outcomes), `false` on a pre-build transient failure (token mint or
    /// workdir setup). The caller uses that to decide whether to keep the
    /// coalescer mark: a pre-build blip should be retryable, a build attempt
    /// should stand so a persistently-failing build isn't re-run on every event.
    async fn run_warm(&self, cand: &WarmCandidate, branch: &str) -> bool {
        let flakeref = build_flakeref(&cand.owner, &cand.repo, branch, &cand.head_sha);

        // Down-scoped contents:read token for just this repo. Never the broad
        // installation token, never on the URL/argv — it rides a 0600 netrc.
        let token = match self.gh.contents_read_token(cand.repo_id).await {
            Ok(t) => t,
            Err(e) => {
                debug!(owner = %cand.owner, repo = %cand.repo, error = %format!("{e:#}"),
                    "cache-warm: contents token mint failed");
                return false;
            }
        };

        // Per-warm private scratch: 0600 netrc + private nix.conf under a fresh
        // HOME + the build gcroot out-links. Dropped (removed) on every exit, so
        // the token-bearing netrc never lingers. The directory is unique *per
        // attempt* (a process-wide counter), not per tip: coalescing can lapse
        // mid-build (a build outliving WARM_COALESCE_TTL_SECS, or TTL=0), so two
        // warms for the same tip may overlap — a shared dir would let one's
        // setup delete the other's netrc/out-links mid-build.
        let attempt = NEXT_ATTEMPT.fetch_add(1, Ordering::Relaxed);
        let slug = warm_slug(&cand.owner, &cand.repo, &cand.head_sha, attempt);
        let warm_parent = self.state_dir.join("warm");
        let netrc_path = warm_parent.join(&slug).join("netrc");
        let nix_conf =
            nix_conf_contents(&netrc_path, &self.substituters, &self.trusted_public_keys);
        let workdir = match WarmWorkdir::create(&warm_parent, &slug, &token, &nix_conf) {
            Ok(w) => w,
            Err(e) => {
                debug!(owner = %cand.owner, repo = %cand.repo, error = %format!("{e:#}"),
                    "cache-warm: workdir setup failed");
                return false;
            }
        };
        // The token is now only on disk (0600 netrc); drop the in-memory copy.
        drop(token);

        let env = self.child_env(&workdir);

        // (1) Seed the locked input sources FIRST: a cold/just-bumped flake.lock
        // makes the first `nix build` fetch inputs from codeload, exactly the
        // transient-502 case this script exists to fix. Best-effort.
        let _ = self
            .run_step(
                &self.warm_flake_inputs_sh,
                &[OsString::from(&flakeref)],
                &env,
                &workdir,
                "warm-flake-inputs.sh",
            )
            .await;

        // (2) Each target independently: build (which realises the closure
        // warm-cache.sh then copies+signs), then copy. A build failure skips
        // only that target's copy.
        for target in WARM_TARGETS {
            let installable = format!("{flakeref}#{target}");
            // Refuse unless the *entire* derivation closure is host-build-safe
            // BEFORE building. nix picks each derivation's builder from its own
            // `system`, not the attr path, so even when `<target>` itself is
            // aarch64-linux a malicious flake can smuggle an aarch64-darwin
            // *input* derivation that the nix-daemon would then build on this
            // macOS host. Checking only the selected derivation's `.system`
            // misses that; inspecting the whole closure catches it. Instantiation
            // is pure (IFD is disabled), so this runs no build, and warm-cache.sh
            // re-asserts the top-level system after the build.
            if !self
                .closure_is_host_build_safe(&installable, &env, &workdir)
                .await
            {
                debug!(installable = %installable,
                    "cache-warm: derivation closure has a non-host-build-safe system; skipping");
                continue;
            }
            let out_link = workdir.roots_dir().join(outlink_slug(target));
            if self
                .run_step(
                    &self.nix_bin,
                    &self.nix_build_args(&installable, &out_link),
                    &env,
                    &workdir,
                    "nix build",
                )
                .await
                .is_err()
            {
                continue;
            }
            let _ = self
                .run_step(
                    &self.warm_cache_sh,
                    &[OsString::from(&installable)],
                    &env,
                    &workdir,
                    "warm-cache.sh",
                )
                .await;
        }
        // workdir drops here: netrc unlinked, out-links (gcroots) released.
        true // reached the build phase; per-target outcomes don't unset the mark
    }

    /// Scrubbed environment for every warmer child: a private HOME/XDG_* (so the
    /// host user's nix.conf/netrc can't leak in), a PATH of trusted dirs only
    /// (the validated nix bin dir + the tools dir + the root-owned system dirs),
    /// and the real cache base/key for the scripts. NIX_CONFIG is absent (the
    /// children inherit only this map).
    fn child_env(&self, workdir: &WarmWorkdir) -> Vec<(String, String)> {
        let home = workdir.home();
        let nix_bin_dir = self.nix_bin.parent().unwrap_or(&self.nix_bin);
        // The two configured dirs are interpolated verbatim around the `:`
        // separators; both are validated colon-free at startup
        // (`reject_path_separator`), so neither can inject extra, unvalidated
        // PATH entries here.
        let path = format!(
            "{}:{}:/usr/bin:/bin:/usr/sbin:/sbin",
            nix_bin_dir.display(),
            self.tools_dir.display()
        );
        vec![
            ("HOME".into(), home.display().to_string()),
            (
                "XDG_CONFIG_HOME".into(),
                home.join(".config").display().to_string(),
            ),
            (
                "XDG_CACHE_HOME".into(),
                home.join(".cache").display().to_string(),
            ),
            (
                "XDG_DATA_HOME".into(),
                home.join(".local/share").display().to_string(),
            ),
            ("PATH".into(), path),
            (
                "GHA_CACHE_DIR".into(),
                self.cache_base.display().to_string(),
            ),
            ("GHA_CACHE_KEY_NAME".into(), self.key_name.clone()),
        ]
    }

    /// Argv for the warmer's own hardened `nix build`, threading the resolved
    /// substituter/key pins through the free `nix_build_args`.
    fn nix_build_args(&self, installable: &str, out_link: &Path) -> Vec<OsString> {
        nix_build_args(
            installable,
            out_link,
            &self.substituters,
            &self.trusted_public_keys,
        )
    }

    /// Spawn one warmer child under the scrubbed env, with stdio discarded, a
    /// hard timeout, and kill_on_drop. cwd is the private HOME (never a dir with
    /// a flake.nix, so a relative installable can't resolve against $PWD).
    /// Errors are logged at debug and returned so the caller can sequence
    /// dependent steps (build before copy).
    async fn run_step(
        &self,
        program: &Path,
        args: &[OsString],
        env: &[(String, String)],
        workdir: &WarmWorkdir,
        label: &'static str,
    ) -> Result<()> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .current_dir(workdir.home())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // Own process group (pgid == child pid) so a timeout can kill the
            // whole tree, not just the shell — `nix copy`/`nix flake archive`
            // descendants must not outlive the wrapper and keep mutating the
            // docroot (the scripts' lock records the shell PID, which a later
            // warm would otherwise see dead and reclaim mid-write).
            .process_group(0)
            .kill_on_drop(true);
        let mut child = cmd.spawn().with_context(|| format!("spawn {label}"))?;
        let pid = child.id();
        // Backstop the cancellation path: if this future is dropped mid-`wait`
        // the guard SIGKILLs the whole group; every path that *returns* below
        // reaps explicitly and then disarms it.
        let mut guard = KillGroupOnDrop::new(pid);
        let result = match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(status)) => Err(anyhow::anyhow!("{label} exited with {status}")),
            Ok(Err(e)) => Err(anyhow::Error::new(e).context(format!("wait {label}"))),
            Err(_) => {
                // Kill the whole process group (negative pid), then reap the
                // shell. kill_on_drop reaches only the direct child, so this is
                // what actually stops the nix descendants.
                kill_group(pid);
                let _ = child.wait().await;
                Err(anyhow::anyhow!(
                    "{label} timed out after {:?}",
                    self.timeout
                ))
            }
        };
        // The wait returned (the child is reaped on every arm), so the pid may
        // now be recycled — drop the group-kill backstop before it could fire.
        guard.disarm();
        if let Err(e) = &result {
            debug!(step = label, error = %format!("{e:#}"), "cache-warm: step failed");
        }
        result
    }

    /// Instantiate the full derivation closure of `installable` and return
    /// whether building it can run *no host-side build code*. Pure instantiation
    /// — it runs no build — so the caller can refuse before nix would build any
    /// host-system (e.g. aarch64-darwin) *input* derivation locally on this Mac.
    /// A `.system` check on only the selected derivation misses such a smuggled
    /// input; the recursive closure check catches it.
    ///
    /// "Host-build-safe" means every derivation's `.system` is either
    /// `aarch64-linux` (offloaded to the trusted linux-builder) or `builtin`
    /// (Nix's internal fixed-output fetchers — `builtin:fetchurl` etc. — which
    /// run hash-checked fetch code, not an attacker's builder, and which a real
    /// builder forged under `system = "builtin"` cannot impersonate: the host has
    /// no `builtin` platform, so such a derivation fails to build rather than
    /// running). Plain `fetchurl` sources show up as `builtin`, so requiring
    /// strict `aarch64-linux` would skip warming almost every real flake.
    ///
    /// `nix derivation show --recursive` emits the closure as JSON, which we
    /// stream through `jq -e` (see `CLOSURE_SYSTEM_FILTER`) so the (potentially
    /// large) JSON never lands in the warmer's address space — jq answers purely
    /// via its exit status, and we proceed only when *both* children exit 0 (nix
    /// instantiated cleanly and every system was host-build-safe). Returns false
    /// on any spawn/exit/timeout failure (err toward not warming).
    async fn closure_is_host_build_safe(
        &self,
        installable: &str,
        env: &[(String, String)],
        workdir: &WarmWorkdir,
    ) -> bool {
        let nix_args = nix_derivation_show_args(installable);
        let mut nix_cmd = Command::new(&self.nix_bin);
        nix_cmd
            .args(&nix_args)
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .current_dir(workdir.home())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true);
        let mut nix_child = match nix_cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                debug!(installable, error = %format!("{e:#}"),
                    "cache-warm: spawn nix derivation show failed");
                return false;
            }
        };
        // Cancellation/timeout backstop (see KillGroupOnDrop): fires for any
        // child not yet reaped when this future unwinds. Each guard is disarmed
        // the instant its child's `wait()` returns, so it never targets a pid
        // that has already been reaped and possibly recycled.
        let mut nix_guard = KillGroupOnDrop::new(nix_child.id());
        // Hand nix's stdout to jq's stdin. If the pipe can't be reparented,
        // return — nix_guard SIGKILLs the orphaned nix child (its closure may
        // include a host-side build that must never start) and kill_on_drop
        // reaps it.
        let jq_stdin: Stdio = match nix_child.stdout.take().and_then(|o| o.try_into().ok()) {
            Some(s) => s,
            None => return false,
        };
        let mut jq_cmd = Command::new(self.tools_dir.join("jq"));
        jq_cmd
            // `-e` sets the exit status from the last output: 0 only when every
            // derivation's system was host-build-safe (so the filter prints
            // `true`).
            .args(["-e", CLOSURE_SYSTEM_FILTER])
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .current_dir(workdir.home())
            .stdin(jq_stdin)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true);
        let mut jq_child = match jq_cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                debug!(installable, error = %format!("{e:#}"),
                    "cache-warm: spawn jq failed");
                return false;
            }
        };
        let mut jq_guard = KillGroupOnDrop::new(jq_child.id());
        // jq must read the whole input to decide `all`, so awaiting it first
        // drains the pipe and lets nix finish; then reap nix for its own status.
        // Disarm each guard as soon as its child is reaped.
        let both = async {
            let jq_status = jq_child.wait().await;
            jq_guard.disarm();
            let nix_status = nix_child.wait().await;
            nix_guard.disarm();
            (nix_status, jq_status)
        };
        // On timeout or a wait error the still-armed guards SIGKILL their groups
        // as this future unwinds, and kill_on_drop reaps the direct children.
        matches!(
            tokio::time::timeout(self.timeout, both).await,
            Ok((Ok(nix_status), Ok(jq_status))) if nix_status.success() && jq_status.success()
        )
    }
}

/// A per-warm private scratch directory under `<state_dir>/warm/`: holds the
/// 0600 netrc, the private nix.conf (at `home/.config/nix/nix.conf`), and the
/// build gcroot out-links (`roots/`). Removed on drop so the token-bearing
/// netrc never outlives the warm.
struct WarmWorkdir {
    root: PathBuf,
}

impl WarmWorkdir {
    fn create(parent: &Path, slug: &str, token: &str, nix_conf: &str) -> Result<Self> {
        // `<state_dir>/warm/` is created lazily on the first warm; ensure it
        // exists (0700) before the single-level slug dir below.
        create_dir_all_0700(parent)?;
        let root = parent.join(slug);
        // The slug is unique per attempt within a process, so a collision only
        // happens across a restart (the counter resets) against a leftover dir
        // from the now-dead process — safe to clear.
        let _ = std::fs::remove_dir_all(&root);
        let wd = Self { root };
        create_dir_0700(&wd.root)?;
        let nix_conf_dir = wd.home().join(".config").join("nix");
        create_dir_all_0700(&nix_conf_dir)?;
        create_dir_0700(&wd.roots_dir())?;
        write_file_0600(&wd.netrc(), netrc_contents(token).as_bytes())?;
        write_file_0600(&nix_conf_dir.join("nix.conf"), nix_conf.as_bytes())?;
        Ok(wd)
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }
    fn netrc(&self) -> PathBuf {
        self.root.join("netrc")
    }
    fn roots_dir(&self) -> PathBuf {
        self.root.join("roots")
    }
}

impl Drop for WarmWorkdir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
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
        repo_id: event.repository.id,
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

/// Argv for the warmer's own hardened `nix build`. The pins repeat the private
/// nix.conf (belt + braces) so they hold even if `ci` is a nix trusted-user on
/// the host, where a flake's nixConfig could otherwise take effect —
/// `allow-import-from-derivation = false` among them, so an IFD derivation can't
/// build host-side during the build's own eval.
fn nix_build_args(
    installable: &str,
    out_link: &Path,
    substituters: &str,
    trusted_public_keys: &str,
) -> Vec<OsString> {
    vec![
        "build".into(),
        installable.into(),
        "--out-link".into(),
        out_link.into(),
        "--no-update-lock-file".into(),
        "--no-registries".into(),
        "--extra-experimental-features".into(),
        "nix-command flakes".into(),
        "--option".into(),
        "accept-flake-config".into(),
        "false".into(),
        "--option".into(),
        "flake-registry".into(),
        "".into(),
        "--option".into(),
        "allow-import-from-derivation".into(),
        "false".into(),
        "--option".into(),
        "require-sigs".into(),
        "true".into(),
        "--option".into(),
        "substituters".into(),
        substituters.into(),
        "--option".into(),
        "trusted-public-keys".into(),
        trusted_public_keys.into(),
    ]
}

/// Argv for `nix derivation show --recursive <installable>` under the same
/// flake-purity pins as the build (minus the build-only substituter/sig options
/// instantiation doesn't use), plus `allow-import-from-derivation = false` so
/// instantiating the closure runs no host-side build. Emits the whole closure as
/// JSON, used to confirm every derivation's `.system` before building.
fn nix_derivation_show_args(installable: &str) -> Vec<OsString> {
    vec![
        "derivation".into(),
        "show".into(),
        "--recursive".into(),
        installable.into(),
        "--no-update-lock-file".into(),
        "--no-registries".into(),
        "--extra-experimental-features".into(),
        "nix-command flakes".into(),
        "--option".into(),
        "accept-flake-config".into(),
        "false".into(),
        "--option".into(),
        "flake-registry".into(),
        "".into(),
        "--option".into(),
        "allow-import-from-derivation".into(),
        "false".into(),
    ]
}

/// The netrc the warmer writes (0600) for the private-flake fetch. The token is
/// an installation token, so the libgit2 `git+https://github.com/...` fetch
/// authenticates as `x-access-token`. Never logged, never on the URL/argv.
fn netrc_contents(token: &str) -> String {
    format!("machine github.com login x-access-token password {token}\n")
}

/// The private nix.conf every warmer child inherits (via HOME/XDG_CONFIG_HOME).
/// This is the load-bearing hardening: `require-sigs` and the pinned
/// substituters/trusted-keys stop a malicious flake from laundering an
/// attacker-built/unsigned path into a Mac-signed one, `accept-flake-config
/// = false` + an empty `flake-registry` stop its nixConfig from adding its own,
/// and `allow-import-from-derivation = false` stops a malicious flake from
/// forcing a host-side build *during evaluation*: import-from-derivation makes
/// `nix eval` / `nix flake archive` / the eval inside `nix build` realise an
/// imported derivation before any `.system` check runs, and an aarch64-darwin
/// IFD derivation would build on this macOS host. Because every child nix
/// process inherits this config, the pin covers the scripts' internal nix calls
/// too. (A flake that genuinely needs IFD simply won't warm — best-effort.)
fn nix_conf_contents(netrc_path: &Path, substituters: &str, trusted_public_keys: &str) -> String {
    format!(
        "netrc-file = {}\n\
         accept-flake-config = false\n\
         flake-registry = \n\
         allow-import-from-derivation = false\n\
         require-sigs = true\n\
         substituters = {}\n\
         trusted-public-keys = {}\n\
         experimental-features = nix-command flakes\n",
        netrc_path.display(),
        substituters,
        trusted_public_keys,
    )
}

/// Resolve the pinned `trusted-public-keys`: an explicit operator override wins;
/// otherwise the Mac cache pubkey (read from `<base>/keys/<name>.public`) plus
/// the well-known cache.nixos.org key, so the build can verify both caches.
fn resolve_trusted_public_keys(configured: &str, mac_pubkey_file: &Path) -> Result<String> {
    if !configured.trim().is_empty() {
        return Ok(configured.trim().to_string());
    }
    let raw = std::fs::read_to_string(mac_pubkey_file)
        .with_context(|| format!("read cache public key {}", mac_pubkey_file.display()))?;
    let mac = raw.trim();
    if mac.is_empty() {
        anyhow::bail!("cache public key {} is empty", mac_pubkey_file.display());
    }
    Ok(format!("{mac} {CACHE_NIXOS_ORG_KEY}"))
}

/// A filesystem-safe, per-*attempt* directory name. `owner`/`repo`/`sha` are
/// already constrained (GitHub names; 40-hex sha), but sanitise defensively so
/// the name is always a single safe component. `attempt` (a process-wide
/// counter) keeps two overlapping warms of the same tip in distinct dirs, so
/// one's setup can't delete the other's scratch.
fn warm_slug(owner: &str, repo: &str, sha: &str, attempt: u64) -> String {
    let safe = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    format!("{}-{}-{}-{}", safe(owner), safe(repo), safe(sha), attempt)
}

/// Out-link basename for a warm target — a short stable label per attribute.
fn outlink_slug(target: &str) -> &'static str {
    if target.starts_with("devShells.") {
        "devshell"
    } else {
        "pkg"
    }
}

/// SIGKILL the process group led by `pid` (warmer children are spawned with
/// `process_group(0)`, so their pgid equals their own pid). A no-op when `pid`
/// is None. Used to reap a child *and its nix descendants* on timeout — plain
/// `kill_on_drop` reaches only the direct child.
fn kill_group(pid: Option<u32>) {
    if let Some(pid) = pid {
        // SAFETY: kill(2) with a negative pid signals the process group whose
        // id is `pid` (the child is its own group leader, set above).
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }
}

/// RAII backstop that SIGKILLs a warmer child's process group on drop, unless
/// `disarm`ed first. `kill_on_drop(true)` reaps only the *direct* child, so when
/// a warm task is cancelled mid-await (the future is dropped — e.g. at daemon
/// shutdown), a `nix copy` / `nix flake archive` descendant would otherwise keep
/// running and mutating the cache after the lock-owner PID is gone. Armed at
/// spawn with the child's pid (== its pgid); the caller `disarm`s it once the
/// `wait()` has *returned* (every completing path reaps explicitly), so the
/// group-kill fires only on the cancellation path and never against a pid that
/// has already been reaped and possibly recycled.
struct KillGroupOnDrop(Option<u32>);

impl KillGroupOnDrop {
    fn new(pid: Option<u32>) -> Self {
        Self(pid)
    }
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for KillGroupOnDrop {
    fn drop(&mut self) {
        kill_group(self.0);
    }
}

fn create_dir_0700(p: &Path) -> Result<()> {
    std::fs::create_dir(p).with_context(|| format!("create {}", p.display()))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", p.display()))
}

fn create_dir_all_0700(p: &Path) -> Result<()> {
    std::fs::create_dir_all(p).with_context(|| format!("create {}", p.display()))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", p.display()))
}

/// Write `bytes` to `p` with mode 0600, failing if `p` already exists (the
/// per-warm dir is freshly created, so a collision means something is wrong).
fn write_file_0600(p: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)
        .with_context(|| format!("create {}", p.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("write {}", p.display()))
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
        assert_eq!(cand.repo_id, 7);
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
    fn coalescer_clear_allows_immediate_retry() {
        // A pre-build warm failure clears our mark so the same tip retries at
        // once, rather than being suppressed for the whole TTL.
        let c = Coalescer::new(Duration::from_secs(60));
        let k = key("o", "r", "main", SHA);
        let t0 = Instant::now();
        assert!(c.check_and_mark(k.clone(), t0), "first warm proceeds");
        assert!(!c.check_and_mark(k.clone(), t0), "same tip is coalesced");
        c.clear(&k, t0);
        assert!(
            c.check_and_mark(k, t0),
            "after clear the same tip may warm again immediately"
        );
    }

    #[test]
    fn coalescer_clear_leaves_a_newer_mark_intact() {
        // A slow pre-build failure can outlive the TTL: by the time it clears,
        // another event has expired the old entry and marked a fresh in-flight
        // warm. clear(marked=old) must NOT remove that newer mark, or a third
        // event would start a duplicate concurrent warm.
        let c = Coalescer::new(Duration::from_secs(60));
        let k = key("o", "r", "main", SHA);
        let t0 = Instant::now();
        assert!(c.check_and_mark(k.clone(), t0), "first warm proceeds");
        // A later event past the TTL replaces the entry with its own mark.
        let t1 = t0 + Duration::from_secs(61);
        assert!(c.check_and_mark(k.clone(), t1), "expired entry reopens");
        // The first warm now fails pre-build and clears with its OLD mark time.
        c.clear(&k, t0);
        // The newer mark must survive, so a third event is still coalesced.
        assert!(
            !c.check_and_mark(k, t1),
            "the newer in-flight mark must not have been cleared"
        );
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

    #[test]
    fn netrc_contents_uses_x_access_token() {
        assert_eq!(
            netrc_contents("ghs_secret"),
            "machine github.com login x-access-token password ghs_secret\n"
        );
    }

    #[test]
    fn nix_conf_pins_the_hardening() {
        let conf = nix_conf_contents(
            Path::new("/state/warm/o-r-sha/netrc"),
            "http://127.0.0.1:8080 https://cache.nixos.org",
            "k1 k2",
        );
        assert!(conf.contains("netrc-file = /state/warm/o-r-sha/netrc\n"));
        assert!(conf.contains("accept-flake-config = false\n"));
        assert!(conf.contains("flake-registry = \n"));
        assert!(conf.contains("allow-import-from-derivation = false\n"));
        assert!(conf.contains("require-sigs = true\n"));
        assert!(conf.contains("substituters = http://127.0.0.1:8080 https://cache.nixos.org\n"));
        assert!(conf.contains("trusted-public-keys = k1 k2\n"));
    }

    #[test]
    fn resolve_trusted_keys_prefers_explicit_then_derives() {
        let dir = tempfile::tempdir().unwrap();
        let pub_file = dir.path().join("gha-mac-cache-1.public");
        std::fs::write(&pub_file, "gha-mac-cache-1:AAAA\n").unwrap();
        // Explicit override wins and is trimmed.
        assert_eq!(
            resolve_trusted_public_keys("  override-key  ", &pub_file).unwrap(),
            "override-key"
        );
        // Empty -> derive: Mac pubkey (trimmed) + cache.nixos.org.
        assert_eq!(
            resolve_trusted_public_keys("", &pub_file).unwrap(),
            format!("gha-mac-cache-1:AAAA {CACHE_NIXOS_ORG_KEY}")
        );
        // Missing pubkey file -> error (only when deriving).
        assert!(resolve_trusted_public_keys("", &dir.path().join("nope")).is_err());
    }

    #[test]
    fn warm_slug_is_a_single_safe_component_with_attempt() {
        assert_eq!(warm_slug("o", "r", SHA, 3), format!("o-r-{SHA}-3"));
        // Anything outside [A-Za-z0-9._-] is replaced (defensive).
        assert_eq!(warm_slug("a/b", "c d", "e:f", 0), "a_b-c_d-e_f-0");
    }

    #[test]
    fn outlink_slug_distinguishes_the_targets() {
        assert_eq!(outlink_slug("devShells.aarch64-linux.default"), "devshell");
        assert_eq!(outlink_slug("packages.aarch64-linux.default"), "pkg");
    }

    /// Assert `args` carries an `--option <key> <value>` triple.
    fn assert_option(args: &[String], key: &str, value: &str) {
        let i = args
            .iter()
            .position(|a| a == key)
            .unwrap_or_else(|| panic!("missing option {key}"));
        assert!(i > 0 && args[i - 1] == "--option", "{key} not an --option");
        assert_eq!(args[i + 1], value, "{key} value");
    }

    #[test]
    fn nix_derivation_show_args_recurses_and_pins_purity_and_no_ifd() {
        let args: Vec<String> = nix_derivation_show_args("flakeref#pkg")
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(&args[0..3], &["derivation", "show", "--recursive"]);
        assert!(args.contains(&"flakeref#pkg".to_string()));
        assert!(args.contains(&"--no-update-lock-file".to_string()));
        assert!(args.contains(&"--no-registries".to_string()));
        // Pinned false so the closure instantiation runs no host-side build.
        assert_option(&args, "accept-flake-config", "false");
        assert_option(&args, "allow-import-from-derivation", "false");
    }

    #[test]
    fn closure_system_filter_admits_builtin_fetchers() {
        // The gate must accept `builtin` (Nix's internal fixed-output fetchers,
        // e.g. plain `fetchurl`) alongside `aarch64-linux`, or it would skip
        // warming almost every real flake — while still excluding the host's
        // own `aarch64-darwin` so a smuggled host-side build is refused.
        assert!(CLOSURE_SYSTEM_FILTER.contains(r#".system == "aarch64-linux""#));
        assert!(CLOSURE_SYSTEM_FILTER.contains(r#".system == "builtin""#));
        assert!(!CLOSURE_SYSTEM_FILTER.contains("aarch64-darwin"));
    }

    #[test]
    fn nix_build_args_disable_ifd() {
        let args: Vec<String> = nix_build_args("flakeref#pkg", Path::new("/o"), "subs", "keys")
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        // The argv belt repeats the nix.conf IFD pin so it holds even if `ci` is
        // a nix trusted-user where a flake's nixConfig could otherwise apply.
        assert_option(&args, "allow-import-from-derivation", "false");
        assert_option(&args, "require-sigs", "true");
    }

    #[test]
    fn warm_workdir_writes_0600_netrc_and_cleans_up_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        // `warm/` does not exist yet — exercises the lazy parent creation.
        let parent = dir.path().join("warm");
        let root;
        {
            let wd = WarmWorkdir::create(&parent, "o-r-sha", "tok", "netrc-file = x\n").unwrap();
            root = wd.root.clone();
            // The token-bearing netrc is 0600 and carries the credential line.
            let netrc_md = std::fs::metadata(wd.netrc()).unwrap();
            assert_eq!(netrc_md.permissions().mode() & 0o777, 0o600);
            assert!(std::fs::read_to_string(wd.netrc())
                .unwrap()
                .contains("x-access-token password tok"));
            // The private nix.conf lands where HOME/XDG_CONFIG_HOME point nix.
            assert_eq!(
                std::fs::read_to_string(wd.home().join(".config/nix/nix.conf")).unwrap(),
                "netrc-file = x\n"
            );
            assert!(wd.roots_dir().is_dir());
            // The slug dir itself is private.
            assert_eq!(
                std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        // Dropped: the whole tree (netrc included) is gone.
        assert!(!root.exists());
    }
}
