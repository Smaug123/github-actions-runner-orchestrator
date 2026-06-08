# AGENTS.md

Tokio daemon that drains a [`gh-webhook-spool`](../gh-webhook-spool)
queue, mints repo-scoped JIT runners via a GitHub App, and runs each
`workflow_job` in an ephemeral Lima VM. macOS + Apple Silicon only.

## Ethos — keep these goals in mind

Security-first, single-host infrastructure on one Apple Silicon Mac. The
choices below are deliberate, not incidental scaffolding — preserve them and
weigh new work against them.

- **Full-VM isolation is the point.** Jobs run untrusted code; a per-job vz VM
  (separate kernel, ephemeral, single-use) is the trust boundary. Containers
  share the host kernel — a downgrade. Defence in depth over convenience.
- **Don't reach for an orchestrator.** One host gives a scheduler nothing to
  schedule; k8s/ARC would either downgrade isolation (containers) or bolt on a
  cluster control plane that *widens* the trust surface — the opposite of the
  goal. **Less standing infrastructure is a feature.** This is not "a
  half-finished orchestrator," it's a deliberately small appliance. (Considered
  and rejected for this threat model + scale: ARC, Nomad+Lima, KubeVirt.)
- **Visibility is a first-class goal, not bloat.** Observability is how you
  notice when a paranoid system misbehaves, and the tool should be a joy to
  operate. Read-only views are welcome — build them well.
- **Where the "are we reinventing an orchestrator?" line sits:**
  - *Read-only observability* (status, queue, VMs, completed) → build freely;
    near-zero new authority or state.
  - *Mutating control* (priority reorder, kill buttons, requeue) → deliberate:
    each adds authority to a loopback no-auth endpoint and new invariants. Not
    free; justify it.
  - *Cross-host / scheduling / autoscaling* → don't. Needing it is the signal
    to re-evaluate adopting a real tool (and the platform), not to grow this
    binary.
- **Single-host, no HA, no near-term scaling are accepted tradeoffs.** If the
  laptop dies, CI stops — a conscious choice for a personal setup, not a gap to
  "fix" with clustering.

## Commands

```
nix develop --command cargo test
nix develop --command cargo clippy --tests -- -D warnings
nix develop --command cargo fmt
nix develop --command env RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
nix build              # release binary
```

## Layout

```
src/main.rs        — CLI parse, file-mode checks, startup self-check, ctrl_c
src/config.rs      — Config + validate() + ensure_paths() + perm helpers
src/spool.rs       — Spool (claim/finalize), read_spool_file, DeliveryId,
                     HMAC verify, file-shape filter, mtime stamp on claim
src/supervisor.rs  — dispatch loop; prepare() is the validation choke point
src/runner.rs      — per-job state machine; vm_name(repo, job_id)
src/gc.rs          — sweep (stale cur/, orphan VMs, offline runners) +
                     reconcile (mint for still-queued jobs lacking a runner)
src/warm.rs        — signing-cache warmer (3c, opt-in): on a default-branch tip,
                     drives warm-{cache,flake-inputs}.sh to sign the closure into
                     the Mac cache; build offloads to the trusted linux-builder
src/control.rs     — optional loopback HTTP control endpoint (pause/resume/status)
src/lima/mod.rs    — limactl wrapper; instance struct, timeouts, kill_on_drop
src/github/        — App JWT, installation tokens (account-scoped), JIT mint
                     (repo-scoped), repo-level runner list/delete
```

## Invariants — do not weaken

1. **HMAC re-verification on every claim.** The spool's HMAC ingress
   check protects against forged GitHub deliveries; ours protects
   against in-host tampering with `new/`. Don't drop or short-circuit
   `verify_signature`. (The reconciler's `write_synthetic_claim` records
   never come from `new/`; they carry an HMAC we compute ourselves over
   authenticated GitHub API data, so they stay re-verifiable.)
2. **VM names come from signed body fields only.** Envelope/delivery is
   **not** under the HMAC. Use `runner::vm_name(repo, job_id)`;
   `DeliveryId` is for logging and as a filename sanity check. The
   reconciler sources `workflow_job.id` from the authenticated Actions
   API instead of a signed body — at least as trustworthy — and feeds it
   through the same `vm_name`.
3. **Repo-scoped everything.** `generate_jit_config` hits
   `/repos/{owner}/{repo}/actions/runners/generate-jitconfig`; runner
   list/delete hit `/repos/{owner}/{repo}/actions/runners`. The
   per-runner repo binding is load-bearing — don't switch to org
   endpoints (there's no org/runner-group model here; repo runners use
   the default group, id 1). Installation lookup is account-scoped
   (`/users/{account}/installation`).
4. **Label policy is an allowlist.** Workflow labels must be a subset
   of `GH_RUNNER_LABELS`. The gate label (`GH_RUNNER_LABEL`) must be
   present and must itself be in the advertised set.
5. **Filesystem opens go through `O_NOFOLLOW | O_NONBLOCK` and fstat.**
   The lstat in `enumerate_new` is the cheap filter; the post-open
   fstat closes the TOCTOU window. Don't replace the open with
   `fs::read`.
6. **`prepare()` is the only place that validates spool data.** New
   consumers of `new/` data should go through it (or use the same
   primitives) so the validation stack stays in one place. The
   reconciler validates authenticated *API* data (not a spool file) and
   so does not route through `prepare()`; it shares only the label
   policy via `supervisor::classify_job_labels`.
7. **Credentials live behind mode checks.** `GH_APP_PRIVATE_KEY_FILE`
   and `GH_WEBHOOK_SECRET_FILE` must have mode 0600 (g/o = 0).
   `LIMA_TEMPLATE` must not be a symlink and must not be g/o-writable.
   `state/` and `spool/{cur,done,error}` are chmod 0700.
8. **Timeouts everywhere.** reqwest carries a per-request timeout;
   every `limactl` invocation runs under `tokio::time::timeout` +
   `kill_on_drop(true)`. The deadline for `Lima::shell` is
   `JOB_MAX_RUNTIME_SECS`.
9. **GC truth is cur/, not memory.** A daemon restart recovers by
   reading `cur/` bodies and the live `limactl list` + GH runner list.
   No in-process durable state. Reconciler-minted runners get a real
   `cur/` record (`write_synthetic_claim`), so they are GC-backed,
   teardown-eligible, and stale-expiring exactly like webhook-minted
   jobs — keep it that way rather than tracking them in memory.
10. **The warmer never signs guest-produced bytes.** `src/warm.rs`
    ingests an *untrusted* private flake and emits *trusted signed*
    bytes, so it builds on the **trusted `linux-builder`** (via the
    nix-daemon), never inside an ephemeral `gha-*` job VM, and never
    harvests/signs a guest's output. The untrusted-flake → signed-bytes
    crossing is held by the hardening in `run_warm` — scrubbed env,
    pinned trusted `PATH`, a private `nix.conf` (`require-sigs`, pinned
    substituters/keys, `accept-flake-config = false`,
    `allow-import-from-derivation = false`), a full-closure
    `aarch64-linux` check before building, and a down-scoped
    `contents:read` token on a `0600` netrc. Don't weaken any of these,
    and keep `maybe_trigger` best-effort/fire-and-forget so a warm can
    never block or fail the job that triggered it.

## Wire contract with the spool

The spool's envelope format and filename shape are a wire contract.
This consumer expects:

- Filename: `<workflow_job_id>.job` (parsed by `parse_spool_filename`,
  which returns the u64 id).
- Envelope `schema` in `1..=2`, fields: `schema, event, delivery,
  repo_id, repo, action, workflow_job_id, received_at_ms, signature`.

Of those, the signed (body-derived) fields are `repo_id, repo, action,
workflow_job_id`; we cross-check each against the parsed body after
HMAC verification succeeds. `event, delivery, received_at_ms` come
from headers / the spool itself and are not under HMAC — only use them
for logging and as a filename sanity check.

If the spool bumps `ENVELOPE_SCHEMA`, update `spool.rs` and bump our
validation in lockstep. Schema bumps are breaking changes.

## Tests

All in-module under `#[cfg(test)]`. `tempfile` is a dev-dep.
`supervisor::tests::test_config` builds a Config via
`Config::try_parse_from`; reuse it instead of constructing fields by
hand.

## Conventions

- Terse comments. Only write a comment when the WHY isn't obvious from
  the code.
- No emojis, no decorative headings in code.
- `anyhow` at the top level; constructed errors get a `.context(...)`
  string oriented around what we were doing, not the syscall.
- New deps need a reason. Current set is intentionally small:
  `tokio`, `reqwest` (rustls), `axum` (loopback control endpoint), `serde`,
  `serde_json`, `clap`, `tracing`, `tracing-subscriber`, `notify`, `anyhow`,
  `hmac`, `sha2`, `hex`, `libc`, `jsonwebtoken`.
