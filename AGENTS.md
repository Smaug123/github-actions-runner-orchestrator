# AGENTS.md

Tokio daemon that drains a [`gh-webhook-spool`](../gh-webhook-spool)
queue, mints repo-scoped JIT runners via a GitHub App, and runs each
`workflow_job` in an ephemeral Lima VM. macOS + Apple Silicon only.

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
src/gc.rs          — reconciler (stale cur/, orphan VMs, offline runners)
src/lima/mod.rs    — limactl wrapper; instance struct, timeouts, kill_on_drop
src/github/        — App JWT, installation tokens (account-scoped), JIT mint
                     (repo-scoped), repo-level runner list/delete
```

## Invariants — do not weaken

1. **HMAC re-verification on every claim.** The spool's HMAC ingress
   check protects against forged GitHub deliveries; ours protects
   against in-host tampering with `new/`. Don't drop or short-circuit
   `verify_signature`.
2. **VM names come from signed body fields only.** Envelope/delivery is
   **not** under the HMAC. Use `runner::vm_name(repo, job_id)`;
   `DeliveryId` is for logging and as a filename sanity check.
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
6. **`prepare()` is the only place that validates.** New consumers of
   spool data should go through it (or use the same primitives) so
   the validation stack stays in one place.
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
   No in-process durable state.

## Wire contract with the spool

The spool's envelope format and filename shape are a wire contract.
This consumer expects:

- Filename: `<workflow_job_id>.job` (parsed by `parse_spool_filename`,
  which returns the u64 id).
- Envelope `schema == 1`, fields: `schema, event, delivery, repo_id,
  repo, action, workflow_job_id, received_at_ms, signature`.

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
  `tokio`, `reqwest` (rustls), `serde`, `serde_json`, `clap`,
  `tracing`, `tracing-subscriber`, `notify`, `anyhow`, `hmac`, `sha2`,
  `hex`, `libc`, `jsonwebtoken`.
