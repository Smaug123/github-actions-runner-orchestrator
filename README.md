# gh-actions-consumer

*Slop status: 100% vibecoded.*

Drains a [`gh-webhook-spool`](../gh-webhook-spool) queue and runs each
`workflow_job` we own in a one-shot Lima VM. Mints a JIT runner config
per job via a GitHub App, boots the VM, blocks on the runner, then tears
the VM down.

```
gh-webhook-spool/new/   ─►  gh-actions-consumer  ─►  limactl start <ephemeral VM>
       │                          │                          │
       │                          │                          ▼
       │                          │                   Runner.Listener (JIT)
       │                          ▼                          │
       └─────────►   cur/ → done/ │ error/  ◄────────────────┘
```

One VM per job, no reuse. The runner deregisters itself on a clean exit;
GC reaps anything left behind.

## Build and run

```
nix build && ./result/bin/gh-actions-consumer
# or
nix develop --command cargo build --release
```

## Configure

| Variable                  | Purpose                                                                  |
| ------------------------- | ------------------------------------------------------------------------ |
| `SPOOL_DIR`               | gh-webhook-spool root. We add `cur/`, `done/`, `error/` and chmod 0700.  |
| `STATE_DIR`               | Per-process working state (`$XDG_STATE_HOME/gh-actions-consumer`).       |
| `GH_APP_ID`               | GitHub App numeric ID.                                                   |
| `GH_APP_PRIVATE_KEY_FILE` | PEM. Refused unless mode is 0600.                                        |
| `GH_WEBHOOK_SECRET[_FILE]`| Same secret the spool uses. We re-verify HMAC on every claim.            |
| `GH_ALLOWED_REPOS`        | Comma-separated `owner/name` list. Required; empty refuses to start.     |
| `GH_ORG`                  | Account login (owner). For a personal account this is your username; it's the `owner` half of every allowlisted repo and is used to find the App installation. |
| `GH_RUNNER_LABEL`         | Gate label workflows put in `runs-on` (default `lima-nix`).              |
| `GH_RUNNER_LABELS`        | Complete advertised label set (default `self-hosted,lima-nix`).          |
| `LIMA_TEMPLATE`           | Lima YAML for the per-job VM. Refused if a symlink or g/o-writable.      |
| `LIMACTL_PATH`            | Absolute path to `limactl`. Refused if relative, group/world-writable, or owned by a foreign uid. |
| `MAX_CONCURRENCY`         | Default 4.                                                               |
| `JOB_MAX_RUNTIME_SECS`    | Hard ceiling per job. Default 6h.                                        |
| `GC_INTERVAL_SECS`        | Default 300.                                                             |
| `GH_API_TIMEOUT_SECS`     | Per-request HTTP timeout. Default 60.                                    |
| `GH_API_URL`              | API base. Override for GHES.                                             |
| `CONTROL_ADDR`            | Optional loopback HTTP control endpoint, e.g. `127.0.0.1:9100`. Unset disables it. Non-loopback is refused (no auth). See [Pausing](#pausing). |
| `RECONCILE_ENABLED`       | Default `true`. Enables the queued-job reconciler (see [Reconciler](#reconciler)). Needs the App's `Actions: read`; startup fails fast without it. |
| `RECONCILE_INTERVAL_SECS` | Default 60. Reconciler cadence; kept faster than `GC_INTERVAL_SECS` so a stolen job recovers promptly. |
| `JOB_COMPLETION_CHECK`    | Default `true`. Finalize a finished runner's spool entry only after GitHub confirms its job left `queued`; log a "steal" otherwise. |

## What we accept

A spool entry is run iff **all** of these hold:

- Filename is `<workflow_job_id>.job` (`u64` parses).
- File is a regular file (not a symlink, FIFO, dir).
- File is ≤ 6 MiB; envelope line ≤ 4 KiB.
- `envelope.schema` is 1 or 2.
- `verify_hmac(envelope.signature, body, GH_WEBHOOK_SECRET)` passes.
- `envelope.workflow_job_id == filename's id`.
- `envelope.repo` is in `GH_ALLOWED_REPOS`.
- Body cross-checks: `repo_id`, `repo`, `workflow_job_id`, `action`
  in the envelope all match the body.
- `envelope.event == "workflow_job"` and `body.action == "queued"`.
- `body.workflow_job.labels` includes `GH_RUNNER_LABEL` and is a subset
  of `GH_RUNNER_LABELS`.

Mismatches in the first group (filename / file type / size / schema /
HMAC / cross-check / allowlist) move the file to `error/` with a
sidecar `.err`. Mismatches in the second group (event / action /
labels) move it to `done/`. Failed jobs after we mint a runner also go
to `error/`.

## Runner identity

JIT runners are minted via the **repo-scoped** endpoint
(`/repos/{owner}/{repo}/actions/runners/generate-jitconfig`), so a
registered runner can only execute jobs from the repo we minted it for.
Repository runners always belong to the repo's default runner group
(id 1); there is no org runner-group concept here. Discovery and cleanup
are likewise repo-scoped (`/repos/{owner}/{repo}/actions/runners`),
swept once per repo in `GH_ALLOWED_REPOS`.

VM names are `gha-<workflow_job.id>` zero-padded to 16 hex chars, taken
from the signed body (and from the filename, which we cross-check
against the envelope and body). A replay produces the same VM name and
the second `limactl start` collides with the first — header data
(`delivery`) is **not** in the identity.

## Reconciler

GitHub assigns a queued job to **any** online, idle runner whose label set is a
superset of the job's labels — a JIT config does not bind a runner to a
specific `workflow_job_id`. So a runner we mint because we saw job A's `queued`
webhook can be handed an unrelated older queued job B in the same repo. If we
then retired A's spool entry just because *a* runner finished, A would be
stranded: still queued on GitHub, but its webhook spent. We avoid that with two
mechanisms, both authoritative against GitHub rather than against our own
webhook bookkeeping:

- **Authoritative completion** (`JOB_COMPLETION_CHECK`, default on). When a
  runner exits, we ask GitHub for its job's status before finalizing. If the
  job left `queued` (ran somewhere, including ran-and-failed) we archive to
  `done/`. If it's still `queued` — our runner ran someone else's job, a
  "steal" — we still archive to `done/` (the webhook delivery is spent and
  cannot be re-served from `new/`) and let the reconciler re-mint. On an API
  error we fail safe toward `done/` and rely on the reconciler. **Note:**
  `done/` therefore means "this webhook delivery is fully processed", not "this
  job left the queue".

- **Queued-job reconciler** (`RECONCILE_ENABLED`, default on). Every
  `RECONCILE_INTERVAL_SECS`, for each allowed repo, we list still-`queued`
  workflow_jobs from GitHub and mint a runner for any that lacks one (not
  backed by a live `cur/` entry or an online `gha-` runner), up to
  `MAX_CONCURRENCY`. This recovers stolen jobs, jobs whose Lima boot failed,
  and `queued` webhooks we never received. Reconciler mints are tracked by a
  **synthetic `cur/` record** built from authenticated API data and self-signed
  with the webhook secret, so GC, teardown, and stale-expiry treat them like
  any webhook-minted job. The reconciler skips while [paused](#pausing).

Runners stay fungible (the webhook fast-path keeps latency low; the reconciler
is the correctness backstop), so jobs may run in a shuffled order — but every
queued job eventually gets a runner and nothing is falsely retired.

This is the standard autoscaler model (treat GitHub's live queue as truth), so
it needs **no workflow changes**. A per-run dynamic `runs-on` label
(`run-${{ github.run_id }}-${{ github.run_attempt }}`) would additionally
*confine* each runner to one run and cut the wasted shuffle, but it's an
optional optimization, not required for correctness.

### Required App permission

The reconciler and completion check read workflow runs/jobs, which need the
App's **`Actions: read`** permission — distinct from the runner-admin rights
(`Administration: write`) used to mint and delete runners. Startup probes it
per allowed repo and fails fast if it's missing (or set `RECONCILE_ENABLED=false`).

## GC

Every `GC_INTERVAL_SECS` and once at startup:

- `cur/` entries older than `JOB_MAX_RUNTIME_SECS` (measured from the
  claim-time mtime) → `error/`.
- Any `gha-*` Lima VM not backed by a live `cur/` entry → `limactl stop
  && limactl delete`.
- For each repo in `GH_ALLOWED_REPOS`, any repo-side runner with the
  `gha-` prefix that is offline (or not busy) and not backed by a `cur/`
  entry → DELETE via API.

### Singleton: exactly one consumer per `SPOOL_DIR` (and per account, allowed repos)

The runner-cleanup branch treats *this* process's `cur/` as the only
source of truth for what `gha-<16hex>` runners ought to exist on each
allowlisted repo. **Do not run two consumers covering the same repo with
separate `SPOOL_DIR`s** — each would see the other's freshly-minted
(online, not yet busy) runners as orphans and delete them between mint
and job pickup.

The VM reaper (startup orphan reap + stale-image sweep) additionally
requires **exactly one consumer per `SPOOL_DIR`**. Running multiple
consumers against one shared `SPOOL_DIR` is **no longer supported**: each
would stop + delete the others' managed VMs (the startup reap deletes
*every* pre-existing `gha-<16hex>` VM; the stale-image sweep deletes any
whose booted image differs from *that* consumer's `LIMA_TEMPLATE`) and
finalize the others' live `cur/` claims to `error/`, failing their
in-flight jobs.

Safe configurations:

- One consumer process per repo (or per disjoint set of repos).
- Separate consumers covering *disjoint* repo sets, each with its own
  `SPOOL_DIR`.

There is no in-band guard for this; the launchd plist / deployment
harness is the right place to enforce singleton.

The reaper's reaping of a **claimed** VM (the startup orphan reap and the
stale-image sweep above) archives that job's `cur/` record to `error/` and
relies on the [reconciler](#reconciler) to re-mint it if GitHub still reports
it queued. It therefore **requires `RECONCILE_ENABLED=true`** (the default):
with reconciliation off, a claimed-but-still-queued job whose VM is reaped is
archived to `error/` and never re-run, so **startup refuses to run with
`RECONCILE_ENABLED=false`**.

## Pausing

Set `CONTROL_ADDR` (e.g. `127.0.0.1:9100`) to expose a tiny loopback HTTP
endpoint:

- `POST /pause` — stop claiming **new** jobs. In-flight VMs and the GC keep
  running; queued deliveries stay in `new/` until resume.
- `POST /resume` — start claiming again.
- `GET /status` — JSON `{paused, in_flight, max_concurrency}`.

The endpoint has no auth, so it must bind a loopback address (non-loopback is
refused at startup); the host boundary is the trust boundary.

The main use is a **clean shutdown / version migration** of the consumer
without orphaning work:

```
curl -XPOST localhost:9100/pause
# wait until nothing is in flight:
until [ "$(curl -s localhost:9100/status | jq .in_flight)" = 0 ]; do sleep 5; done
# now stop the consumer, deploy the new build, start it again
```

Keep the spool (and its tunnel) running throughout — webhooks land on the
spool, not the consumer, so deliveries during the consumer's downtime are
captured in `new/` and drained on restart. A blunt restart without pausing is
also safe for *queued* jobs, but abandons in-flight VMs (GC reaps them only
after `JOB_MAX_RUNTIME_SECS`).

### Shutdown signals

The same drain happens automatically on shutdown signals, so under launchd /
systemd you don't need the manual `pause` dance:

- **SIGTERM**, or the **first Ctrl+C** (SIGINT), pauses new claims and waits for
  in-flight VMs to finish, then exits cleanly — no orphaned VMs.
- A **second Ctrl+C** forces an immediate teardown, abandoning in-flight VMs
  (the next start's GC reaps them after `JOB_MAX_RUNTIME_SECS`).

There is no drain deadline: a stuck job holds shutdown open until its
`JOB_MAX_RUNTIME_SECS` watchdog fires, unless you send a second Ctrl+C or your
service manager escalates to SIGKILL. Under a service manager, set its stop
timeout accordingly.

## Guest VM

Whichever guest is used, the contract is the same: the consumer copies the
JIT config into the VM and runs `sudo gha-run-once /tmp/jit`, which reads the
config as root and execs the runner's `run.sh --jitconfig` as the unprivileged
`runner` user — one job, then the VM is destroyed.

### NixOS image (preferred)

`nix/guest.nix` declares the guest as a NixOS appliance — the runner, a
node24 toolchain, `gha-run-once`, the `lima`/`runner` users with passwordless
sudo, and the Lima boot contract (cloud-init NoCloud, a native lima-guestagent
service, `/bin/bash`). `lima/build-nixos-image.sh` builds it into a UEFI raw
image and emits a matching Lima template:

```
./lima/build-nixos-image.sh        # prints a LIMA_TEMPLATE=... path
```

It builds `.#gha-guest-image` for `aarch64-linux` (Nix offloads to the
`host-setup/linux-builder`, since the host is `aarch64-darwin`), copies the
image to `~/.local/share/gha-images/` (out of the GC-able Nix store), and
writes a template that boots it with **no per-job provisioning** — VMs are
ready in ~15s. Point `LIMA_TEMPLATE` at the emitted template and restart the
consumer; no code change. Re-run after editing `nix/guest.nix`.

Nix is part of the OS here, with `nix-command` + `flakes` enabled, so jobs run
`nix build` / `nix develop` / `nix flake …` directly. **Workflows targeting
this runner must not run a Nix installer** (e.g. `DeterminateSystems/nix-installer-action`):
it refuses on NixOS and would fight the daemon-managed, read-only `/etc/nix`.
Drop the install step. Store warmth comes from the shared substituter (planned,
Phase 3), not a per-job cache action.

The image is built with `systemd-repart` (not `make-disk-image`, whose nested
VM needs the `kvm` build feature unavailable on Apple Silicon). Because Lima's
runtime guest scripts assume an FHS distro, a few of its boot scripts fail
harmlessly on NixOS (so `systemctl is-system-running` reports `degraded`); the
parts the consumer needs — SSH, the guest agent, sudo, `gha-run-once` — are
provided declaratively and verified to work.

### Ubuntu template (interim)

`lima/runner-aarch64.yaml` boots a stock Ubuntu 24.04 aarch64 cloud image and
installs the runner + git + node via Lima provisioning on every boot.
`lima/build-prebuilt-image.sh` snapshots a provisioned boot into a reusable
image. The image is pinned to a dated Ubuntu release + digest; refresh it from
a newer `releases/24.04/release-YYYYMMDD/` (the file has a comment showing
how). Validate edits with `limactl validate lima/runner-aarch64.yaml`.

## See also

- [`DEFERRED.md`](DEFERRED.md) — work that hasn't landed yet
  (`/nix/store` sharing, Keychain integration, launchd plist, graceful
  shutdown, multi-arch, integration tests, guest image).
