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

## What we accept

A spool entry is run iff **all** of these hold:

- Filename is `<workflow_job_id>.job` (`u64` parses).
- File is a regular file (not a symlink, FIFO, dir).
- File is ≤ 6 MiB; envelope line ≤ 4 KiB.
- `envelope.schema == 1`.
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

## GC

Every `GC_INTERVAL_SECS` and once at startup:

- `cur/` entries older than `JOB_MAX_RUNTIME_SECS` (measured from the
  claim-time mtime) → `error/`.
- Any `gha-*` Lima VM not backed by a live `cur/` entry → `limactl stop
  && limactl delete`.
- For each repo in `GH_ALLOWED_REPOS`, any repo-side runner with the
  `gha-` prefix that is offline (or not busy) and not backed by a `cur/`
  entry → DELETE via API.

### Singleton per (account, allowed repos)

The runner-cleanup branch treats *this* process's `cur/` as the only
source of truth for what `gha-<16hex>` runners ought to exist on each
allowlisted repo. **Do not run two consumers covering the same repo with
separate `SPOOL_DIR`s** — each would see the other's freshly-minted
(online, not yet busy) runners as orphans and delete them between mint
and job pickup. Safe configurations:

- One consumer process per repo (or per disjoint set of repos).
- Multiple processes sharing the same `SPOOL_DIR` (and so the same
  `cur/`), because each sees every claim.
- Separate consumers covering *disjoint* repo sets.

There is no in-band guard for this; the launchd plist / deployment
harness is the right place to enforce singleton.

## Guest VM

`lima/runner-aarch64.yaml` is the Lima template for the per-job guest.
Point `LIMA_TEMPLATE` at it. It boots a stock Ubuntu 24.04 aarch64 cloud
image and, via Lima provisioning, installs git + node + the GitHub
Actions runner (linux-arm64), creates an unprivileged `runner` user, and
drops a `gha-run-once` wrapper at `/usr/local/bin`. The consumer copies
the JIT config into the guest and runs `sudo gha-run-once /tmp/jit`,
which reads the config as root and execs `./run.sh --jitconfig` as the
`runner` user — one job, then the VM is destroyed.

The image is pinned to a dated Ubuntu release + digest; refresh it from a
newer `releases/24.04/release-YYYYMMDD/` (the file has a comment showing
how). Validate edits with `limactl validate lima/runner-aarch64.yaml`.

## See also

- [`DEFERRED.md`](DEFERRED.md) — work that hasn't landed yet
  (`/nix/store` sharing, Keychain integration, launchd plist, graceful
  shutdown, multi-arch, integration tests, guest image).
