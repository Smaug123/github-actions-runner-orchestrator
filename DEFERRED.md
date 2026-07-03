# Deferred work

Items intentionally left out of the first cut. Each one needs its own design
pass before we ship it.

## Shared `/nix/store` for cross-job caching

Every VM today boots with an empty Nix store, so every job re-downloads or
rebuilds the world. Sharing the host's store would be the single biggest
speed-up available, but the host trusts each VM very little — anyone who can
land a workflow file can run arbitrary code inside.

Options, roughly safest → fastest:

1. **Host-local binary cache.** Host runs `nix-serve` (or `attic`) bound to
   a loopback address that's also reachable from the Lima VM. Each guest's
   `nix.conf` lists the host as a substituter and trusts its signing key.
   The protocol is read-only over HTTP; the guest can't push paths back.
   This is the default I'd reach for: simple, no shared filesystem, no
   privilege bridge, and the threat surface is just "what if a guest can
   read every path I've ever cached." If that matters, segment the cache
   per-project.

2. **virtiofs read-only mount of host `/nix/store` with a tmpfs overlay for
   new paths.** Faster than HTTP (no copy at all) but the guest can
   enumerate every store path the host has, which leaks information about
   what the host has built, and the shared page cache is a timing
   side-channel. Mitigation: a curated host-side store at
   `/var/lib/gh-actions-consumer/nix-store/` containing only paths we're
   comfortable advertising. Lima supports virtiofs on Apple
   Virtualization.framework hosts.

3. **Read-write shared store.** Don't. A single malicious or buggy job
   poisons the store for every later job, including jobs on other repos.

Decision pending; needs a separate threat model that enumerates what an
attacker who can land a workflow file can actually do.

## Keychain integration

The first cut reads the GitHub App private key from
`GH_APP_PRIVATE_KEY_FILE` on disk. A defence-in-depth upgrade on macOS is to
store it in the Keychain and have the daemon fetch it at startup.

Sketch:

- New flag `GH_APP_PRIVATE_KEY_KEYCHAIN_ITEM=<service>:<account>`. If set,
  the daemon shells out to
  `security find-generic-password -s <service> -a <account> -w`
  (or links the Security framework directly via the `security-framework`
  crate) and ignores `GH_APP_PRIVATE_KEY_FILE`.
- Cache the PEM in memory for the process lifetime; install a `SIGHUP`
  handler to re-read so rotation doesn't require a restart.

Decisions still to make:

- **Which keychain.** For a user-mode launchd agent the login keychain is
  fine but the daemon can't start before the user logs in (which is
  acceptable for a single-operator host). For a system service we need the
  System keychain, and Security framework access from a launchd-system
  context has its own quirks worth proving out.
- **ACL on the key item.** `security` can restrict reads to a specific
  binary path, but only at item-create time. Probably worth scripting that
  setup so the daemon binary is the only thing that can unlock the item.
- **Fallback behaviour.** If the keychain item is missing or the user is
  prompted for unlock and refuses, fail loudly rather than silently falling
  back to a file path.

Likely ships as an opt-in feature flag, defaulting to the file path so
nothing changes for users who don't care.

## launchd plist

Not in scope yet. When we ship, we'll want:

- One agent (or daemon, depending on the Keychain decision above) for
  `gh-actions-consumer` and one matching one for `gh-webhook-spool` if
  there isn't one already. They share `SPOOL_DIR`.
- `KeepAlive = true`, `RunAtLoad = true`,
  `StandardOutPath`/`StandardErrorPath` pointed at `STATE_DIR/logs/`,
  `ThrottleInterval` ≥ 5s so a crash loop doesn't hammer the host.
- Probably packaged as a single `nix run`-installable that drops both
  plists with paths derived from the flake.

## Graceful shutdown (partially done)

SIGTERM, or the first Ctrl+C, now pauses new claims and waits for in-flight
VMs to drain before exiting cleanly; a second Ctrl+C forces immediate teardown
(see `supervisor::run_shutdown`). On a forced teardown the in-flight VMs
survive the daemon's death — Lima processes are independent — and the next
start's GC sweep reaps them, with the cur/ stale-claim logic re-routing their
spool files to error/. What's still deferred:

- **No drain deadline.** A wedged job is bounded only by `JOB_MAX_RUNTIME_SECS`
  (its watchdog) and, from outside, by the operator's second Ctrl+C or the
  service manager's SIGKILL timeout. A bounded `SHUTDOWN_DRAIN_TIMEOUT_SECS`
  that auto-escalates to teardown could be added if launchd/systemd's own
  timeout proves too blunt.
- **No checkpointing.** Per-job state is not checkpoint-able, so a forced
  teardown (or SIGKILL) still throws away a VM's in-progress work; the next
  start's GC just reaps it. A checkpoint-able per-job state machine would let a
  longer drain resume rather than restart.

## Metrics and observability

Structured `tracing` JSON to stdout will be enough for a while. When we
want more:

- Prometheus exporter on a loopback port: job count, in-flight VMs, claim
  → done latency, JIT-mint latency, GH API call counts and failure rates,
  reconciler corrections per sweep.
- A `--dump-state` signal or local-socket endpoint that prints the
  current in-flight map.

## Multi-arch / x86 emulation

Apple Silicon host with aarch64-linux guests is the only target. If a
workflow needs x86 the cleanest path is a second consumer with a
QEMU/TCG-backed Lima template and its own custom label
(`lima-nix-amd64`). Not in this code yet.

## End-to-end test against a real GitHub org

There's no integration test that exercises the App → JIT → Lima → runner
→ delete loop against a real org. Adding one means: a test org, a test
App installation, a test repo with a trivial workflow, and a runner that
boots and processes it. Gated behind an env-var so it doesn't run by
default. Worth doing before we trust this for anything real.

## Guest image

`lima/runner-aarch64.yaml` is the shipped guest: a stock Ubuntu 24.04
aarch64 cloud image that installs the Actions runner and a `gha-run-once`
wrapper at first boot via Lima provisioning. It's the path `LIMA_TEMPLATE`
should point at today.

A NixOS-based guest built from this repo's flake would be a stronger
story — reproducible, no apt/network at boot, and a natural home for a
shared `/nix/store` substituter — but producing the qcow2 from a darwin
host needs a remote Linux builder or `linux-builder` (nix-darwin's
managed VM), and that integration is its own moving part. Deferred until
the Ubuntu template proves the loop end to end.

The Ubuntu template pins a dated image digest; refresh it from a newer
`releases/24.04/release-YYYYMMDD/` when desired (see the comment in the
file).
