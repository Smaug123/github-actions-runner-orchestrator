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

## Graceful shutdown

On SIGINT today we exit immediately. In-flight VMs survive the daemon's
death because Lima processes are independent; on the next start the GC
sweep reaps them and the cur/ stale-claim logic re-routes their spool
files to error/. That's correct but wasteful (we throw away ~minutes of
work per VM). A nicer story:

- On SIGINT, stop accepting new claims, wait up to N seconds for in-flight
  jobs to finish their normal teardown, then force-stop the rest.
- Per-job state machine should be checkpoint-able so a longer drain
  doesn't fight a SIGTERM from launchd.

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

The `guest/` directory contains a NixOS configuration sketch but isn't
wired into the flake yet. Producing the qcow2 from a darwin host
requires either a remote Linux builder or `linux-builder` (nix-darwin's
managed VM), and that integration is its own moving part. For now the
operator builds the image out-of-band and points `LIMA_TEMPLATE` at a
Lima YAML that references it.
