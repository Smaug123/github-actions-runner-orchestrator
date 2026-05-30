# Mac signing cache (Phase 3 / 3a)

The *read path* of the shared Nix store. A curated, signed `aarch64-linux`
binary cache served from the Mac that the ephemeral guests substitute from —
prepended ahead of `cache.nixos.org` — so a job that would otherwise rebuild
the expensive Rust crate closure (`cargoArtifacts`) from source instead pulls
warm, signed paths over HTTP.

**Why a curated cache and not the live `/nix/store`:** serving the whole store
would let any reachable guest fetch any private path on the Mac by hash (other
repos' source and outputs included). The cache is a *dedicated directory* that
only ever holds what we deliberately published into it, served read-only with a
server that physically cannot reach outside its docroot.

**Trust domain:** all allowed repos share this one cache. Anyone who can land a
workflow in any allowed repo can fetch any path warmed for any other. That is
an accepted decision (see `ROLLOUT_PLAN.md`, "One shared cache = one trust
domain"). Segmenting per-repo is deferred (`DEFERRED.md`).

## Status — built so far

- **slice 1: signing keypair + curated cache docroot.** `init-cache.sh`.
- **slice 2a: confined static server + serve-start gate.** `serve-cache.sh` +
  `common.sh` (shared layout, so the gate checks the same key path the writer
  created).
- **slice 2b: deploy under launchd + tests.** `setup-server.sh`
  (creates the `_gha-cache` user, installs/loads the LaunchDaemon, asserts the
  user can't read the key) and `test-cache.sh` (the (+)/(−) harness). Binds
  **loopback** — see "Deploying the server" for why that, not a `pf`-fenced LAN
  address.
- **slice 3 (this commit): warm the cache.** `warm-cache.sh <target>...` copies
  the full signed **build closure** into the docroot (see "Warming the cache").
- **slice 3 (inputs): warm flake inputs.** `warm-flake-inputs.sh [flake-ref...]`
  signs a flake's locked **input source trees** into the docroot so the guest's
  `nix develop` substitutes them instead of fetching from GitHub (see "Warming
  flake inputs") — fixes the in-VM flake-input 502s.
- **3b (guest config, in `nix/guest.nix`):** the guest's `nix.settings` appends
  this cache + its public key via `extra-substituters` /
  `extra-trusted-public-keys`, keeping `cache.nixos.org` and its key.

Still to come:

- **Prune** (a `warm-cache.sh` follow-up): delete stale NARs behind the host
  lock, gated on a GC-truth precondition (no `gha-*` Lima VMs + empty spool) and
  a delete-vs-live-fetch grace window. Deliberately not in this slice.

The automatic host warmer (3c) is deferred — v1 is populated manually by running
`warm-cache.sh` yourself, with `cache.nixos.org` as fallback.

## One-time setup

From this directory, as the `ci` user (no sudo needed — everything lands under
`$HOME`):

    ./init-cache.sh

This is idempotent. It:

1. Generates a binary-cache signing keypair (`gha-mac-cache-1`) if absent. An
   existing key is **never** regenerated (that would invalidate the public key
   already baked into guests). Every run re-applies the private key's `0600`
   mode and re-derives the public key from the secret, so the printed value
   always matches the signing key even after a partial setup or restore.
2. Creates the curated cache docroot with a `nix-cache-info` advertising
   `Priority: 10`.
3. Prints the **public key** — bake this into the guest's
   `trusted-public-keys` in the 3b slice.

## Serving the cache

`serve-cache.sh` is the static HTTP server (darkhttpd) over `cache/`. It is the
single ExecStart for the launchd daemon that slice 2b installs; run it directly
only for local testing.

It enforces "the signing key is never reachable from the served docroot" in
layers, strongest first:

1. **Dedicated user (primary).** Run as root, it drops to `GHA_CACHE_USER`
   (default `_gha-cache`) — a user that cannot read the `0600`-`ci` signing key.
   macOS perms are per-inode, so a symlink *or* hardlink to the key under the
   docroot still `EACCES`es; the kernel enforces this for every writer, no audit
   needed. (The `_gha-cache` user is created by slice 2b.)
2. **chroot.** darkhttpd chroots into the docroot, so no path (`..`, symlink)
   can name a file outside the served tree.
3. **Serve-start inode gate.** Before serving, it walks the docroot, refuses any
   symlink (any depth) or non-regular/non-directory entry, and refuses to start
   if any entry shares the key's `(dev, inode)` (a hardlink) — one ground-truth
   check covering `init-cache.sh`, `warm-cache.sh`, and manual edits alike.
4. **No autoindex** (`--no-listing`) and **a specific bind address only**, never
   `0.0.0.0`. In this deployment that address is `127.0.0.1` (loopback); see
   "Deploying the server" for why loopback is what makes it guest-reachable
   *and* off the LAN.

Config (env): `GHA_CACHE_BIND_ADDR` (**required**; a canonical specific IPv4 —
any-address forms like `0`/`0.0`/`0.0.0.0` are rejected), `GHA_CACHE_PORT`
(default `8080`), `GHA_CACHE_USER` / `GHA_CACHE_GROUP` (default `_gha-cache`),
`GHA_DARKHTTPD` (darkhttpd path if not on `PATH`), plus the `GHA_CACHE_DIR` /
`GHA_CACHE_KEY_NAME` shared with `init-cache.sh`. **`GHA_CACHE_DIR` is required
when running as root** (the launchd plist must pass it) — root's `$HOME` is not
where `init-cache.sh`, run as `ci`, wrote the cache.

Run modes: **as root** (launchd/production) it chroots and drops to the
dedicated user; **as non-root** it serves as the invoking user with NO chroot
and NO privilege drop, printing a loud warning — local testing only.

## Deploying the server

Three steps, in order:

    brew install darkhttpd          # the static server binary
    ./init-cache.sh                 # as the signing user (no sudo) — keypair + docroot
    sudo ./setup-server.sh          # create _gha-cache, install + load the LaunchDaemon

`setup-server.sh` is idempotent. It creates the dedicated `_gha-cache` service
user/group (hidden, no login, no home), then **actually attempts to read the
signing key as that user and aborts if it succeeds** (the whole defense rests on
that read failing, so it is verified rather than assumed). It then installs
**root-owned copies** of `serve-cache.sh`, `common.sh`, **and the `darkhttpd`
binary** to `/usr/local/libexec/gha-mac-cache/` (override `GHA_CACHE_LIBEXEC`)
and points the daemon at those — the root daemon must never execute code (script
*or* binary) out of a user-writable path like the checkout or Homebrew, or
anyone who can write it would get root code-execution on the next launch. The
daemon's `PATH` is likewise pinned to root-owned system dirs only (no
`/opt/homebrew/bin`), and the install dir's whole (canonicalised) ancestry is
asserted root-owned and not group/other/ACL-writable. (Re-run setup to pick up a `darkhttpd`
or script update — the daemon runs the snapshots, not the live copies.) Finally
it creates a root-owned log dir
outside the docroot and installs + loads
`/Library/LaunchDaemons/uk.co.patrickstevens.gha-mac-cache.plist`. The daemon
runs the installed `serve-cache.sh` copy **as root** so it can chroot and
privilege-drop; logs go to `/Library/Logs/gha-mac-cache/serve.{out,err}.log`.
**Re-run `setup-server.sh` after editing the scripts** (the daemon runs the
installed copy, not the checkout); `sudo ./setup-server.sh uninstall
[--purge-user]` reverses it. `./setup-server.sh print-plist` emits the plist
without root (for review).

**Bind model — loopback, no `pf` rule (a deliberate deviation from the original
plan).** Lima's `vz` guests use the built-in user-mode network (`192.168.5.0/24`,
guest `…5.15`). `host.lima.internal` (`192.168.5.2`) is **virtual** — there is no
real host interface at that address to bind or to fence with `pf`; it lives
inside Lima's in-process usernet gateway, which forwards `host.lima.internal:PORT`
to the host's **`127.0.0.1:PORT`**. So the server binds **`127.0.0.1`**: that is
exactly what the guests reach (as `host.lima.internal:8080`) and it is not
LAN-routable, satisfying the "never `0.0.0.0`/LAN" intent. A `pf` rule on
loopback would be redundant, so none is added. Trade-off: any *host-local*
process can also reach `127.0.0.1:8080` — acceptable, because the docroot is
public (the inode gate + dedicated user guarantee no secret is ever served).

### Testing the deployment

    ./test-cache.sh                 # host-side (+)/(-) checks vs the running daemon
    ./test-cache.sh --dev           # same checks against a darkhttpd this script starts
    ./test-cache.sh --vm NAME       # also run guest-side checks inside Lima VM NAME

The guest-side checks run `curl` *inside* a Lima VM, so point `--vm` at a
**throwaway** VM — not one of the busy ephemeral `gha-*` runners. They assert a
guest fetches `nix-cache-info` via `host.lima.internal` (proving the usernet
forward) and that a live `/nix/store` path is 404 (curated, not the whole store).

## Warming the cache

`warm-cache.sh <target>...` populates the docroot with signed `aarch64-linux`
build closures. Run it as the signing user (`ci`, not root) after `init-cache.sh`:

    # realise the target first (off the hot path) — this is the one slow build:
    nix build .#packages.aarch64-linux.default
    # then publish its signed closure into the cache:
    ./warm-cache.sh default          # bare name -> .#packages.aarch64-linux.<name>
    ./warm-cache.sh default gha-guest-image '.#packages.aarch64-linux.foo'

For each target it:

1. **Forces `aarch64-linux` and asserts it.** The flake is `eachDefaultSystem`,
   so an unqualified `.#default` on this Mac would resolve to *aarch64-darwin* — a
   closure useless to Linux guests. A bare name is rewritten to
   `.#packages.aarch64-linux.<name>`, and the resolved derivation's `system` is
   asserted to be `aarch64-linux` (a fully-qualified target is honoured verbatim
   but still asserted) — wrong-platform targets are refused, not warmed.
2. **Preflights that the target is built**, then **copies the full build
   closure.** It first checks the target derivation's own output is valid locally
   — if you haven't `nix build`-ed it, it stops and says so (rather than copy the
   stray sources a never-built target still exposes and claim success). It then
   copies `nix-store -qR --include-outputs` of the `.drv` — not just the output
   runtime closure, which would miss `cargoArtifacts` (the crane Rust deps) and
   leave guests rebuilding them. `*.drv` paths are filtered out (guests
   substitute outputs, not build instructions); the list streams into `nix copy
   --stdin` (no `ARG_MAX`).
3. **Signs during the copy** with the Mac key (`file://…?secret-key=…`), so each
   narinfo carries a `gha-mac-cache-1:` signature the guests trust (3b).
4. **Records a manifest** (`$GHA_CACHE_DIR/manifest/warmed.log`, outside the
   docroot) of every warmed path — the future prune's keep-set.

It **copies what is already realised; it never builds** (a from-source
`aarch64-linux` build is slow on the single-vCPU `linux-builder` and would
contend with live CI). So **`nix build` the target first, then warm right
after** — from the **same clean checkout** (the derivation hash is tied to the
tree) and before any `nix-collect-garbage`, since gcroots protect the target's
runtime closure but *not* build-only deps like `cargoArtifacts`. The whole
copy/manifest sequence runs under one host-level lock (atomic `mkdir`, since
macOS has no `flock`) so it can't interleave with the running server or a
concurrent warm.

## Warming flake inputs

`warm-flake-inputs.sh [flake-ref...]` solves a *different* flakiness source than
`warm-cache.sh`: the in-VM `nix develop` / `nix build` fetching a flake's **input
sources** (`nixpkgs`, `crane`, `rust-overlay`, …) straight from
`codeload`/`api.github.com` and getting intermittent **502s** ("unpacking
`github:owner/repo/<rev>?narHash=…` into the Git cache…"), even past Nix's 5
retries. Flake-input fetching is a separate Nix subsystem from the binary cache,
so warming build closures never helped it.

It works because a **locked** input's source is a content-addressed
`/nix/store/<narHash>-source` path, and Nix's flake fetcher is
`fetchOrSubstituteTree` — it **substitutes the locked tree from the configured
substituters before touching the origin**. The guest already trusts this cache
(`nix/guest.nix`), so once the `-source` paths are signed into the docroot the
guest pulls them over HTTP from `host.lima.internal` and never calls GitHub.
(Verified: a fresh store, `--offline`, substituter = this docroot, sigs checked
against the guest's key, resolves the whole flake.)

Run it as the signing user (`ci`), like `warm-cache.sh`:

    ./warm-flake-inputs.sh                 # no arg -> warm THIS repo's inputs
    ./warm-flake-inputs.sh /path/to/repo   # a checkout dir (canonicalised)
    ./warm-flake-inputs.sh github:owner/repo

For each flake it `nix flake archive`s the inputs (fetching any missing ones into
the **host** store first — do this once, here, where retries have a chance),
extracts the input source paths (the flake's own per-commit source is
deliberately skipped), then streams them into the same signed
`nix copy --stdin --to file://…?secret-key=…` pipeline `warm-cache.sh` uses —
under the **same** host lock (`$base/warm-cache.lock`) so it can't interleave
with a closure-warm. It records its own manifest (`manifest/inputs-warmed.log`).

Caveats: **locked inputs only** (substitution replaces the *tree fetch*, not the
ref→rev resolution an unlocked input still pings GitHub for — all our flakes pin
a `flake.lock`), and **re-warm after a `flake.lock` bump** (warming is keyed by
the pinned `narHash`). There is **no `aarch64-linux` assertion** here — an input
`-source` tree is system-agnostic (the exact content the lock pins), so warming
from this `aarch64-darwin` host is correct.

## Layout

Out-of-tree (host state; only the scripts here are version-controlled), under
`$GHA_CACHE_DIR` (default `~/.local/share/gha-mac-cache/`):

    keys/                      # NOT served — sibling of, never under, cache/
      gha-mac-cache-1.secret   # 0600 signing private key
      gha-mac-cache-1.public   # the trusted-public-keys string for guests
    manifest/                  # NOT served — 0700; the warmers' records
      warmed.log               # warm-cache.sh: TSV timestamp <TAB> target <TAB> store_path
      inputs-warmed.log        # warm-flake-inputs.sh: TSV timestamp <TAB> flake-ref <TAB> store_path
    cache/                     # the docroot the server will expose, read-only
      nix-cache-info           # StoreDir / WantMassQuery / Priority: 10
      # nar/ and *.narinfo land here once warm-cache.sh runs

**Invariant — the signing key is never reachable from the docroot.** The
private key (plus, later, netrc / staging dirs / logs) lives outside `cache/`;
the docroot holds only `nar/`, `*.narinfo`, and `nix-cache-info`. But "outside
the tree" is only the first layer — the server enforces the invariant by
*capability*: it serves as a dedicated user that cannot read the key, chrooted
into the docroot, behind a serve-start inode gate (see "Serving the cache"). So
a stray symlink or hardlink to the key cannot leak it regardless of file mode.

**Invariant — Priority beats list order.** Nix prefers a substituter by the
`Priority:` in its `nix-cache-info` (lower = preferred), *not* by the order it
appears in `substituters`. `cache.nixos.org` advertises `40`; the `10` here
makes the Mac win for any path present in both. The 3b slice verifies this from
a guest.
