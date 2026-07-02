#!/usr/bin/env bash
# Warm the curated Mac signing cache with SIGNED aarch64-linux build closures
# (Phase 3 / 3a, slice 3).
#
# This is the *write/populate* side of the shared store. `init-cache.sh` laid
# the foundation (signing keypair + docroot + nix-cache-info); `serve-cache.sh`
# exposes the docroot read-only to the guests. This script puts content INTO the
# docroot: for each flake target it resolves the aarch64-linux derivation, copies
# its FULL BUILD CLOSURE into the docroot signed with the Mac key, and records a
# manifest of what was warmed (used later for pruning).
#
# Five landmines from prior review rounds, each load-bearing — read before
# touching anything:
#
#  1. WRONG-PLATFORM WARM (P1). The flake is `flake-utils.lib.eachDefaultSystem`
#     (flake.nix:15), so an UNQUALIFIED `.#default` on this aarch64-DARWIN host
#     resolves to the aarch64-darwin package (flake.nix:49) — a closure that is
#     USELESS to the aarch64-linux guests and, worse, would be signed and served
#     to them. So we (a) force the installable to `.#packages.aarch64-linux.<t>`
#     and (b) ASSERT the resolved derivation's `system == "aarch64-linux"` before
#     copying anything. Belt (force) AND braces (assert): a future flake that
#     stops using eachDefaultSystem, or a target that overrides system, would
#     slip past the path-rewrite alone.
#
#  2. BUILD CLOSURE, NOT OUTPUTS (requirement). `cargoArtifacts` (flake.nix:34)
#     is an internal `let` binding consumed only by buildPackage (flake.nix:38);
#     it is NEVER a flake output. So copying the package's *output* runtime
#     closure (`nix copy .#pkg`) does NOT publish the crane deps, and a guest
#     would re-compile the expensive Rust dependency closure from source anyway —
#     defeating the entire point of the cache. So we copy the .drv's closure
#     WITH outputs (`nix-store -qR --include-outputs`), which includes
#     cargoArtifacts' output when it is realised. We PREFLIGHT that the TARGET
#     output is actually built — failing with "nix build it first" rather than
#     copying the stray sources a never-built target would still expose and
#     writing a success manifest. We COPY what exists; we do not build from
#     source here (see "BUILD vs COPY" below).
#
#  3. ARG_MAX. The full build closure is hundreds–thousands of store paths. We
#     must NOT splat that list into argv (`nix copy $list` / `cp -- $list`):
#     E2BIG. We STREAM the newline-delimited path list into `nix copy --stdin`,
#     which reads installables from stdin (Nix 2.34 supports `--stdin`). One copy
#     invocation, bounded argv.
#
#  4. SIGN DURING COPY. The destination store URL `file://$cache_dir?secret-key=
#     $KEY` makes `nix copy` sign each path's narinfo with the Mac key as it
#     writes it. The signature name (the `gha-mac-cache-1` prefix from the key
#     file) must match a `trusted-public-keys` entry the guests carry (3b), or
#     the guests reject the path. Signing happens here, in the copy, NOT in a
#     separate `nix store sign` pass.
#
#  5. ONE HOST-LEVEL LOCK. The running server (`serve-cache.sh`, a SEPARATE
#     process) and any concurrent warm must not interleave writes to the docroot.
#     We wrap the whole mutating sequence (copy -> manifest append -> cache-info
#     ensure) in a single host-level lock. macOS has no `flock(1)` by default and
#     no `shlock` guarantee, so we use an atomic `mkdir` lock (mkdir is atomic
#     create-or-fail on POSIX; no external dependency). See "LOCK" below.
#
# PRUNE is explicitly OUT OF SCOPE for this slice (see the TODO near the end):
# the plan ties deletion to a GC-truth precondition and a delete-vs-live-fetch
# race that needs its own design.
#
# Runs as the SIGNING user (`ci`) — it must READ the 0600 `$secret_key` to sign.
# It must NOT run as root (root can read the key, but then the narinfos/manifest
# it writes into ci's docroot would be root-owned and the serve-start gate /
# next warm would choke; and running the signer as root is needless privilege).
set -euo pipefail

# Shared layout (base, key_name + validation, keys_dir, cache_dir, secret_key,
# public_key, cache_info). One definition, shared with init/serve, so we sign
# with and write into exactly the paths the server gates on. set -euo pipefail
# is already in effect (required before sourcing — an unsafe key name exit's us).
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "$dir/common.sh"

# --- preconditions -----------------------------------------------------------

# Must be the SIGNING user, never root. Signing needs to READ the 0600 secret;
# the writes must be owned by `ci` (the docroot's owner) so the serve-start gate
# and subsequent warms aren't tripped by root-owned files. Refuse uid 0 loudly.
if [ "$(id -u)" -eq 0 ]; then
  echo "error: do not run warm-cache.sh as root; run it as the signing user (ci) that owns $secret_key." >&2
  exit 1
fi

# Public umask: the docroot is served read-only to guests and the production
# server drops to _gha-cache, which must READ every cache file — and
# serve-cache.sh's root-mode gate refuses to start if any docroot entry is not
# world rx/r. Under a restrictive umask (e.g. 077) the files `nix copy` writes
# would be owner-only and break both. Force 022 so new cache payload is 644/755,
# matching init-cache.sh's 755 docroot. (Doesn't affect the 0700 manifest dir —
# that is chmod'd explicitly below; keys/ is never touched here.)
umask 022

# Need nix (copy) and nix-store (closure query) on PATH.
for tool in nix nix-store; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool not found on PATH (add /nix/var/nix/profiles/default/bin)." >&2
    exit 1
  fi
done

# Usage: at least one target. A target is either a bare attr name (`default`,
# `gh-actions-consumer`) which we map under .#packages.aarch64-linux.<name>, or
# a fully-qualified `.#packages.aarch64-linux.<name>` the caller wrote out.
if [ "$#" -eq 0 ]; then
  echo "usage: $(basename "$0") <flake-target>..." >&2
  echo "  <flake-target> is a package attr name (e.g. 'default', 'gh-actions-consumer')" >&2
  echo "  or a fully-qualified '.#packages.aarch64-linux.<name>'." >&2
  echo "  Each is FORCED to aarch64-linux and its derivation's system is asserted." >&2
  exit 2
fi

# Signing key must be present, a regular file, and readable by us — we can't
# sign without it. (init-cache.sh creates it 0600-ci; serve-cache.sh's gate
# guarantees no docroot entry shares its inode.)
if [ -L "$secret_key" ] || [ ! -f "$secret_key" ]; then
  echo "error: signing key $secret_key missing or not a regular file; run init-cache.sh first (as ci)." >&2
  exit 1
fi
if [ ! -r "$secret_key" ]; then
  echo "error: signing key $secret_key not readable by $(id -un); warm-cache.sh must run as the key owner." >&2
  exit 1
fi

# Docroot must be a real directory (not a symlink) — we write narinfos/nar into
# it and the server only serves a real-dir docroot.
if [ -L "$cache_dir" ]; then
  echo "error: docroot $cache_dir is a symlink." >&2
  exit 1
fi
if [ ! -d "$cache_dir" ]; then
  echo "error: docroot $cache_dir not found; run init-cache.sh first." >&2
  exit 1
fi

# The flake we warm from is THIS repo's flake (warm-cache.sh ships beside it
# under host-setup/mac-cache/). Resolve the repo root (two levels up) so the
# script works regardless of the caller's cwd, and so `nix` evaluates the right
# flake rather than whatever flake happens to be in $PWD.
flake_root="$(cd "$dir/../.." && pwd)"
if [ ! -f "$flake_root/flake.nix" ]; then
  echo "error: no flake.nix at expected repo root $flake_root." >&2
  exit 1
fi

# We force aarch64-linux for every target. Keep the platform string in one place.
target_system="aarch64-linux"

# --- lock --------------------------------------------------------------------
# ONE host-level lock around the whole mutating sequence (requirement 5). The
# server is a separate process and a second warm could run concurrently, so an
# in-process mutex is insufficient. The lock (an atomic PID-carrying symlink,
# stale-reclaim, and the ABA-safe reclaim serialization) lives in common.sh so
# warm-cache.sh and warm-flake-inputs.sh share exactly one lock by path. We
# install the release trap here — not in common.sh — so sourcing common.sh never
# clobbers init/serve's own EXIT handling.
trap 'release_lock' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

acquire_lock

# --- nix-cache-info ensure (requirement 8) -----------------------------------
# init-cache.sh writes nix-cache-info (StoreDir/WantMassQuery/Priority: 10). We
# only VERIFY it is present — we must NOT clobber it (re-writing could drop the
# Priority and let cache.nixos.org win for shared paths). If it is missing the
# cache was never initialised correctly; abort rather than serve unsigned/
# mis-prioritised content.
if [ ! -f "$cache_info" ]; then
  echo "error: $cache_info missing; run init-cache.sh first (it writes Priority: 10)." >&2
  exit 1
fi

# --- manifest (requirement 7) ------------------------------------------------
# Record what we warmed, OUTSIDE the served docroot (the manifest lists internal
# store paths and target/timestamp metadata that need not be public, and must
# never be served or trip the serve-start gate). Layout: $base/manifest/.
# One append-only log line per warmed store path, plus a per-run header, so a
# later prune (slice 3a-3 follow-up) can compute the keep-set as the union of
# recent manifests per (target).
manifest_dir="$base/manifest"
mkdir -p "$manifest_dir"
chmod 700 "$manifest_dir"
manifest_log="$manifest_dir/warmed.log"
# RFC3339-ish UTC timestamp; one run can warm several targets.
run_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Append a record. Fields are tab-separated: ts <TAB> target <TAB> store_path.
# Written under the lock, so no interleaving with a concurrent warm.
manifest_record() {
  # $1 = target label, $2 = store path
  printf '%s\t%s\t%s\n' "$run_ts" "$1" "$2" >> "$manifest_log"
}

# --- per-target warm ---------------------------------------------------------
# For each target: build the forced installable, resolve its .drv, ASSERT the
# system, compute the build closure, stream-copy+sign it, and record a manifest.
warm_one() {
  local raw="$1" installable

  # Build the installable, always anchored to THIS repo's flake — never the
  # caller's cwd. A RELATIVE flake ref (`.#attr` or `#attr`) passed verbatim to
  # nix would resolve `.` against $PWD, so running `./warm-cache.sh .#…` from
  # host-setup/mac-cache (or any other dir) would eval whatever flake sits there
  # — or fail — and could sign/serve the wrong checkout. So we rewrite relative
  # refs onto $flake_root, map a bare attr name to the forced aarch64-linux
  # package, and honour only an EXPLICIT flakeref (absolute path / URL, e.g.
  # `/path#pkgs.foo`) verbatim. The system assert below is the safety net
  # regardless of how the target was spelled.
  case "$raw" in
    .#*)
      installable="$flake_root#${raw#.#}"
      ;;
    '#'*)
      installable="$flake_root$raw"
      ;;
    *'#'*)
      installable="$raw"
      ;;
    *)
      installable="$flake_root#packages.$target_system.$raw"
      ;;
  esac

  echo "==> target '$raw' -> $installable"

  # Resolve the .drv path and the system by EVALUATION only (no build, no jq).
  # `nix eval --raw <installable>.drvPath` asks for the derivation, not the
  # output, so it never realises/substitutes; `.system` is the platform the drv
  # builds for. Evaluating a FLAKE installable needs BOTH nix-command AND flakes,
  # so we enable both here (the host may not have flakes globally on) — same
  # belt-and-braces as init-cache.sh. eval returns a single value, no guard needed.
  local drv sys
  if ! drv="$(nix eval --extra-experimental-features 'nix-command flakes' --raw "$installable.drvPath" 2>/dev/null)"; then
    echo "error: could not resolve a derivation for $installable (does .#packages.$target_system.$raw exist?)." >&2
    exit 1
  fi
  [ -n "$drv" ] || { echo "error: empty derivation path for $installable." >&2; exit 1; }

  # ASSERT system == aarch64-linux (requirement 1, the braces). `.system` is the
  # derivation's build platform, read by eval — exact and jq-free. A flake that
  # drops eachDefaultSystem, or a target overriding system, is caught here before
  # anything is signed or served.
  if ! sys="$(nix eval --extra-experimental-features 'nix-command flakes' --raw "$installable.system" 2>/dev/null)"; then
    echo "error: could not read .system for $installable." >&2
    exit 1
  fi
  if [ "$sys" != "$target_system" ]; then
    echo "error: REFUSING to warm $installable: resolved derivation system is '$sys', not '$target_system'." >&2
    echo "       (eachDefaultSystem means an unqualified target resolves to the host platform; warming it would" >&2
    echo "        sign and serve a closure useless to the Linux guests.)" >&2
    exit 1
  fi
  echo "    system asserted: $sys"
  echo "    drv: $drv"

  # PREFLIGHT: the TARGET must actually be built locally. `nix-store -q --outputs
  # <drv>` lists the target's declared output paths (deterministic, no build);
  # each must be VALID. This is the reliable "is it realised" signal — if the
  # operator runs warm-cache BEFORE building, the output is absent and we fail,
  # rather than copy the stray sources/realised-deps that -qR would still return
  # (a partial set + a success manifest would silently leave guests rebuilding).
  # We can't enforce "every declared output of every build dep" — multi-output
  # deps legitimately leave unused outputs (.man/.dev) unrealised, so that would
  # false-fail; the target-output check is the meaningful one.
  local o
  while IFS= read -r o; do
    [ -n "$o" ] || continue
    if ! nix-store --check-validity "$o" >/dev/null 2>&1; then
      echo "error: $installable is not realised locally (output $o is missing). Build it first:" >&2
      echo "         nix build $installable" >&2
      echo "       then re-run. (warm-cache.sh copies; it never builds.)" >&2
      exit 1
    fi
  done < <(nix-store -q --outputs "$drv")

  # FULL BUILD CLOSURE of what's realised. -qR --include-outputs gives the .drv
  # closure PLUS the OUTPUTS of build-time deps present locally — so cargoArtifacts
  # (a build-only dep, NOT in the target's runtime closure) is included while it
  # is still in the store. We drop *.drv (build instructions, not substitutable
  # content; copying an absent one can error) and copy the rest, signed.
  #
  # CAVEAT (the GC edge): --include-outputs lists a dep output only if it is
  # realised NOW. gcroots protect the target's runtime closure but NOT build-only
  # deps like cargoArtifacts, so warm RIGHT AFTER building — before any
  # nix-collect-garbage — or the crane deps may already be gone and the warm
  # incomplete (the guest rebuilds them). Closing this fully needs a build-time
  # gcroot on cargoArtifacts, which is the deferred 3c warmer's job.
  local closure n
  closure="$(nix-store -qR --include-outputs "$drv" | grep -v '\.drv$' || true)"
  if [ -z "$closure" ]; then
    echo "error: empty build closure for $drv (unexpected after the target-output check)." >&2
    exit 1
  fi
  n="$(printf '%s\n' "$closure" | grep -c '^/nix/store/' || true)"
  echo "    build closure: $n store paths present (streaming into nix copy --stdin)"

  # STREAM + SIGN (requirements 3, 4, 5). Pipe the newline-delimited path list
  # into `nix copy --stdin` (reads installables from stdin — no argv splat) with
  # the destination a local file store carrying the secret-key query parameter,
  # which signs each narinfo with the Mac key as it is written. --to selects the
  # destination store. We are already under the host lock.
  #
  # The secret-key value is a FILE PATH (nix reads the key from it); it does not
  # put the key bytes on the command line, but the path itself is visible in ps —
  # acceptable, it is just a path, not the secret.
  printf '%s\n' "$closure" \
    | nix copy --stdin \
        --extra-experimental-features nix-command \
        --to "file://$cache_dir?secret-key=$secret_key"

  # Record EVERY copied path in the manifest (requirement 7) so a later prune
  # keeps the whole build closure, not just the output (output-only gcroots would
  # let a prune evict cargoArtifacts — the exact thing we warmed). The target
  # label recorded is the user's raw arg, which is enough to group per-target.
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    manifest_record "$raw" "$p"
  done <<< "$closure"

  echo "    warmed and signed: $installable ($n paths)"
}

# Warm every requested target under the single lock we already hold.
for t in "$@"; do
  warm_one "$t"
done

# --- prune: OUT OF SCOPE for this slice --------------------------------------
# TODO(3a-3 follow-up): prune behind flock + GC-truth precondition.
#   Deletion is deliberately NOT implemented here. The plan ties pruning to:
#     (a) a GC-truth precondition — `limactl list` shows NO `gha-*` instances
#         AND the spool `cur/` is empty (in-process `in_flight` is insufficient;
#         it misses orphan/manual VMs); and
#     (b) a delete-vs-live-fetch race — a guest that already fetched a *.narinfo
#         can still 404 on its nar/, so pruning needs a generation/grace scheme
#         (drop narinfo before its nar within the grace window), all under THIS
#         same host lock.
#   The manifest written above is the input to that prune (keep-set = union of
#   recent per-target manifests). Implementing deletion is its own slice.

echo
echo "warm-cache: done. Warmed $# target(s) into $cache_dir, signed with $key_name."
echo "  manifest: $manifest_log"
echo "  (prune is out of scope for this slice — see TODO(3a-3 follow-up).)"
