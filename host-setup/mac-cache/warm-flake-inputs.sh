#!/usr/bin/env bash
# Warm the curated Mac signing cache with a flake's LOCKED INPUT SOURCES
# (Phase 3 / 3a). Companion to warm-cache.sh.
#
# WHERE warm-cache.sh PUBLISHES aarch64-linux BUILD CLOSURES (so guests don't
# recompile the Rust crate closure), THIS publishes the *source trees of a
# flake's locked inputs* (nixpkgs, crane, rust-overlay, flake-utils, systems, …)
# so that a guest's `nix develop` / `nix build` / `nix flake` SUBSTITUTES those
# inputs from the Mac ahead of GitHub — killing the intermittent 502s that the
# in-VM flake-input fetch hits against codeload/api.github.com ("unpacking
# 'github:owner/repo/<rev>?narHash=…' into the Git cache…").
#
# WHY THIS WORKS, AND WHY IT IS A SEPARATE MECHANISM. Flake-input fetching is a
# DIFFERENT Nix subsystem from the binary cache that warm-cache.sh feeds: warming
# build closures never touched it, which is why the 502s persisted. But a LOCKED
# input's source is a content-addressed `/nix/store/<narHash>-source` path, and
# Nix's flake fetcher is `fetchOrSubstituteTree` — it tries to SUBSTITUTE the
# locked tree from the configured substituters BEFORE fetching from the origin.
# The guest already trusts this cache (nix/guest.nix: extra-substituters +
# extra-trusted-public-keys, Priority 10 ahead of cache.nixos.org), so once the
# `-source` paths are signed into the docroot the guest pulls them over HTTP from
# host.lima.internal and never calls GitHub. Verified empirically: a fresh store,
# `--offline`, with ONLY this cache as a substituter, resolves the whole flake.
#
# SCOPE / CAVEATS:
#  - LOCKED inputs only. Substitution replaces the TREE FETCH for an input pinned
#    by narHash in flake.lock. It does NOT cover ref->rev resolution for an
#    UNLOCKED input (e.g. `github:NixOS/nixpkgs/nixos-unstable` with no lock
#    entry) — that still pings api.github.com. Warm flakes with a committed
#    flake.lock (all of ours).
#  - RE-WARM ON LOCK BUMP. Warming is keyed by the pinned narHash; when a repo
#    bumps an input, re-run this for that repo.
#  - INPUTS ONLY, not the flake's own source. The top-level source tree changes
#    every commit (no guest ever substitutes its own checkout) — warming it would
#    just bloat the shared cache with per-commit trees. We descend into `.inputs`.
#  - NO aarch64-linux assertion (unlike warm-cache.sh). An input `-source` tree is
#    system-agnostic: it is the exact content the guest's lock pins by narHash,
#    whatever platform evaluates it, so warming from this aarch64-darwin host is
#    correct — there is no wrong-platform closure to guard against.
#
# Mechanism mirrors warm-cache.sh's load-bearing invariants:
#  - SIGN DURING COPY. The destination `file://$cache_dir?secret-key=$secret_key`
#    signs each narinfo with the Mac key as it is written; the signature name
#    (gha-mac-cache-1) must stay one the guests carry (3b) or they reject it.
#  - SHARED HOST LOCK. Takes warm-cache.sh's EXACT lock dir ($base/warm-cache.lock)
#    so an input-warm and a closure-warm (or two of either) cannot interleave
#    docroot writes (warm-cache.sh requirement 5). The lock is by PATH — atomic
#    mkdir on the same dir — so cross-process exclusion holds even though the lock
#    code is duplicated here rather than shared (kept self-contained to leave the
#    reviewed warm-cache.sh untouched; a later DRY pass can hoist it to common.sh).
#  - STREAM via `nix copy --stdin`. An input set (nixpkgs source + the rest) is
#    many paths; never splat them into argv (E2BIG). Bounded argv, one copy.
#  - MANIFEST outside the docroot, to manifest/inputs-warmed.log (kept SEPARATE
#    from warm-cache.sh's warmed.log) — the future prune's keep-set.
#  - Runs as the SIGNING user (ci), never root: it must READ the 0600 key to sign,
#    and its docroot writes must be ci-owned so the serve-start gate / next warm
#    are not tripped by root-owned files.
#
# We COPY what `nix flake archive` realises; the archive step first fetches any
# not-yet-present inputs into the LOCAL store — do that here on the well-connected
# host, once, ahead of every guest (this is the one place the 5 built-in retries
# against GitHub actually have a fighting chance).
set -euo pipefail

# Shared layout (base, key_name + validation, keys_dir, cache_dir, secret_key,
# public_key, cache_info). One definition, shared with init/serve/warm, so we
# sign with and write into exactly the paths the server gates on. set -euo
# pipefail is already in effect (required before sourcing).
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "$dir/common.sh"

# --- preconditions -----------------------------------------------------------

# Must be the SIGNING user, never root (same reasoning as warm-cache.sh): signing
# reads the 0600 secret, and the writes must be ci-owned so the serve gate and
# subsequent warms aren't tripped by root-owned files. Refuse uid 0 loudly.
if [ "$(id -u)" -eq 0 ]; then
  echo "error: do not run warm-flake-inputs.sh as root; run it as the signing user (ci) that owns $secret_key." >&2
  exit 1
fi

# Public umask: the docroot is served read-only and the production server drops
# to _gha-cache, which must READ every file; serve-cache.sh's gate refuses to
# start if any docroot entry is not world rx/r. Force 022 so new payload is
# 644/755 (matches init-cache.sh's docroot and warm-cache.sh).
umask 022

# Need nix (flake archive + copy) and jq (parse the archive tree) on PATH.
for tool in nix jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool not found on PATH (nix: add /nix/var/nix/profiles/default/bin; jq: brew install jq)." >&2
    exit 1
  fi
done

# Signing key must be present, a regular file, and readable by us — we can't sign
# without it. (init-cache.sh creates it 0600-ci.)
if [ -L "$secret_key" ] || [ ! -f "$secret_key" ]; then
  echo "error: signing key $secret_key missing or not a regular file; run init-cache.sh first (as ci)." >&2
  exit 1
fi
if [ ! -r "$secret_key" ]; then
  echo "error: signing key $secret_key not readable by $(id -un); warm-flake-inputs.sh must run as the key owner." >&2
  exit 1
fi

# Docroot must be a real directory (not a symlink) — we write narinfos/nars into
# it and the server only serves a real-dir docroot.
if [ -L "$cache_dir" ]; then
  echo "error: docroot $cache_dir is a symlink." >&2
  exit 1
fi
if [ ! -d "$cache_dir" ]; then
  echo "error: docroot $cache_dir not found; run init-cache.sh first." >&2
  exit 1
fi

# nix-cache-info must already be present (init-cache.sh's Priority: 10). We only
# VERIFY it — never clobber it (re-writing could drop the Priority and let
# cache.nixos.org win for shared paths).
if [ ! -f "$cache_info" ]; then
  echo "error: $cache_info missing; run init-cache.sh first (it writes Priority: 10)." >&2
  exit 1
fi

# The flake whose THIS repo ships beside, used as the default target when the
# caller names none — the common case is "warm this repo's own inputs".
flake_root="$(cd "$dir/../.." && pwd)"
if [ ! -f "$flake_root/flake.nix" ]; then
  echo "error: no flake.nix at expected repo root $flake_root." >&2
  exit 1
fi

# Usage: zero or more flake refs. A ref is a checkout directory (path) or any
# flakeref nix understands (URL / registry). No args => warm THIS repo's inputs.
if [ "$#" -eq 0 ]; then
  set -- "$flake_root"
  echo "note: no flake ref given; defaulting to this repo ($flake_root)."
fi

# --- lock --------------------------------------------------------------------
# ONE host-level lock around the whole mutating sequence, SHARED WITH warm-cache.sh
# by using its exact lock dir: two docroot writers (a closure-warm and an
# input-warm, or two of either) must not interleave their copy + manifest writes
# (warm-cache.sh requirement 5). mkdir is atomic create-or-fail on POSIX (macOS
# ships no flock(1)); the lock is by PATH, so exclusion holds across the two
# scripts even though this is a separate copy of the logic.
lock_dir="$base/warm-cache.lock"
# `held` gates the release trap: only ever rm the lock dir we actually own, so a
# failed acquire never deletes the live holder's lock. Set to 1 only after mkdir.
held=0
release_lock() {
  if [ "$held" -eq 1 ]; then
    rm -rf "$lock_dir" 2>/dev/null || true
  fi
}
trap 'release_lock' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

acquire_lock() {
  local tries=0 owner
  while ! mkdir "$lock_dir" 2>/dev/null; do
    owner=""
    [ -f "$lock_dir/pid" ] && owner="$(cat "$lock_dir/pid" 2>/dev/null || true)"
    if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
      tries=$((tries + 1))
      if [ "$tries" -ge 60 ]; then
        echo "error: could not acquire $lock_dir after 60s; warm held by live PID $owner." >&2
        exit 1
      fi
      sleep 1
      continue
    fi
    # No live owner: stale lock (holder died). Reclaim and re-mkdir.
    echo "warn: reclaiming stale lock $lock_dir (owner PID '${owner:-unknown}' not alive)." >&2
    rm -rf "$lock_dir" 2>/dev/null || true
  done
  held=1
  echo "$$" > "$lock_dir/pid"
}

acquire_lock

# --- manifest ----------------------------------------------------------------
# Record what we warmed OUTSIDE the served docroot, in its OWN log (kept separate
# from warm-cache.sh's warmed.log so the two warmers' records don't interleave
# and a prune can treat input sources distinctly). TSV: ts <TAB> ref <TAB> path.
manifest_dir="$base/manifest"
mkdir -p "$manifest_dir"
chmod 700 "$manifest_dir"
manifest_log="$manifest_dir/inputs-warmed.log"
run_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

manifest_record() {
  # $1 = ref label, $2 = store path
  printf '%s\t%s\t%s\n' "$run_ts" "$1" "$2" >> "$manifest_log"
}

# --- per-flake warm ----------------------------------------------------------
# For each ref: realise + enumerate the flake's input source trees, then
# stream-copy+sign them into the docroot and record a manifest.
warm_inputs_one() {
  local raw="$1" flakeref json paths n

  # A directory ref is canonicalised to an absolute path so the meaning never
  # depends on nix's cwd handling; anything else (URL / registry / explicit
  # flakeref) is honoured verbatim.
  if [ -d "$raw" ]; then
    flakeref="$(cd "$raw" && pwd)"
  else
    flakeref="$raw"
  fi
  echo "==> flake '$raw' -> $flakeref"

  # Realise + enumerate the flake and ALL its (transitive) inputs. `nix flake
  # archive --json` copies the input source trees into the LOCAL store — fetching
  # any missing ones from their origin HERE, on the well-connected host — and
  # prints the path tree to stdout. --no-update-lock-file preserves the "locked
  # inputs only" contract: a stale/missing lock fails here instead of warming
  # paths that the committed CI checkout will not use. Needs nix-command + flakes
  # (host may not have them on globally), same belt-and-braces as warm-cache.sh /
  # init-cache.sh.
  # stderr (fetch progress + the real failure cause, e.g. the very 502 we're
  # fixing) is LEFT VISIBLE — this is a long network op and the operator wants it;
  # only stdout (the JSON) is captured.
  if ! json="$(nix flake archive \
      --extra-experimental-features 'nix-command flakes' \
      --no-update-lock-file \
      --json \
      "$flakeref")"; then
    echo "error: 'nix flake archive --no-update-lock-file --json $flakeref' failed (bad flakeref, stale/missing lock, or an input could not be fetched — see the nix error above; update/commit flake.lock or retry on a good connection)." >&2
    exit 1
  fi

  # INPUTS ONLY: descend into `.inputs` and collect every `.path` at any depth
  # (transitive inputs included), deduped (a shared input reached via `follows`
  # appears more than once). Starting at `.inputs` excludes the flake's OWN
  # top-level `.path` on purpose (see header: per-commit source, never warmed).
  paths="$(printf '%s' "$json" | jq -r '[.inputs | .. | .path? // empty] | unique[]' | grep '^/nix/store/' || true)"
  if [ -z "$paths" ]; then
    echo "error: no input source paths in the archive of $flakeref (a flake with no inputs, or an unexpected --json shape)." >&2
    exit 1
  fi
  n="$(printf '%s\n' "$paths" | grep -c '^/nix/store/' || true)"
  echo "    input sources: $n path(s) (streaming into nix copy --stdin)"

  # STREAM + SIGN (same as warm-cache.sh): pipe the newline-delimited list into
  # `nix copy --stdin` (no argv splat) with the destination a local file store
  # carrying the secret-key query, which signs each narinfo with the Mac key as
  # it is written. We are already under the host lock.
  printf '%s\n' "$paths" \
    | nix copy --stdin \
        --extra-experimental-features nix-command \
        --to "file://$cache_dir?secret-key=$secret_key"

  # Record every copied path (label = the user's raw ref) so a future prune keeps
  # the whole input set, not just whatever a guest last fetched.
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    manifest_record "$raw" "$p"
  done <<< "$paths"

  echo "    warmed and signed: $flakeref ($n input paths)"
}

# Warm every requested flake under the single lock we already hold.
for f in "$@"; do
  warm_inputs_one "$f"
done

echo
echo "warm-flake-inputs: done. Warmed input sources for $# flake(s) into $cache_dir, signed with $key_name."
echo "  manifest: $manifest_log"
echo "  (re-run after any flake.lock bump; substitution covers LOCKED inputs only.)"
