# shellcheck shell=bash
# Shared layout + key-name resolution for the Mac signing cache scripts.
#
# SOURCED (not executed) by init-cache.sh (the writer) and serve-cache.sh (the
# server). Sharing one definition of where the key and docroot live means the
# server's inode gate provably checks the same key path the writer created —
# no drift between the two. Callers must `set -euo pipefail` before sourcing;
# an unsafe key name `exit`s the sourcing script.
#
# Defines: base, key_name, keys_dir, cache_dir, secret_key, public_key,
# cache_info.

# Base dir is out-of-tree (like the linux-builder and guest images): the
# key/cache are host state, only the *scripts* are version-controlled.
base="${GHA_CACHE_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/gha-mac-cache}"

# The signing key name becomes the prefix of every narinfo signature and must
# match a trusted-public-keys entry name in the guest (3b). The `-1` suffix
# leaves room to rotate (publish `-2` alongside, retire `-1`) without a
# flag-day. Override only if you know why.
key_name="${GHA_CACHE_KEY_NAME:-gha-mac-cache-1}"

# Constrain the key name to a safe single basename before it lands in any path.
# It's interpolated into keys/<name>.secret, so a '/' or '..' could escape
# keys_dir and write the PRIVATE key under the served docroot. A ':' would also
# break the `name:base64` signature format. Allow only [A-Za-z0-9._-], non-empty,
# with no '..'.
case "$key_name" in
  "" | *[!A-Za-z0-9._-]* | *..*)
    echo "error: GHA_CACHE_KEY_NAME must be a non-empty name of [A-Za-z0-9._-] with no '..'; got '$key_name'." >&2
    exit 1
    ;;
esac

# Layout: keys/ is a SIBLING of cache/, never under it. cache/ is the served
# docroot; keys/ (the signing key) stays outside it.
keys_dir="$base/keys"
cache_dir="$base/cache"
secret_key="$keys_dir/$key_name.secret"
public_key="$keys_dir/$key_name.public"
cache_info="$cache_dir/nix-cache-info"

# --- host-level warm lock ----------------------------------------------------
# ONE host-level lock around the whole docroot-mutating sequence of a warm (copy
# -> manifest append -> cache-info ensure). The running server (serve-cache.sh)
# and a second concurrent warm are separate PROCESSES, so an in-process mutex is
# insufficient; we need a filesystem lock. macOS ships no flock(1) and no
# reliable shlock. Defined here — not duplicated per warm script — so both
# warm-cache.sh and warm-flake-inputs.sh share the SAME lock by path and can
# never interleave their docroot writes. init/serve source this file too but
# simply never call acquire_lock, so these definitions are inert for them.
#
# The lock is a SYMLINK whose target is the holder's PID: `ln -s "$$" "$lock_dir"`
# both creates the lock exclusively (ln -s fails if the path exists — atomic on
# POSIX) AND records the owner in the SAME operation. That atomic owner token is
# load-bearing: a plain mkdir-then-write-pid lock has a window where the lock
# exists but the pid is not written yet, during which a racing reclaimer reads an
# empty owner and deletes the fresh lock. With the symlink there is no such
# window — a live lock always has a readable owner.
#
# Warm callers install the release trap themselves (so sourcing this file never
# clobbers init/serve's own EXIT handling) and then call acquire_lock:
#     trap 'release_lock' EXIT; trap 'exit 130' INT; trap 'exit 143' TERM
#     acquire_lock
lock_dir="$base/warm-cache.lock"
# reclaim_lock_dir serializes stale-lock reclamation (see reclaim_if_stale). A
# SIBLING of lock_dir under $base, never inside the served docroot.
reclaim_lock_dir="$base/warm-cache.lock.reclaim"
# `held` gates the release trap so we only ever remove a lock we actually own.
# `reclaiming` gates cleanup of the reclaim mutex if we are killed mid-reclaim.
held=0
reclaiming=0
release_lock() {
  # Drop the reclaim mutex first if a signal caught us inside reclaim_if_stale,
  # so an interrupted reclaim can't wedge future warms (Codex P3). SIGKILL still
  # bypasses this, but the reclaim mutex is held only across O(1) filesystem
  # calls — never the long copy the warm timeout SIGKILLs — so a leak needs a
  # host crash in that window, and even then the next warm fails loud, never
  # silently double-writes.
  if [ "$reclaiming" -eq 1 ]; then
    rmdir "$reclaim_lock_dir" 2>/dev/null || true
    reclaiming=0
  fi
  if [ "$held" -eq 1 ]; then
    rm -f "$lock_dir" 2>/dev/null || true
  fi
}

# The current holder's PID, or empty if there is no lock. Reads the symlink
# target; also understands a legacy mkdir+pid-file lock so a stale one left by a
# pre-upgrade warmer is still reclaimable (deployment is atomic, so old and new
# warmers never run concurrently).
lock_owner() {
  if [ -L "$lock_dir" ]; then
    readlink "$lock_dir" 2>/dev/null || true
  elif [ -d "$lock_dir" ] && [ -f "$lock_dir/pid" ]; then
    cat "$lock_dir/pid" 2>/dev/null || true
  fi
}

# Reclaim a lock whose holder PID is no longer alive.
#
# The destructive removal is the dangerous step: a bare check-then-remove lets
# two waiters that both judged the lock stale race so that the second removes a
# lock the first FRESHLY re-acquired (an ABA), leaving two live holders in the
# docroot at once. This path is hot in practice because the warmer's wall-clock
# timeout SIGKILLs the process group, skipping the EXIT trap, so a stale lock is
# the expected residue of any timed-out warm.
#
# Close it by serializing reclamation under a second, briefly-held mutex
# (reclaim_lock_dir) AND re-reading the holder PID while holding it. Under that
# mutex the lock cannot transition dead->live between the check and the remove:
# nobody can create "$lock_dir" while it still exists, and no other reclaimer can
# run. So we only ever remove a lock that is *still* dead. Returns 0 if it
# removed a stale lock (caller should retry the acquire), non-zero otherwise.
#
# An empty owner here means a legacy/corrupt lock, never a live symlink lock (a
# live one always carries its pid atomically), so it is safe to reclaim.
reclaim_if_stale() {
  local owner
  mkdir "$reclaim_lock_dir" 2>/dev/null || return 1
  reclaiming=1
  owner="$(lock_owner)"
  if { [ -L "$lock_dir" ] || [ -d "$lock_dir" ]; } \
    && { [ -z "$owner" ] || ! kill -0 "$owner" 2>/dev/null; }; then
    echo "warn: reclaiming stale lock $lock_dir (owner PID '${owner:-unknown}' not alive)." >&2
    rm -rf "$lock_dir" 2>/dev/null || true
    rmdir "$reclaim_lock_dir" 2>/dev/null || true
    reclaiming=0
    return 0
  fi
  rmdir "$reclaim_lock_dir" 2>/dev/null || true
  reclaiming=0
  return 1
}

# Acquire the host-level warm lock, waiting out a live holder (bounded to 60s of
# wall clock via $SECONDS, independent of the poll interval) and reclaiming a
# dead one via reclaim_if_stale. Exits non-zero if it can't acquire within the
# bound. WARM_LOCK_POLL_SECS tunes how often a waiter retries (default 1s; the
# tests set it small to exercise contention quickly).
acquire_lock() {
  local start=$SECONDS owner
  while true; do
    # `ln -s x DIR` does NOT fail when DIR is an existing directory — it silently
    # creates DIR/x and succeeds. A legacy mkdir-format lock is exactly such a
    # directory, so guard against it: only attempt the symlink when nothing sits
    # at the path. (No current code ever creates a directory here, so a directory
    # can only be a static pre-upgrade leftover — not something a peer races in,
    # so this check-then-ln is not a TOCTOU. Concurrent new warmers only ever
    # create symlinks, and `ln -s` is atomic and fails if a symlink exists.)
    if [ ! -d "$lock_dir" ] && ln -s "$$" "$lock_dir" 2>/dev/null; then
      break
    fi
    owner="$(lock_owner)"
    if [ -n "$owner" ] && kill -0 "$owner" 2>/dev/null; then
      : # live holder — fall through to the bounded wait below
    elif reclaim_if_stale; then
      continue # removed a stale lock (symlink or legacy dir); retry immediately
    fi
    # A live holder, or a stale lock another reclaimer is handling right now.
    if [ "$((SECONDS - start))" -ge 60 ]; then
      echo "error: could not acquire $lock_dir after $((SECONDS - start))s; warm held by PID '${owner:-unknown}'." >&2
      exit 1
    fi
    sleep "${WARM_LOCK_POLL_SECS:-1}"
  done
  # We hold it. The symlink already records our PID atomically; nothing to write.
  held=1
}
