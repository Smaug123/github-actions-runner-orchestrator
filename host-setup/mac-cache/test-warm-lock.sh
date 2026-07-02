#!/usr/bin/env bash
# Tests for the shared host-level warm lock in common.sh.
#
# CI runs only the Rust + Nix jobs, so this is a manual/local harness (like
# test-cache.sh). It covers the correctness properties that matter for the lock:
#
#   * reclaim_if_stale removes a lock whose holder PID is dead;
#   * reclaim_if_stale REFUSES to remove a lock whose holder PID is alive — this
#     is the ABA guard: a waiter that judged the lock stale must not delete a
#     lock a peer freshly re-acquired;
#   * reclaim_if_stale is serialized (fails while the reclaim mutex is held);
#   * under heavy contention against a seeded stale lock, at most ONE warmer ever
#     holds the lock at a time, and every warmer eventually acquires it.
#
# Run: ./test-warm-lock.sh   (exit 0 = all pass, non-zero = a property failed)
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
common="$dir/common.sh"

fails=0
ok() { printf 'ok   - %s\n' "$1"; }
bad() { printf 'FAIL - %s\n' "$1" >&2; fails=$((fails + 1)); }

# A PID that is (almost) certainly not alive: kill -0 on it fails.
dead_pid() {
  local p
  for p in 2147483646 999999 4194303; do
    if ! kill -0 "$p" 2>/dev/null; then
      printf '%s\n' "$p"
      return 0
    fi
  done
  printf '2147483646\n'
}

# Point GHA_CACHE_DIR at a fresh throwaway sandbox, or abort.
#
# Deliberately NOT `GHA_CACHE_DIR="$(make_tempdir)"`: errexit does not reliably
# propagate out of a command substitution, so a failed mktemp there would leave
# GHA_CACHE_DIR empty and the tests would then run against the REAL cache dir
# ($HOME/.local/share/gha-mac-cache), creating/removing the real warm lock. So
# assign then verify as statements in the main shell, and exit if the sandbox is
# not a fresh directory.
new_sandbox() {
  GHA_CACHE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/warmlock.XXXXXX")" || true
  if [ -z "${GHA_CACHE_DIR:-}" ] || [ ! -d "$GHA_CACHE_DIR" ]; then
    echo "FATAL: could not create a temp sandbox; refusing to touch a real cache dir" >&2
    exit 1
  fi
  export GHA_CACHE_DIR
}

# --- deterministic unit checks ----------------------------------------------

test_reclaim_removes_dead() {
  new_sandbox
  # shellcheck source=./common.sh
  . "$common"
  mkdir -p "$base"
  ln -s "$(dead_pid)" "$lock_dir"
  if reclaim_if_stale && [ ! -e "$lock_dir" ] && [ ! -L "$lock_dir" ]; then
    ok "reclaim_if_stale removes a dead-owner lock"
  else
    bad "reclaim_if_stale should have removed the dead-owner lock"
  fi
  rm -rf "$GHA_CACHE_DIR"
}

test_reclaim_spares_live() {
  new_sandbox
  # shellcheck source=./common.sh
  . "$common"
  mkdir -p "$base"
  # Our own PID is alive: reclaim must refuse, even though the caller reached the
  # reclaim path. This is the ABA guard.
  ln -s "$$" "$lock_dir"
  if reclaim_if_stale; then
    bad "reclaim_if_stale wrongly removed a LIVE-owner lock (ABA hole)"
  elif [ -L "$lock_dir" ] && [ "$(readlink "$lock_dir")" = "$$" ]; then
    ok "reclaim_if_stale spares a live-owner lock"
  else
    bad "reclaim_if_stale damaged a live-owner lock"
  fi
  rm -rf "$GHA_CACHE_DIR"
}

# A live symlink lock always carries its owner atomically, so the empty-owner
# reclaim window that a mkdir+pid-file lock has cannot occur: acquire records the
# pid in the same syscall that creates the lock.
test_acquire_records_owner_atomically() {
  new_sandbox
  # shellcheck source=./common.sh
  . "$common"
  mkdir -p "$base"
  acquire_lock
  if [ -L "$lock_dir" ] && [ "$(readlink "$lock_dir")" = "$$" ]; then
    ok "acquire_lock creates the lock with its owner set atomically"
  else
    bad "acquire_lock left the lock without an owner"
  fi
  release_lock
  if [ -L "$lock_dir" ] || [ -e "$lock_dir" ]; then
    bad "release_lock left the lock behind"
  else
    ok "release_lock removes the lock"
  fi
  rm -rf "$GHA_CACHE_DIR"
}

# acquire_lock must not be fooled by a legacy dir-format lock: `ln -s x DIR`
# silently creates DIR/x and "succeeds", so a naive acquire would think it holds
# the lock while a (possibly live) legacy dir lock sits there. A stale one must
# be reclaimed and replaced by our symlink; the path must end up as OUR symlink,
# never a directory with a nested link.
test_acquire_reclaims_legacy_dir() {
  new_sandbox
  # shellcheck source=./common.sh
  . "$common"
  mkdir -p "$base"
  mkdir "$lock_dir"
  dead_pid > "$lock_dir/pid"
  acquire_lock
  if [ -L "$lock_dir" ] && [ "$(readlink "$lock_dir")" = "$$" ]; then
    ok "acquire_lock reclaims a stale legacy dir lock and takes it as a symlink"
  else
    bad "acquire_lock did not properly take over a legacy dir lock"
  fi
  release_lock
  rm -rf "$GHA_CACHE_DIR"
}

# A stale legacy mkdir+pid-file lock (left by a pre-upgrade warmer) must still be
# reclaimable so an upgrade doesn't wedge on it.
test_reclaim_removes_legacy_dir() {
  new_sandbox
  # shellcheck source=./common.sh
  . "$common"
  mkdir -p "$base"
  mkdir "$lock_dir"
  dead_pid > "$lock_dir/pid"
  if reclaim_if_stale && [ ! -e "$lock_dir" ]; then
    ok "reclaim_if_stale removes a stale legacy dir-format lock"
  else
    bad "reclaim_if_stale should have removed the legacy dir lock"
  fi
  rm -rf "$GHA_CACHE_DIR"
}

test_reclaim_serialized() {
  new_sandbox
  # shellcheck source=./common.sh
  . "$common"
  mkdir -p "$base"
  ln -s "$(dead_pid)" "$lock_dir"
  # Simulate a concurrent reclaimer already inside the critical section.
  mkdir "$reclaim_lock_dir"
  if reclaim_if_stale; then
    bad "reclaim_if_stale ran while the reclaim mutex was held"
  else
    ok "reclaim_if_stale yields while another reclaimer holds the mutex"
  fi
  rmdir "$reclaim_lock_dir"
  rm -rf "$GHA_CACHE_DIR"
}

# The release trap must drop the reclaim mutex if a (trap-able) signal caught us
# mid-reclaim, so an interrupted reclaim can't wedge future warms (P3).
test_release_cleans_reclaim_mutex() {
  new_sandbox
  # shellcheck source=./common.sh
  . "$common"
  mkdir -p "$base"
  # Simulate being killed mid-reclaim: mutex held, reclaiming flag set.
  mkdir "$reclaim_lock_dir"
  reclaiming=1
  held=0
  release_lock
  if [ ! -d "$reclaim_lock_dir" ]; then
    ok "release_lock clears a held reclaim mutex"
  else
    bad "release_lock left the reclaim mutex behind (would wedge future warms)"
  fi
  rm -rf "$GHA_CACHE_DIR"
}

# --- contention / ABA stress ------------------------------------------------
# Seed a stale lock, then start K warmers at once so they race the reclaim.
# Each records IN <pid> on entering its critical section and OUT <pid> on exit
# (short lines -> atomic O_APPEND). Replaying the log must never show two holders
# at once. Repeat R rounds.
test_contention_no_overlap() {
  local K=12 R=12 round
  new_sandbox
  local worker="$GHA_CACHE_DIR/worker.sh"
  cat > "$worker" <<WORKER
#!/usr/bin/env bash
set -euo pipefail
export GHA_CACHE_DIR="\$1"
log="\$2"
export WARM_LOCK_POLL_SECS=0.02   # keep contention fast in the test
. "$common"
acquire_lock
printf 'IN %s\n' "\$\$" >> "\$log"
sleep 0.05
printf 'OUT %s\n' "\$\$" >> "\$log"
release_lock
WORKER
  chmod +x "$worker"

  local overlap=0 missing=0
  for round in $(seq 1 "$R"); do
    local sandbox log
    sandbox="$GHA_CACHE_DIR/round.$round"
    mkdir -p "$sandbox"
    log="$sandbox/log"
    : > "$log"
    # Seed a stale lock so every worker starts in the reclaim path.
    ln -s "$(dead_pid)" "$sandbox/warm-cache.lock"
    local pids=()
    for _ in $(seq 1 "$K"); do
      bash "$worker" "$sandbox" "$log" &
      pids+=("$!")
    done
    local p
    for p in "${pids[@]}"; do wait "$p" || true; done

    # Replay the log: held count must never exceed 1.
    local held=0 max=0 ins=0 op
    while read -r op _; do
      case "$op" in
        IN) held=$((held + 1)); ins=$((ins + 1)); [ "$held" -gt "$max" ] && max=$held ;;
        OUT) held=$((held - 1)) ;;
      esac
    done < "$log"
    [ "$max" -gt 1 ] && overlap=$((overlap + 1))
    [ "$ins" -ne "$K" ] && missing=$((missing + 1))
  done

  if [ "$overlap" -eq 0 ] && [ "$missing" -eq 0 ]; then
    ok "contention: no overlap across $R rounds x $K warmers; all acquired"
  else
    bad "contention: $overlap round(s) with >1 concurrent holder, $missing round(s) with a lost warmer"
  fi
  rm -rf "$GHA_CACHE_DIR"
}

test_reclaim_removes_dead
test_reclaim_spares_live
test_acquire_records_owner_atomically
test_acquire_reclaims_legacy_dir
test_reclaim_removes_legacy_dir
test_reclaim_serialized
test_release_cleans_reclaim_mutex
test_contention_no_overlap

if [ "$fails" -eq 0 ]; then
  echo "all warm-lock tests passed"
else
  echo "$fails warm-lock test(s) failed" >&2
  exit 1
fi
