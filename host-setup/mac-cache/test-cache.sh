#!/usr/bin/env bash
# (+)/(-) tests for the Mac signing cache server (Phase 3 / 3a, slice 2b).
#
# Proves the deploy contract from ROLLOUT_PLAN.md:
#   HOST-SIDE (no sudo; against the running daemon, or self-hosted with --dev):
#     (+) nix-cache-info is served (200, real StoreDir).
#     (-) autoindex is off: GET / -> 404 (no directory listing).
#     (-) path traversal is refused: GET /../../etc/passwd -> not 200.
#     (-) NOT the whole store: a live /nix/store path absent from the cache
#         -> 404 (we serve the curated docroot, not /nix/store).
#     (-) loopback only: the host's LAN address refuses the connection.
#     (-) serve-start gate: a symlink AND a hardlink to the signing key dropped
#         in the docroot make the server REFUSE TO START (so the key is never
#         served), instead of exposing it.
#   GUEST-SIDE (--vm NAME; run by the operator against a THROWAWAY Lima VM, not
#   a busy runner):
#     (+) a guest fetches nix-cache-info via host.lima.internal:PORT (200).
#     (-) a live /nix/store path is 404 from the guest too.
#
# Usage:
#   ./test-cache.sh                 # host-side checks vs the deployed daemon (127.0.0.1:8080)
#   ./test-cache.sh --dev           # host-side checks against a darkhttpd this script starts
#   ./test-cache.sh --vm gha-test   # also run the guest-side checks inside that VM
#   ./test-cache.sh --addr 127.0.0.1 --port 8080
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "$dir/common.sh"   # -> cache_dir, secret_key, key_name, ...

addr="127.0.0.1"
port="${GHA_CACHE_PORT:-8080}"
dev=0
vm=""
limactl="${GHA_LIMACTL:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --dev) dev=1 ;;
    --vm) shift; vm="${1:-}"; [ -n "$vm" ] || { echo "error: --vm needs a VM name" >&2; exit 2; } ;;
    --addr) shift; addr="${1:-}" ;;
    --port) shift; port="${1:-}" ;;
    --limactl) shift; limactl="${1:-}" ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "error: unknown arg '$1'" >&2; exit 2 ;;
  esac
  shift
done

pass=0 fail=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail + 1)); }
note() { printf '  ---- %s\n' "$1"; }

# HTTP status code for a URL (000 if the connection failed), bounded time.
# curl already prints "000" via -w on a failed connection; don't append another.
http_code() {
  local c
  c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@" 2>/dev/null)" || true
  printf '%s' "${c:-000}"
}

# A real regular file's path RELATIVE to /nix/store (e.g. "<hash>-foo/bin/foo").
# This is the actual leak the negative test must catch: it would be served (200)
# only if the docroot were wrongly the whole /nix/store, and 404s against the
# curated cache. A "<hash>.narinfo" name would NOT do — it doesn't exist under
# /nix/store, so it 404s even on a leak (a false pass). `|| true` neutralises
# find's SIGPIPE (exit 141) when head closes the pipe early under `pipefail`.
live_store_relpath() {
  local f
  f="$(find /nix/store -mindepth 2 -maxdepth 5 -type f 2>/dev/null | head -1 || true)"
  [ -n "$f" ] || return 1
  printf '%s' "${f#/nix/store/}"
}

host_checks() {
  local base="http://$addr:$port"
  echo "host-side checks against $base"

  local code
  code="$(http_code "$base/nix-cache-info")"
  if [ "$code" = "200" ] && curl -s --max-time 5 "$base/nix-cache-info" | grep -q '^StoreDir:'; then
    ok "(+) nix-cache-info served (200, has StoreDir)"
  else
    bad "(+) nix-cache-info not served as expected (got HTTP $code)"
  fi

  code="$(http_code "$base/")"
  if [ "$code" = "404" ]; then
    ok "(-) autoindex off: GET / -> 404"
  else
    bad "(-) GET / returned $code (expected 404; --no-listing should hide the dir)"
  fi

  code="$(curl -s -o /dev/null -w '%{http_code}' --path-as-is --max-time 5 "$base/../../../etc/passwd" 2>/dev/null || echo 000)"
  if [ "$code" != "200" ]; then
    ok "(-) path traversal refused: /../../../etc/passwd -> $code (not 200)"
  else
    bad "(-) path traversal returned 200 — server escaped its docroot!"
  fi

  local rel
  if rel="$(live_store_relpath)"; then
    code="$(http_code "$base/$rel")"
    if [ "$code" = "404" ]; then
      ok "(-) live /nix/store file not in cache -> 404 (curated, not whole store)"
    else
      bad "(-) /$rel returned $code (expected 404; is the live /nix/store being served?)"
    fi
  else
    note "skipped whole-store check (no /nix/store files found)"
  fi

  # Loopback-only: the host's own LAN address must refuse (server bound to
  # 127.0.0.1). Only meaningful when a non-loopback address exists.
  local lan
  lan="$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -vE '^(127\.|169\.254\.)' | head -1 || true)"
  if [ -n "$lan" ] && [ "$lan" != "$addr" ]; then
    code="$(http_code "http://$lan:$port/nix-cache-info")"
    if [ "$code" = "000" ]; then
      ok "(-) LAN address $lan:$port refuses (loopback-only bind)"
    else
      bad "(-) LAN address $lan:$port answered ($code) — server is NOT loopback-only!"
    fi
  else
    note "skipped LAN-bind check (no distinct non-loopback address)"
  fi
}

# Run serve-cache.sh (dev mode) against a throwaway base dir whose docroot
# contains $entry (a symlink or hardlink to the key). Expect it to EXIT NON-ZERO
# via the serve-start gate rather than start darkhttpd. Returns 0 if it refused.
gate_refuses() {
  local kind=$1 fake out rc port_t
  fake="$(mktemp -d)"
  mkdir -p "$fake/cache" "$fake/keys"
  cp "$secret_key" "$fake/keys/$key_name.secret"
  chmod 600 "$fake/keys/$key_name.secret"
  cp "$cache_dir/nix-cache-info" "$fake/cache/nix-cache-info" 2>/dev/null || echo 'StoreDir: /nix/store' >"$fake/cache/nix-cache-info"
  case "$kind" in
    symlink)  ln -s "$fake/keys/$key_name.secret" "$fake/cache/leaked.narinfo" ;;
    hardlink) ln    "$fake/keys/$key_name.secret" "$fake/cache/leaked.narinfo" ;;
  esac
  port_t=$((port + 1001))
  set +e
  GHA_CACHE_DIR="$fake" GHA_CACHE_BIND_ADDR=127.0.0.1 GHA_CACHE_PORT="$port_t" \
    GHA_DARKHTTPD="${GHA_DARKHTTPD:-$(command -v darkhttpd)}" \
    "$dir/serve-cache.sh" >/dev/null 2>"$fake/err" &
  local pid=$!
  # The gate runs before exec; a refusal exits immediately. If it's still alive
  # after a beat, the gate WRONGLY passed and darkhttpd is now serving.
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null; pkill -P "$pid" 2>/dev/null
    rc=99   # started a server -> gate did NOT refuse
  else
    wait "$pid"; rc=$?
  fi
  set -e
  out="$(cat "$fake/err" 2>/dev/null)"
  rm -rf "$fake"
  [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi 'gate'
}

gate_checks() {
  echo "serve-start gate (key planted in the docroot)"
  if [ ! -r "$secret_key" ]; then
    note "skipped gate checks (signing key not readable here; run init-cache.sh)"
    return
  fi
  if gate_refuses symlink; then
    ok "(-) symlink to key in docroot -> server refuses to start"
  else
    bad "(-) symlink to key in docroot did NOT stop the server"
  fi
  if gate_refuses hardlink; then
    ok "(-) hardlink to key in docroot -> server refuses to start"
  else
    bad "(-) hardlink to key in docroot did NOT stop the server"
  fi
}

resolve_limactl() {
  [ -n "$limactl" ] && { [ -x "$limactl" ] || command -v "$limactl" >/dev/null; } && return 0
  for c in "$(command -v limactl 2>/dev/null || true)" /opt/homebrew/bin/limactl; do
    if [ -n "$c" ] && [ -x "$c" ]; then limactl="$c"; return 0; fi
  done
  return 1
}

guest_checks() {
  echo "guest-side checks in VM '$vm' (reaching host.lima.internal:$port)"
  resolve_limactl || { bad "limactl not found (set --limactl)"; return; }
  local base="http://host.lima.internal:$port" code
  code="$("$limactl" shell "$vm" -- curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$base/nix-cache-info" 2>/dev/null || true)"; code="${code:-000}"
  if [ "$code" = "200" ]; then
    ok "(+) guest fetched nix-cache-info via host.lima.internal ($code)"
  else
    bad "(+) guest could not fetch nix-cache-info (got $code) — usernet forward / daemon down?"
  fi
  local rel
  if rel="$(live_store_relpath)"; then
    code="$("$limactl" shell "$vm" -- curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$base/$rel" 2>/dev/null || true)"; code="${code:-000}"
    if [ "$code" = "404" ]; then
      ok "(-) guest: live /nix/store file -> 404 (curated, not whole store)"
    else
      bad "(-) guest: /$rel returned $code (expected 404)"
    fi
  fi
}

# --- run ---
if [ "$dev" -eq 1 ]; then
  : "${GHA_DARKHTTPD:=$(command -v darkhttpd || true)}"
  [ -n "$GHA_DARKHTTPD" ] || { echo "error: darkhttpd not found for --dev (set GHA_DARKHTTPD)" >&2; exit 2; }
  export GHA_DARKHTTPD
  port=18080
  echo "--dev: starting darkhttpd on $addr:$port over $cache_dir ..."
  GHA_CACHE_BIND_ADDR="$addr" GHA_CACHE_PORT="$port" "$dir/serve-cache.sh" >/tmp/gha-test-serve.log 2>&1 &
  dev_pid=$!
  # Preserve the real exit status: serve-cache.sh exec's into darkhttpd, so
  # $dev_pid IS darkhttpd and the cleanup's pkill -P (no children) returns 1.
  # Capture $? first, and `|| true` each cleanup command so set -e doesn't abort
  # the trap before `exit "$rc"` (that's what was leaking a spurious 1).
  trap 'rc=$?; kill "$dev_pid" 2>/dev/null || true; pkill -P "$dev_pid" 2>/dev/null || true; exit "$rc"' EXIT
  sleep 1
  kill -0 "$dev_pid" 2>/dev/null || { echo "error: dev server failed to start:" >&2; cat /tmp/gha-test-serve.log >&2; exit 1; }
fi

host_checks
gate_checks
[ -n "$vm" ] && guest_checks

echo
echo "tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
