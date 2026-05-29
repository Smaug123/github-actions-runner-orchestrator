#!/usr/bin/env bash
# (+)/(-) harness for the Mac S3 cache/artifact store.
#
# Host-side (default): asserts the server is up on loopback, the runner account
# can round-trip an object in BOTH buckets, and — the security-critical (-)
# checks — that the runner account CANNOT reach the admin API or create a new
# bucket. Mirrors mac-cache/test-cache.sh.
#
# Guest-side (--vm NAME): runs the same round-trip from INSIDE a Lima VM via
# host.lima.internal, proving the usernet forward reaches the store, and asserts
# the guest has no /nix/store write path (a sanity (-) check). Point --vm at a
# THROWAWAY VM, never a live gha-* runner.
#
#   ./test-s3.sh                 # host-side checks vs the running daemon
#   ./test-s3.sh --vm NAME       # also run guest-side checks inside Lima VM NAME
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "$dir/common.sh"

vm=""
case "${1:-}" in
  --vm) vm="${2:-}"; [ -n "$vm" ] || { echo "error: --vm needs a VM name." >&2; exit 2; } ;;
  "") : ;;
  *) echo "usage: $0 [--vm NAME]" >&2; exit 2 ;;
esac

mc_bin="${GHA_MC:-$(command -v mc || true)}"
[ -n "$mc_bin" ] && [ -x "$mc_bin" ] || { echo "error: mc not found; 'brew install minio/stable/mc' or set GHA_MC." >&2; exit 1; }

# The runner secret is loaded by common.sh from runner_env (0600, owned by the
# human). Empty means either setup-server.sh hasn't run or you are not the user
# who owns runner.env.
[ -n "$runner_secret_key" ] || {
  echo "error: runner secret unavailable — run setup-server.sh, and run this as the user who owns $runner_env." >&2
  exit 1
}

pass=0; fail=0
ok()   { printf '  [+] %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  [-] %s\n' "$1"; fail=$((fail + 1)); }
# expect_ok "desc" cmd...  / expect_fail "desc" cmd...
expect_ok()   { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d (expected success)"; fi; }
expect_fail() { local d=$1; shift; if "$@" >/dev/null 2>&1; then bad "$d (expected FAILURE — privilege boundary breached!)"; else ok "$d"; fi; }

mc_runner() { MC_HOST_run="http://$runner_access_key:$runner_secret_key@$bind_addr:$port" "$mc_bin" "$@"; }

echo "Host-side checks ($bind_addr:$port):"
expect_ok "server health endpoint responds" \
  /usr/bin/curl -fsS "http://$bind_addr:$port/minio/health/ready"

probe="__test_probe_$$"
tf="$(mktemp)"; echo "roundtrip-$$" >"$tf"; got="$(mktemp)"
for b in "$bucket_cache" "$bucket_artifacts"; do
  expect_ok "runner can PUT into $b"  mc_runner cp "$tf" "run/$b/$probe"
  if mc_runner cp "run/$b/$probe" "$got" >/dev/null 2>&1 && diff -q "$tf" "$got" >/dev/null 2>&1; then
    ok "runner can GET the same bytes from $b"
  else
    bad "runner GET/round-trip from $b"
  fi
  mc_runner rm "run/$b/$probe" >/dev/null 2>&1 || true
done
rm -f "$tf" "$got"

# (-) the privilege boundary: the runner account is object-CRUD on two buckets
# and nothing more.
expect_fail "runner CANNOT reach the admin API"      mc_runner admin info run
# DNS-safe name, so this fails for lack of CreateBucket permission, not because
# an invalid name fails `mb` regardless of policy.
expect_fail "runner CANNOT create a new bucket"      mc_runner mb "run/gha-deny-mb-probe-$$"
# Off-limits *read* denial needs a real third bucket created with root creds,
# which this runner-creds-only harness lacks; setup-server.sh's
# assert_runner_scoped performs that authoritative check at deploy time.

if [ -n "$vm" ]; then
  echo
  echo "Guest-side checks (inside Lima VM '$vm', via host.lima.internal:$port):"
  # mc is on PATH in the NixOS guest (nix/guest.nix adds pkgs.minio-client).
  # Use a connection string so no alias config is needed in the throwaway VM.
  guest_script=$(cat <<GUEST
set -e
export MC_HOST_h="http://$runner_access_key:$runner_secret_key@host.lima.internal:$port"
echo "guest-probe-\$\$" > /tmp/gp
mc cp /tmp/gp "h/$bucket_artifacts/__guest_probe_\$\$"
mc cp "h/$bucket_artifacts/__guest_probe_\$\$" /tmp/gp.back
diff -q /tmp/gp /tmp/gp.back
mc rm "h/$bucket_artifacts/__guest_probe_\$\$" || true
GUEST
)
  if limactl shell "$vm" -- bash -c "$guest_script" >/dev/null 2>&1; then
    ok "guest reaches the store over host.lima.internal and round-trips an object"
  else
    bad "guest round-trip via host.lima.internal failed (usernet forward / mc / creds)"
  fi
  # Sanity (-): the guest must have no write path into the host /nix/store. The
  # store isn't mounted into the guest at all (mounts: []), so a write attempt
  # to a host path is meaningless; assert the guest's own /nix/store is not the
  # host's by checking the mount is local, not a host share.
  if limactl shell "$vm" -- bash -c 'mount | grep -E " /nix/store " | grep -qiE "virtiofs|9p|sshfs|nfs"' >/dev/null 2>&1; then
    bad "guest /nix/store appears to be a host share — unexpected write path"
  else
    ok "guest /nix/store is local to the VM, not a host share (no host-store write path)"
  fi
fi

echo
echo "Summary: $pass passed, $fail failed."
[ "$fail" -eq 0 ]
