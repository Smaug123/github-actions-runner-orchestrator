# shellcheck shell=bash
# Shared layout + validation for the Mac S3 cache/artifact store scripts.
#
# SOURCED (not executed) by serve-s3.sh (the server), setup-server.sh (the
# deployer) and test-s3.sh. Sharing one definition of where the data dir, the
# two credential files, the bucket names and the runner identity live means
# every script agrees with the others — no drift. Callers must `set -euo
# pipefail` before sourcing.
#
# This is the WRITE side of the self-hosted GitHub Actions cache: a single
# MinIO (S3-compatible) server on the Mac that backs both the build cache
# (tespkg/actions-cache) and the per-run artifact handoff (mc), so jobs stop
# hitting GitHub's external cache/artifact storage. It is deliberately separate
# from, and orthogonal to, the read-only Nix substituter in ../mac-cache: that
# one warms /nix/store; this one stores non-Nix build outputs. Neither gives a
# guest any write path into the host /nix/store.
#
# Defines: base, data_dir, keys_dir, root_env, runner_env, logs_dir, bind_addr,
# port, service_user, service_group, bucket_cache, bucket_artifacts,
# runner_access_key, runner_secret_key, scoped_policy_name, github_secret_name,
# ilm_artifacts_days, ilm_cache_days; plus require_loopback_ipv4().

# This is a sourced library: every variable below is consumed by the scripts
# that source it, not by this file, so standalone shellcheck would flag them all
# as unused. Suppress that one false positive file-wide.
# shellcheck disable=SC2034

# Base dir is a SYSTEM location, never under a human $HOME. The daemon runs as a
# dedicated unprivileged user (service_user) and must traverse the data dir
# end-to-end AS ITSELF — it never starts as root (unlike mac-cache's chrooting
# darkhttpd), so a 0700 path under a human home would be unreachable. setup-server.sh
# (root) creates this whole tree. Only the *scripts* here are version-controlled.
base="${GHA_S3_DIR:-/usr/local/var/gha-mac-s3}"

# Layout: keys/ is a SIBLING of data/, never under it.
#   data/       MinIO backend (bucket objects + metadata); owned by service_user
#               0700; NEVER /nix/store.
#   root.env    MinIO superuser; root-owned, service-group-readable 0640 — the
#               daemon reads it to start MinIO but cannot modify it (so a setup
#               rerun that sources it as root can't run daemon-injected content).
#   runner.env  the bucket-scoped runner SECRET; owned by the HUMAN 0600 — read
#               to register the GitHub secret and by the tests, NOT by the
#               daemon (the service user cannot read it).
# keys/ itself is root-owned and world-traversable (0755): it contains nothing
# world-readable (the env files are 0640/0600, group/owner only), and the daemon
# + the human each need to traverse it to reach their own file.
data_dir="$base/data"
keys_dir="$base/keys"
root_env="$keys_dir/root.env"
runner_env="$keys_dir/runner.env"

# Loopback ONLY (enforced by require_loopback_ipv4 below; default 127.0.0.1) —
# identical bind model to ../mac-cache: Lima's vz guests reach the host's
# 127.0.0.1:PORT as host.lima.internal:PORT through the in-process usernet
# gateway, and loopback is not LAN-routable. A non-loopback override is refused,
# so the loopback trust boundary can't be misconfigured away. 9000 is MinIO's
# conventional S3 API port. The web console is disabled entirely (serve-s3.sh
# sets MINIO_BROWSER=off), so no second port is exposed; `mc admin` still works
# over the API port.
bind_addr="${GHA_S3_BIND_ADDR:-127.0.0.1}"
port="${GHA_S3_PORT:-9000}"

# Dedicated unprivileged principal the daemon runs as (set as the LaunchDaemon's
# UserName). It owns data/ and root.env; it canNOT read runner.env.
service_user="${GHA_S3_USER:-_gha-s3}"
service_group="${GHA_S3_GROUP:-$service_user}"

# Two buckets, two lifetimes (see README "Buckets"):
#   - cache:     cross-run build cache (tespkg/actions-cache). Capped, not 1-day.
#   - artifacts: per-run job-to-job handoff (mc). Expires fast, mirroring the
#                workflow's old `retention-days: 1`.
bucket_cache="${GHA_S3_BUCKET_CACHE:-gha-actions-cache}"
bucket_artifacts="${GHA_S3_BUCKET_ARTIFACTS:-gha-actions-artifacts}"
ilm_artifacts_days="${GHA_S3_ARTIFACTS_EXPIRE_DAYS:-1}"
ilm_cache_days="${GHA_S3_CACHE_EXPIRE_DAYS:-14}"

# The runner's identity. The access-key id is NOT secret — it is committed in
# the consumer workflow as S3_ACCESS_KEY. The secret key is a REAL generated
# value (setup-server.sh, openssl), kept host-side in runner_env and registered
# as the consumer repo's GitHub secret (github_secret_name); it is never
# committed. The IAM policy attached to this account (setup-server.sh) permits
# object CRUD + listing on ONLY the two buckets above: no admin, no bucket
# creation, no other buckets. We load the secret here when it is readable (the
# scripts that need it — provisioning, tests — run as the human or as root); the
# daemon neither needs nor can read it.
runner_access_key="${GHA_S3_RUNNER_ACCESS_KEY:-gha-runner}"
scoped_policy_name="${GHA_S3_RUNNER_POLICY:-gha-runner-scoped}"
github_secret_name="${GHA_S3_GITHUB_SECRET:-S3_CACHE_SECRET_KEY}"
runner_secret_key="${GHA_S3_RUNNER_SECRET_KEY:-}"
if [ -z "$runner_secret_key" ] && [ -r "$runner_env" ]; then
  # shellcheck disable=SC1090  # runner_env is a runtime path computed above
  runner_secret_key="$( . "$runner_env"; printf '%s' "${RUNNER_SECRET_KEY:-}" )" || runner_secret_key=""
fi

logs_dir="/Library/Logs/gha-mac-s3"

# Reject empty / metacharacter-laden names before they reach a bucket path,
# `mc` argument, or IAM policy. Bucket names additionally must be DNS-safe for
# S3 (lowercase, 3-63 chars, no leading/trailing hyphen).
_validate_bucket() {
  local b=$1
  case "$b" in
    "" | *[!a-z0-9-]* | -* | *- ) return 1 ;;
  esac
  [ "${#b}" -ge 3 ] && [ "${#b}" -le 63 ]
}
for _b in "$bucket_cache" "$bucket_artifacts"; do
  _validate_bucket "$_b" || {
    echo "error: bucket name '$_b' is not a DNS-safe S3 name ([a-z0-9-], 3-63, no leading/trailing '-')." >&2
    exit 1
  }
done
case "$service_user" in
  "" | *[!A-Za-z0-9._-]* | *..* )
    echo "error: GHA_S3_USER must be a non-empty name of [A-Za-z0-9._-] with no '..'; got '$service_user'." >&2
    exit 1 ;;
esac
case "$runner_access_key" in
  "" | *[!A-Za-z0-9._-]* )
    echo "error: runner access key must be a non-empty [A-Za-z0-9._-] id; got '$runner_access_key'." >&2
    exit 1 ;;
esac
if [ -n "$runner_secret_key" ]; then
  case "$runner_secret_key" in
    *[!A-Za-z0-9._-]* )
      echo "error: runner secret must be [A-Za-z0-9._-] (URL-safe, embeddable in an MC_HOST connection string)." >&2
      exit 1 ;;
  esac
fi

# A CANONICAL specific IPv4 in the LOOPBACK range 127.0.0.0/8 — nothing else.
# The store's whole trust model is "loopback only, reached by guests via Lima's
# usernet forward (host.lima.internal -> 127.0.0.1)"; binding any non-loopback
# address (e.g. a LAN IP) would expose the write-capable S3 + admin API to the
# network. So beyond rejecting any-address / IPv6 / abbreviated inet_aton forms
# (0, 0.0, leading zeros, ...), the first octet MUST be 127 — which also rejects
# 0.0.0.0. MinIO parses --address with the Go net stack; this is the guard that
# keeps a fat-fingered GHA_S3_BIND_ADDR from binding off-loopback.
require_loopback_ipv4() {
  local addr=$1 oct first=""
  case "$addr" in
    "" | *[!0-9.]* | .* | *. | *..*) return 1 ;;
  esac
  local IFS=.
  # shellcheck disable=SC2206  # deliberate split on '.' into octets
  local parts=( $addr )
  [ "${#parts[@]}" -eq 4 ] || return 1
  for oct in "${parts[@]}"; do
    [ -n "$oct" ] || return 1
    [ "${#oct}" -le 3 ] || return 1
    case "$oct" in 0?*) return 1 ;; esac
    [ "$oct" -le 255 ] || return 1
    [ -z "$first" ] && first="$oct"
  done
  [ "$first" -eq 127 ]
}
