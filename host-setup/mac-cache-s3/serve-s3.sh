#!/usr/bin/env bash
# Serve the Mac S3 cache/artifact store (MinIO).
#
# This is the single ExecStart for the launchd daemon that setup-server.sh
# installs. Unlike mac-cache's serve-cache.sh it needs NO root and NO privilege
# drop: MinIO does not require root, so the daemon runs directly AS the dedicated
# unprivileged service user (set via the plist's UserName). This script just
# validates its inputs and execs the server.
#
# Run modes:
#   - under launchd as $service_user (production): reads root.env (root-owned,
#     readable by the service group) and serves the data dir.
#   - local dev/test: run it AS the service user — `sudo -u <service_user>
#     ./serve-s3.sh` — since root.env is owned by that user, a human-owned run
#     can't read the credentials. Stop with Ctrl-C.
#
# Hardening, weakest-to-strongest is inverted from mac-cache because there is no
# secret IN the served tree here (the data dir holds only bucket objects):
#   - bind a specific loopback address only, never an any-address (validated).
#   - the web console is disabled entirely (MINIO_BROWSER=off): no UI, no second
#     port; `mc admin` still works over the API port for provisioning.
#   - the root password lives OUTSIDE the data dir, in keys/, owner-only.
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "$dir/common.sh"

minio_bin="${GHA_MINIO:-$(command -v minio || true)}"
if [ -z "$minio_bin" ] || [ ! -x "$minio_bin" ]; then
  echo "error: minio not found; 'brew install minio/stable/minio' or set GHA_MINIO." >&2
  exit 1
fi

if ! require_loopback_ipv4 "$bind_addr"; then
  echo "error: GHA_S3_BIND_ADDR='$bind_addr' must be a loopback address (127.0.0.0/8). The store is loopback-only — guests reach it via Lima's usernet forward; a non-loopback bind would expose the write-capable S3 + admin API to the network." >&2
  exit 1
fi

if [ -L "$data_dir" ]; then
  echo "error: data dir $data_dir is a symlink; refusing." >&2
  exit 1
fi
if [ ! -d "$data_dir" ]; then
  echo "error: data dir $data_dir not found; run setup-server.sh first (it creates the store)." >&2
  exit 1
fi
if [ ! -f "$root_env" ]; then
  echo "error: $root_env missing; run setup-server.sh first (it creates the store)." >&2
  exit 1
fi
if [ -L "$root_env" ]; then
  echo "error: $root_env is a symlink; refusing." >&2
  exit 1
fi

# Load the superuser credentials into the environment MinIO reads at startup.
set -a
# shellcheck disable=SC1090  # path is computed in common.sh
. "$root_env"
set +a
if [ -z "${MINIO_ROOT_USER:-}" ] || [ -z "${MINIO_ROOT_PASSWORD:-}" ]; then
  echo "error: $root_env did not define MINIO_ROOT_USER / MINIO_ROOT_PASSWORD." >&2
  exit 1
fi

# No embedded web console: we drive everything via the S3 API + `mc admin`.
export MINIO_BROWSER=off

if [ "$(id -u)" -eq 0 ]; then
  # The launchd plist runs us as $service_user, never root. If we somehow got
  # here as root, refuse: a root-owned MinIO would write the whole data tree
  # root-owned and defeat the unprivileged-principal design.
  echo "error: running as root; the daemon must run as the unprivileged $service_user (set via the plist UserName)." >&2
  exit 1
fi

running_as="$(id -un)"
if [ "$running_as" != "$service_user" ]; then
  echo "WARNING: serving as '$running_as', not '$service_user' — DEV MODE (local testing only)." >&2
fi

echo "Serving MinIO from $data_dir on $bind_addr:$port as $running_as (browser off)."
exec "$minio_bin" server "$data_dir" --address "$bind_addr:$port" --quiet
