#!/bin/bash
# Deploy the Mac S3 cache/artifact store under launchd, then provision it.
#
# PRIVILEGED, all-in-one slice. Run as root (via sudo). It:
#   1. Creates the dedicated unprivileged service user+group (default _gha-s3):
#      hidden, no login shell, no real home. The daemon runs AS this user
#      (MinIO needs no root), so the store must live where that user can
#      traverse it end-to-end — hence a SYSTEM path (default /usr/local/var),
#      NOT a human home (see common.sh).
#   2. Creates the store tree and GENERATES the two credentials (idempotent,
#      never regenerated once present):
#        - root.env   MinIO superuser, owned by the service user 0600.
#        - runner.env the bucket-scoped runner SECRET, owned by the HUMAN 0600 —
#          you register it as the consumer repo's GitHub secret; the daemon
#          cannot read it.
#   3. Installs root-owned copies of serve-s3.sh, common.sh, `minio` and `mc`
#      into a root-only tree and points the daemon at them — never executing
#      code (script or binary) from a user-writable path (as mac-cache does).
#   4. Installs + loads the LaunchDaemon (runs as the service user), waits for
#      readiness, then PROVISIONS via `mc` with the root creds: the two buckets,
#      their expiry (ILM), the bucket-scoped runner account, and an ASSERTION
#      that that account cannot reach admin or any other bucket.
#   5. Prints the `gh secret set` command to register the runner secret.
#
# Idempotent — safe to re-run (picks up script/binary updates; repairs the
# account; never touches existing credentials or bucket data).
#
# Usage:
#   sudo ./setup-server.sh                  # install + load + provision
#   sudo ./setup-server.sh uninstall        # bootout + remove plist (keeps user, data, secrets)
#   sudo ./setup-server.sh uninstall --purge-user   # also delete the user+group
#        ./setup-server.sh print-plist      # emit the plist (no root)
#
# Overrides (env): GHA_S3_DIR (default /usr/local/var/gha-mac-s3),
# GHA_S3_BIND_ADDR (127.0.0.1), GHA_S3_PORT (9000), GHA_S3_USER/GHA_S3_GROUP
# (_gha-s3), GHA_MINIO / GHA_MC (binary paths), GHA_S3_LABEL (launchd label),
# GHA_S3_LIBEXEC (install dir).
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin   # see mac-cache/setup-server.sh

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
serve_script="$dir/serve-s3.sh"

label="${GHA_S3_LABEL:-uk.co.patrickstevens.gha-mac-s3}"
plist_path="/Library/LaunchDaemons/$label.plist"
install_dir="${GHA_S3_LIBEXEC:-/usr/local/libexec/gha-mac-s3}"
id_start="${GHA_S3_ID_START:-300}"
id_end="${GHA_S3_ID_END:-399}"

die() { echo "error: $*" >&2; exit 1; }

xml_escape() {
  local s=$1; s=${s//&/&amp;}; s=${s//</&lt;}; s=${s//>/&gt;}; printf '%s' "$s"
}

# The store base is a fixed system path (NOT derived from a human home — the
# daemon, an unprivileged dedicated user, must traverse it). Resolve it, require
# absolute, then source the shared layout. Also resolve the HUMAN who will own
# runner.env (SUDO_USER under sudo; root if invoked as a root login).
owner_user=""; owner_uid=0; owner_gid=0
prepare_paths() {
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    owner_user="$SUDO_USER"
    owner_uid="$(id -u "$SUDO_USER" 2>/dev/null || echo 0)"
    owner_gid="$(id -g "$SUDO_USER" 2>/dev/null || echo 0)"
  else
    owner_user="root"; owner_uid=0; owner_gid=0
  fi
  if [ -n "${GHA_S3_DIR:-}" ] && [ -d "$GHA_S3_DIR" ]; then
    GHA_S3_DIR="$(cd "$GHA_S3_DIR" && pwd -P)"; export GHA_S3_DIR
  fi
  # shellcheck source=./common.sh
  . "$dir/common.sh"
  case "$base" in /*) : ;; *) die "store base must be absolute (launchd has no usable cwd); got '$base'." ;; esac
  GHA_S3_DIR="$base"; export GHA_S3_DIR
}

resolve_bin() {  # $1=env override, $2=command name -> echoes absolute path
  local override=$1 name=$2 c
  if [ -n "$override" ]; then
    [ -x "$override" ] || die "$name override '$override' is not executable."
    echo "$override"; return 0
  fi
  for c in "/opt/homebrew/bin/$name" "/usr/local/bin/$name" "$(command -v "$name" 2>/dev/null || true)"; do
    if [ -n "$c" ] && [ -x "$c" ]; then echo "$c"; return 0; fi
  done
  die "$name not found; 'brew install minio/stable/$name' or set GHA_$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')."
}

# Assert a path and every ancestor is root-owned and not group/other/ACL
# writable — see mac-cache/setup-server.sh for the full rationale (a daemon must
# not run code from a path a non-root user can swap).
assert_root_only() {
  local p owner mode grp oth
  p="$(cd "$1" 2>/dev/null && pwd -P)" || die "$1 does not exist or is not a directory."
  while :; do
    owner="$(stat -f '%u' "$p")"; mode="$(stat -f '%Lp' "$p")"
    [ "$owner" -eq 0 ] || die "$p is owned by uid $owner, not root — set GHA_S3_LIBEXEC to a root-only dir."
    grp="${mode: -2:1}"; oth="${mode: -1}"
    case "$grp" in [2367]) die "$p is group-writable (mode $mode)." ;; esac
    case "$oth" in [2367]) die "$p is world-writable (mode $mode)." ;; esac
    if /bin/ls -lde "$p" 2>/dev/null | grep -qE '^[[:space:]]*[0-9]+: '; then
      die "$p carries an ACL that could grant write — strip it (chmod -N) or set GHA_S3_LIBEXEC elsewhere."
    fi
    [ "$p" = "/" ] && break
    p="$(dirname "$p")"
  done
}

# Create the store tree with split ownership (see common.sh "Layout") and
# generate the two credentials. Never regenerate an existing credential:
# rotating root.env would lock the running daemon's `mc admin` out, and rotating
# runner.env would desync the already-registered GitHub secret + MinIO account.
runner_secret_generated=0
gen_store() {
  echo "creating store tree under $base ..."
  install -d -o root -g wheel -m 755 "$base"
  install -d -o root -g wheel -m 755 "$keys_dir"
  install -d -o "$uid" -g "$gid" -m 700 "$data_dir"

  # root.env is root-owned and service-group-readable (0640): the daemon reads it
  # to start MinIO but CANNOT modify it. That matters because setup-server reruns
  # read it AS ROOT — if the daemon (service_user) could write it, a daemon
  # compromise would become root code execution on the next rerun.
  if [ -e "$root_env" ]; then
    [ ! -L "$root_env" ] || die "$root_env is a symlink; refusing."
    chown "root:$gid" "$root_env"; chmod 640 "$root_env"
    echo "MinIO root credentials already present (left untouched)."
  else
    echo "generating MinIO root credentials -> $root_env ..."
    local tmp; tmp="$(mktemp)"
    {
      printf 'MINIO_ROOT_USER=%s\n'     "gha-mac-s3-root"
      printf 'MINIO_ROOT_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    } >"$tmp"
    install -o root -g "$gid" -m 640 "$tmp" "$root_env"
    rm -f "$tmp"
  fi

  if [ -e "$runner_env" ]; then
    [ ! -L "$runner_env" ] || die "$runner_env is a symlink; refusing."
    chown "$owner_uid:$owner_gid" "$runner_env"; chmod 600 "$runner_env"
    echo "runner secret already present (left untouched)."
  else
    echo "generating runner secret -> $runner_env (owned by $owner_user) ..."
    local tmp; tmp="$(mktemp)"
    printf 'RUNNER_SECRET_KEY=%s\n' "$(openssl rand -hex 24)" >"$tmp"
    install -o "$owner_uid" -g "$owner_gid" -m 600 "$tmp" "$runner_env"
    rm -f "$tmp"
    runner_secret_generated=1
  fi
}

install_files() {
  [ -f "$dir/common.sh" ] || die "common.sh not found next to this script."
  echo "installing daemon files to $install_dir (root:wheel)..."
  install -d -o root -g wheel -m 755 "$install_dir"
  install_dir="$(cd "$install_dir" && pwd -P)" || die "cannot resolve install dir."
  assert_root_only "$install_dir"
  installed_serve="$install_dir/serve-s3.sh"
  installed_minio="$install_dir/minio"
  installed_mc="$install_dir/mc"
  install -o root -g wheel -m 644 "$serve_script" "$installed_serve"
  install -o root -g wheel -m 644 "$dir/common.sh" "$install_dir/common.sh"
  install -o root -g wheel -m 755 "$minio_bin" "$installed_minio"
  install -o root -g wheel -m 755 "$mc_bin" "$installed_mc"
}

emit_plist() {
  # Runs as $service_user (UserName/GroupName) — MinIO needs no root. PATH is
  # root-owned system dirs only. GHA_MINIO is the absolute installed copy, so
  # serve-s3.sh does no PATH lookup of the server binary.
  local e_label e_serve e_dir e_bind e_port e_user e_group e_minio e_out e_err
  e_label="$(xml_escape "$label")"; e_serve="$(xml_escape "$installed_serve")"
  e_dir="$(xml_escape "$GHA_S3_DIR")"; e_bind="$(xml_escape "$bind_addr")"
  e_port="$(xml_escape "$port")"; e_user="$(xml_escape "$service_user")"
  e_group="$(xml_escape "$service_group")"; e_minio="$(xml_escape "$installed_minio")"
  e_out="$(xml_escape "$logs_dir/minio.out.log")"; e_err="$(xml_escape "$logs_dir/minio.err.log")"
  cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$e_label</string>
    <key>UserName</key>
    <string>$e_user</string>
    <key>GroupName</key>
    <string>$e_group</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$e_serve</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>GHA_S3_DIR</key>
        <string>$e_dir</string>
        <key>GHA_S3_BIND_ADDR</key>
        <string>$e_bind</string>
        <key>GHA_S3_PORT</key>
        <string>$e_port</string>
        <key>GHA_MINIO</key>
        <string>$e_minio</string>
        <key>PATH</key>
        <string>/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>$e_out</string>
    <key>StandardErrorPath</key>
    <string>$e_err</string>
</dict>
</plist>
PLIST
}

id_in_use() {
  dscl . -list "$1" "$2" 2>/dev/null | awk -v want="$3" '$2 == want { f = 1 } END { exit f ? 0 : 1 }'
}
find_free_id() {
  local path=$1 key=$2 i
  for ((i = id_start; i <= id_end; i++)); do
    if ! id_in_use "$path" "$key" "$i"; then echo "$i"; return 0; fi
  done
  die "no free id in $id_start..$id_end for $path $key; widen GHA_S3_ID_START/END."
}
ensure_group() {
  if dscl . -read "/Groups/$service_group" >/dev/null 2>&1; then
    gid="$(dscl . -read "/Groups/$service_group" PrimaryGroupID 2>/dev/null | awk '{print $2}')"
    echo "group $service_group exists (gid $gid)."; return 0
  fi
  gid="$(find_free_id /Groups PrimaryGroupID)"
  echo "creating group $service_group (gid $gid)..."
  dscl . -create "/Groups/$service_group"
  dscl . -create "/Groups/$service_group" PrimaryGroupID "$gid"
  dscl . -create "/Groups/$service_group" RealName "GitHub Actions Mac S3 store"
  dscl . -create "/Groups/$service_group" Password "*"
}
ensure_user() {
  if dscl . -read "/Users/$service_user" >/dev/null 2>&1; then
    uid="$(dscl . -read "/Users/$service_user" UniqueID 2>/dev/null | awk '{print $2}')"
    echo "user $service_user exists (uid $uid)."
  else
    uid="$(find_free_id /Users UniqueID)"
    echo "creating user $service_user (uid $uid)..."
    dscl . -create "/Users/$service_user"
    dscl . -create "/Users/$service_user" UniqueID "$uid"
    dscl . -create "/Users/$service_user" PrimaryGroupID "$gid"
    dscl . -create "/Users/$service_user" RealName "GitHub Actions Mac S3 store"
    dscl . -create "/Users/$service_user" UserShell /usr/bin/false
    dscl . -create "/Users/$service_user" NFSHomeDirectory /var/empty
    dscl . -create "/Users/$service_user" Password "*"
    dscl . -create "/Users/$service_user" IsHidden 1
  fi
  [ "$uid" -ne 0 ] || die "$service_user resolved to uid 0; refusing (must be unprivileged)."
  # The daemon runs as this user; it must NOT be the human who owns runner.env
  # (default: SUDO_USER), or MinIO could read the runner secret and the
  # split-ownership model collapses. Caught early here; re-verified by a real
  # read-denied check after the files exist (assert_daemon_cannot_read_secret).
  [ "$uid" -ne "$owner_uid" ] || die "$service_user (uid $uid) owns runner.env ($owner_user); set GHA_S3_USER to a distinct dedicated user so the daemon cannot read the runner secret."
}

# Belt-and-braces for the split-ownership invariant: actually attempt to read
# runner.env AS the service user and abort if it succeeds (catches group/ACL
# readability that a uid check alone would miss — mirrors mac-cache's
# assert_cannot_read_key). root.env is legitimately the daemon's to read; only
# the runner secret must be out of its reach.
assert_daemon_cannot_read_secret() {
  if sudo -u "$service_user" /bin/test -r "$runner_env" 2>/dev/null; then
    die "SECURITY: $service_user can read $runner_env — the daemon would hold the runner secret. Aborting before loading the daemon."
  fi
  echo "verified: $service_user cannot read the runner secret ($runner_env)."
}

load_daemon() {
  launchctl bootout "system/$label" 2>/dev/null || true
  launchctl bootstrap system "$plist_path"
  launchctl enable "system/$label"
  launchctl kickstart -k "system/$label" 2>/dev/null || true
}

wait_ready() {
  local i
  for ((i = 0; i < 60; i++)); do
    if /usr/bin/curl -fsS "http://$bind_addr:$port/minio/health/ready" >/dev/null 2>&1; then
      echo "server is ready."; return 0
    fi
    sleep 1
  done
  die "server did not become ready on $bind_addr:$port within 60s; check $logs_dir/minio.err.log."
}

# --- provisioning (root creds + the installed mc; no persistent mc config) ---
mc_root() { MC_HOST_local="http://$MINIO_ROOT_USER:$MINIO_ROOT_PASSWORD@$bind_addr:$port" "$installed_mc" "$@"; }
mc_runner() { MC_HOST_run="http://$runner_access_key:$RUNNER_SECRET_KEY@$bind_addr:$port" "$installed_mc" "$@"; }

provision() {
  # root.env is now root-owned (the daemon can't modify it), so sourcing it as
  # root is safe; runner.env is owned by the operator who ran sudo (already
  # privileged). Both are simple KEY=value files we generate.
  set -a
  # shellcheck disable=SC1090  # $root_env is a runtime path from common.sh
  . "$root_env"
  set +a
  [ -n "${MINIO_ROOT_USER:-}" ] && [ -n "${MINIO_ROOT_PASSWORD:-}" ] || die "root.env incomplete."
  # shellcheck disable=SC1090  # $runner_env is a runtime path from common.sh
  . "$runner_env"
  [ -n "${RUNNER_SECRET_KEY:-}" ] || die "runner.env missing RUNNER_SECRET_KEY."

  echo "creating buckets..."
  mc_root mb --ignore-existing "local/$bucket_cache"
  mc_root mb --ignore-existing "local/$bucket_artifacts"

  echo "setting expiry (ILM) rules..."
  ensure_expiry "$bucket_cache" "$ilm_cache_days"
  ensure_expiry "$bucket_artifacts" "$ilm_artifacts_days"

  echo "creating bucket-scoped runner account '$runner_access_key'..."
  local pol; pol="$(mktemp)"
  cat >"$pol" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket", "s3:GetBucketLocation"],
      "Resource": [
        "arn:aws:s3:::$bucket_cache", "arn:aws:s3:::$bucket_cache/*",
        "arn:aws:s3:::$bucket_artifacts", "arn:aws:s3:::$bucket_artifacts/*"
      ]
    }
  ]
}
JSON
  # Recreate the user AND its policy authoritatively, so a re-run (e.g. after a
  # config change) cannot leave a previously-attached policy still granting the
  # account access beyond the two buckets — `policy attach` is additive, so we
  # must start from a clean slate. Removing the user first drops all of its
  # policy attachments (and lets `policy rm` succeed, since nothing references
  # it); then (re)create the scoped policy, re-add the user, and attach exactly
  # that one policy. `policy attach` is no longer tolerated-on-failure: the user
  # is freshly created, so it must succeed.
  mc_root admin user rm local "$runner_access_key" >/dev/null 2>&1 || true
  mc_root admin policy rm local "$scoped_policy_name" >/dev/null 2>&1 || true
  mc_root admin policy create local "$scoped_policy_name" "$pol"
  rm -f "$pol"
  mc_root admin user add local "$runner_access_key" "$RUNNER_SECRET_KEY"
  mc_root admin policy attach local "$scoped_policy_name" --user "$runner_access_key"

  assert_runner_scoped
}

ensure_expiry() {
  local bucket=$1 days=$2
  if mc_root ilm rule ls "local/$bucket" 2>/dev/null | grep -q .; then
    echo "  $bucket: an ILM rule already exists (left as-is; edit with 'mc ilm rule edit')."
  else
    mc_root ilm rule add "local/$bucket" --expire-days "$days"
    echo "  $bucket: objects expire after ${days}d."
  fi
}

# The trust model rests on the runner account being unable to do anything beyond
# object CRUD on the two buckets. Verify it on THIS deployment: it must write+read
# a probe, but must NOT reach the admin API or create a fresh bucket.
assert_runner_scoped() {
  echo "verifying the runner account is bucket-scoped..."
  local probe="setup-probe-$$" tf; tf="$(mktemp)"; echo ok >"$tf"
  mc_runner cp "$tf" "run/$bucket_artifacts/$probe" >/dev/null 2>&1 \
    || die "runner account cannot write $bucket_artifacts — policy attach failed."
  mc_runner rm "run/$bucket_artifacts/$probe" >/dev/null 2>&1 || true
  rm -f "$tf"

  if mc_runner admin info run >/dev/null 2>&1; then
    die "SECURITY: runner account '$runner_access_key' can reach the admin API — policy too broad. Aborting."
  fi

  # Create-bucket denial. The name MUST be DNS-safe, or `mc mb` fails on name
  # validation instead of on permission and the check would pass blindly even if
  # the policy allowed CreateBucket.
  local mkb="gha-deny-mb-probe-$$"
  if mc_runner mb "run/$mkb" >/dev/null 2>&1; then
    mc_root rb --force "local/$mkb" >/dev/null 2>&1 || true
    die "SECURITY: runner account can create buckets — policy too broad. Aborting."
  fi

  # Off-limits read denial, against a REAL third bucket the runner is not scoped
  # to (created + destroyed with root creds). A non-existent name would fail with
  # NoSuchBucket regardless of permission, so the probe must actually exist.
  local offb="gha-offlimits-probe-$$"
  mc_root mb --ignore-existing "local/$offb" >/dev/null 2>&1 \
    || die "could not create the off-limits probe bucket with root creds."
  if mc_runner ls "run/$offb" >/dev/null 2>&1; then
    mc_root rb --force "local/$offb" >/dev/null 2>&1 || true
    die "SECURITY: runner account can read a bucket outside its allowlist — policy too broad. Aborting."
  fi
  mc_root rb --force "local/$offb" >/dev/null 2>&1 || true

  echo "verified: runner account is limited to object CRUD on the two buckets."
}

require_root() { [ "$(id -u)" -eq 0 ] || die "must run as root: sudo $0 ${1:-install}"; }

cmd_install() {
  require_root install
  prepare_paths
  minio_bin="$(resolve_bin "${GHA_MINIO:-}" minio)"
  mc_bin="$(resolve_bin "${GHA_MC:-}" mc)"
  [ -f "$serve_script" ] || die "serve-s3.sh not found next to this script."

  ensure_group
  ensure_user
  gen_store
  assert_daemon_cannot_read_secret
  install_files

  # Owned by the service user: launchd opens StandardOut/ErrorPath AS the daemon's
  # user (UserName=$service_user), so a root-only log dir blocks the spawn
  # outright — no logs, MinIO never starts. (mac-cache's daemon runs as root, so
  # its root:wheel log dir is fine; ours must be writable by $service_user.)
  echo "creating log dir $logs_dir (owned by $service_user so the daemon can write)..."
  mkdir -p "$logs_dir"; chown "$uid:$gid" "$logs_dir"; chmod 750 "$logs_dir"

  echo "installing $plist_path..."
  local tmp; tmp="$(mktemp "/Library/LaunchDaemons/.$label.XXXXXX")"
  emit_plist >"$tmp"
  plutil -lint "$tmp" >/dev/null || { rm -f "$tmp"; die "generated plist failed plutil -lint."; }
  chown root:wheel "$tmp"; chmod 644 "$tmp"; mv -f "$tmp" "$plist_path"

  echo "loading daemon $label..."
  load_daemon
  wait_ready
  provision

  cat <<EOF

Done. S3 store deployed:
  data:      $data_dir   (MinIO backend, owned by $service_user; NEVER /nix/store)
  bind:      $bind_addr:$port   (loopback; guests reach it as host.lima.internal:$port)
  as user:   $service_user (uid $uid)
  files:     $install_dir   (root-owned copies the daemon runs)
  plist:     $plist_path
  logs:      $logs_dir/minio.{out,err}.log
  buckets:   $bucket_cache (expire ${ilm_cache_days}d), $bucket_artifacts (expire ${ilm_artifacts_days}d)
  runner:    access=$runner_access_key   secret in $runner_env (owned by $owner_user)

Register the runner secret with each consumer repo (one-time, per repo):
  ( . "$runner_env" && printf %s "\$RUNNER_SECRET_KEY" ) | gh secret set $github_secret_name -R <owner>/<repo>

Check it:  curl -sS http://$bind_addr:$port/minio/health/ready && echo OK
Status:    sudo launchctl print system/$label | grep -E 'state|pid'
Tests:     ./test-s3.sh             # host-side (+)/(-) checks (run as $owner_user)
           ./test-s3.sh --vm NAME   # guest-side (+)/(-) (use a throwaway VM)
EOF
  [ "$runner_secret_generated" -eq 1 ] && echo "(runner secret was freshly generated this run — register it now.)"
  return 0
}

cmd_uninstall() {
  require_root uninstall
  prepare_paths
  echo "booting out $label..."
  launchctl bootout "system/$label" 2>/dev/null || true
  [ -f "$plist_path" ] && { rm -f "$plist_path"; echo "removed $plist_path."; }
  install_dir="$(cd "$install_dir" 2>/dev/null && pwd -P || echo "$install_dir")"
  rm -f "$install_dir/serve-s3.sh" "$install_dir/common.sh" "$install_dir/minio" "$install_dir/mc"
  rmdir "$install_dir" 2>/dev/null && echo "removed now-empty $install_dir." || true
  if [ "${1:-}" = "--purge-user" ]; then
    echo "deleting user/group $service_user..."
    dscl . -delete "/Users/$service_user" 2>/dev/null || true
    dscl . -delete "/Groups/$service_group" 2>/dev/null || true
  else
    echo "left user $service_user, the data dir, and the credentials in place (pass --purge-user to delete the user)."
  fi
  echo "data + secrets left under $base; logs under $logs_dir."
}

cmd_print_plist() {
  prepare_paths
  minio_bin="$(resolve_bin "${GHA_MINIO:-}" minio)"; mc_bin="$(resolve_bin "${GHA_MC:-}" mc)"
  install_dir="$(cd "$install_dir" 2>/dev/null && pwd -P || echo "$install_dir")"
  installed_serve="$install_dir/serve-s3.sh"; installed_minio="$install_dir/minio"
  emit_plist
}

case "${1:-install}" in
  install) cmd_install ;;
  uninstall) shift || true; cmd_uninstall "${1:-}" ;;
  print-plist) cmd_print_plist ;;
  *) die "unknown command '${1:-}'; use: install | uninstall [--purge-user] | print-plist" ;;
esac
