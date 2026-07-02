#!/bin/bash
# Deploy the Mac signing cache server under launchd (Phase 3 / 3a, slice 2b).
#
# This is the PRIVILEGED wiring slice. It must run as root (via `sudo`) because
# it creates a system user, installs a LaunchDaemon, and loads it. It does NOT
# touch the cache contents or the signing key — `init-cache.sh` (run as the
# signing user, no sudo) owns those. Run order: init-cache.sh first, then this.
#
# What it does (idempotent — safe to re-run):
#   1. Creates the dedicated unprivileged service user+group (default
#      `_gha-cache`): hidden, no login shell, no real home, no password. This is
#      the PRINCIPAL the server drops to — the whole symlink/hardlink defense
#      rests on it being UNABLE to read the 0600 signing key.
#   2. ASSERTS that capability holds on THIS machine: it actually tries to read
#      the key as the service user and aborts if it succeeds. The design is only
#      as good as this check passing, so we verify it rather than assume it.
#   3. Creates a root-owned log dir OUTSIDE the served docroot.
#   4. Generates, lint-checks (`plutil`), and installs the LaunchDaemon plist,
#      then (re)loads it. The daemon runs serve-cache.sh AS ROOT so it can
#      chroot into the docroot and drop to the service user (see serve-cache.sh).
#
# Bind address: 127.0.0.1 (loopback) by default. Lima's vz guests use the
# built-in user-mode network (192.168.5.0/24); there is NO real host interface
# at host.lima.internal (192.168.5.2) to bind — that address is virtual, inside
# Lima's in-process usernet gateway, which forwards `host.lima.internal:PORT` to
# the host's 127.0.0.1:PORT. So binding loopback is what makes the cache
# reachable from guests as host.lima.internal AND keeps it off the LAN (loopback
# is not routable). A `pf` rule would be redundant on loopback, so none is added
# (see README / ROLLOUT_PLAN.md "Bind model").
#
# Usage:
#   sudo ./setup-server.sh                 # install (default) + load the daemon
#   sudo ./setup-server.sh uninstall       # bootout + remove plist (keeps user)
#   sudo ./setup-server.sh uninstall --purge-user   # also delete the user+group
#        ./setup-server.sh print-plist     # emit the plist to stdout (no root)
#
# Overrides (env): GHA_CACHE_DIR (base; required when the invoking user can't be
# resolved), GHA_CACHE_BIND_ADDR (default 127.0.0.1), GHA_CACHE_PORT (8080),
# GHA_CACHE_USER/GHA_CACHE_GROUP (default _gha-cache), GHA_DARKHTTPD (darkhttpd
# path), GHA_CACHE_LABEL (launchd label).
set -euo pipefail
# This installer runs as root (via sudo) and invokes many utilities. Pin PATH to
# root-owned system dirs so a preserved/`-E` sudo PATH containing a user-writable
# dir can't make us resolve (and run as root) a planted stat/install/launchctl.
# The shebang is /bin/bash (absolute), not `env bash`, for the same reason.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
serve_script="$dir/serve-cache.sh"   # the in-checkout source (copied on install)

label="${GHA_CACHE_LABEL:-uk.co.patrickstevens.gha-mac-cache}"
plist_path="/Library/LaunchDaemons/$label.plist"
log_dir="/Library/Logs/gha-mac-cache"
# The root daemon must NOT execute scripts out of the (user-writable) checkout,
# or anyone who can write the checkout gets root code-execution on the next
# launch. Install root-owned copies of serve-cache.sh + common.sh here and point
# the plist at them. Must itself be a root-only-writable tree (asserted below).
install_dir="${GHA_CACHE_LIBEXEC:-/usr/local/libexec/gha-mac-cache}"
installed_serve="$install_dir/serve-cache.sh"
# darkhttpd is execed by the root daemon (it does the chroot + uid drop itself),
# so it too must be a root-owned binary on a root-only path — Homebrew's copy is
# user-writable. Snapshot it into the install tree; re-run setup to update.
installed_darkhttpd="$install_dir/darkhttpd"
serve_user="${GHA_CACHE_USER:-_gha-cache}"
serve_group="${GHA_CACHE_GROUP:-$serve_user}"
bind_addr="${GHA_CACHE_BIND_ADDR:-127.0.0.1}"
port="${GHA_CACHE_PORT:-8080}"
# Free-ID search window for the role account (Apple's hidden daemon users live
# below 500). Both ids are taken from here only when the account doesn't exist.
id_start="${GHA_CACHE_ID_START:-300}"
id_end="${GHA_CACHE_ID_END:-399}"

die() { echo "error: $*" >&2; exit 1; }

# Escape XML metacharacters so a valid path containing &, <, or > (e.g.
# /Volumes/A&B/...) produces well-formed plist text instead of breaking the
# heredoc and failing plutil -lint. & must be substituted first.
xml_escape() {
  local s=$1
  s=${s//&/&amp;}
  s=${s//</&lt;}
  s=${s//>/&gt;}
  printf '%s' "$s"
}

# --- resolve the cache base dir, then source the shared layout ---
# Run via sudo, $HOME is root's, which is NOT where init-cache.sh (run as the
# signing user) wrote the cache. Prefer an explicit GHA_CACHE_DIR; else, when
# invoked via sudo, derive it from SUDO_USER's home; a non-root run (e.g.
# print-plist for review) falls back to common.sh's own $HOME default. Only the
# root path insists on a definite base — root's $HOME would silently be wrong.
prepare_paths() {
  if [ -z "${GHA_CACHE_DIR:-}" ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    local home
    # `dscl -read` prints `NFSHomeDirectory: /Users/foo`; strip the key label and
    # keep the rest verbatim so a home directory containing spaces survives
    # (awk '{print $2}' would truncate it at the first space).
    home="$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p')"
    [ -n "$home" ] && { GHA_CACHE_DIR="$home/.local/share/gha-mac-cache"; export GHA_CACHE_DIR; }
  fi
  if [ "$(id -u)" -eq 0 ] && [ -z "${GHA_CACHE_DIR:-}" ]; then
    die "running as root: set GHA_CACHE_DIR (or run via 'sudo' as the signing user so SUDO_USER resolves); root's \$HOME is not where init-cache.sh wrote the cache."
  fi
  # The plist's GHA_CACHE_DIR must be ABSOLUTE: launchd starts with a different
  # cwd, so a relative base would send the daemon to the wrong tree. Canonicalise
  # an existing explicit value (resolves symlinks/.. too) before common.sh
  # derives cache_dir/secret_key from it.
  if [ -n "${GHA_CACHE_DIR:-}" ] && [ -d "$GHA_CACHE_DIR" ]; then
    GHA_CACHE_DIR="$(cd "$GHA_CACHE_DIR" && pwd -P)"; export GHA_CACHE_DIR
  fi
  # shellcheck source=./common.sh
  . "$dir/common.sh"   # -> base, cache_dir, secret_key, cache_info (uses GHA_CACHE_DIR)
  case "$base" in
    /*) : ;;
    *) die "cache base must be an absolute path (launchd has no usable cwd); got '$base'. Set GHA_CACHE_DIR to an absolute dir." ;;
  esac
  GHA_CACHE_DIR="$base"; export GHA_CACHE_DIR   # canonical absolute base for the plist
}

resolve_darkhttpd() {
  if [ -n "${GHA_DARKHTTPD:-}" ]; then
    [ -x "$GHA_DARKHTTPD" ] || die "GHA_DARKHTTPD=$GHA_DARKHTTPD is not executable."
    darkhttpd_bin="$GHA_DARKHTTPD"
    return 0
  fi
  # launchd has a minimal PATH and won't see Homebrew; resolve to an absolute
  # path here so the plist can hand the daemon an unambiguous binary.
  for c in /opt/homebrew/bin/darkhttpd /usr/local/bin/darkhttpd "$(command -v darkhttpd 2>/dev/null || true)"; do
    if [ -n "$c" ] && [ -x "$c" ]; then darkhttpd_bin="$c"; return 0; fi
  done
  die "darkhttpd not found; 'brew install darkhttpd' or set GHA_DARKHTTPD."
}

# Assert a path and EVERY ancestor up to / is owned by root and not writable by
# group or other. A root LaunchDaemon executes the script at this path, so a
# non-root-writable directory anywhere in the chain would let a non-root user
# swap the code (or rename a parent dir) and run as root. Fail closed.
assert_root_only() {
  local p owner mode grp oth
  # Canonicalise first: macOS `stat` does NOT follow symlinks, so a symlinked
  # ancestor would otherwise be judged by the LINK's mode (e.g. 0755) instead of
  # its (possibly writable) target. pwd -P resolves every component to a real
  # directory, so the walk below stats real dirs.
  p="$(cd "$1" 2>/dev/null && pwd -P)" || die "$1 does not exist or is not a directory."
  while :; do
    owner="$(stat -f '%u' "$p")"
    mode="$(stat -f '%Lp' "$p")"   # octal perm bits, e.g. 755 (or 4755 w/ setuid)
    [ "$owner" -eq 0 ] || die "$p is owned by uid $owner, not root — refusing to run a root daemon from a path a non-root user can replace. Set GHA_CACHE_LIBEXEC to a root-only dir."
    grp="${mode: -2:1}"; oth="${mode: -1}"   # group / other octal digit
    case "$grp" in [2367]) die "$p is group-writable (mode $mode) — a non-root user could inject code into the root daemon." ;; esac
    case "$oth" in [2367]) die "$p is world-writable (mode $mode) — a non-root user could inject code into the root daemon." ;; esac
    # A 0755 root-owned dir can STILL be writable via an ACL. Mode bits don't
    # show that, so reject any ACL on the chain (ACE lines look like " 0: ...").
    # The `@` xattr marker is NOT an ACL and prints no ACE lines, so it passes.
    if /bin/ls -lde "$p" 2>/dev/null | grep -qE '^[[:space:]]*[0-9]+: '; then
      die "$p carries an ACL that could grant a non-root user write — strip it (sudo chmod -N '$p') or set GHA_CACHE_LIBEXEC to a clean root-only dir."
    fi
    [ "$p" = "/" ] && break
    p="$(dirname "$p")"
  done
}

# Install root-owned copies of the daemon scripts into a root-only tree, so the
# privileged daemon never executes code out of the user-writable checkout (see
# install_dir). serve-cache.sh sources common.sh from its OWN dir, so both go in.
install_scripts() {
  [ -f "$dir/common.sh" ] || die "common.sh not found next to this script."
  echo "installing daemon scripts to $install_dir (root:wheel)..."
  install -d -o root -g wheel -m 755 "$install_dir"
  # Canonicalise and use the RESOLVED path everywhere (incl. the plist): pwd -P
  # strips any symlinked component, so launchd traverses a real, root-only path
  # and a later symlink swap can't repoint the root daemon. Then assert that real
  # chain is root-owned and not group/other-writable.
  install_dir="$(cd "$install_dir" && pwd -P)" || die "cannot resolve install dir."
  installed_serve="$install_dir/serve-cache.sh"
  installed_darkhttpd="$install_dir/darkhttpd"
  assert_root_only "$install_dir"
  install -o root -g wheel -m 644 "$serve_script" "$installed_serve"
  install -o root -g wheel -m 644 "$dir/common.sh" "$install_dir/common.sh"
  # Copy darkhttpd too (follows the Homebrew symlink, writes a root-owned regular
  # file) so the daemon never execs a user-writable binary as root.
  install -o root -g wheel -m 755 "$darkhttpd_bin" "$installed_darkhttpd"
}

emit_plist() {
  # The daemon runs as root (no UserName key) on purpose: serve-cache.sh needs
  # root to chroot into the docroot and privilege-drop to $serve_user. PATH is
  # ROOT-OWNED system dirs only — NOT /opt/homebrew/bin, which is user-writable;
  # serve-cache.sh runs as root and would otherwise resolve unqualified commands
  # (stat, find, id, ...) from a path a non-root user could plant binaries in.
  # darkhttpd is passed as the absolute root-owned copy, so no PATH lookup of it.
  # KeepAlive is Crashed-only (NOT plain true): a serve-start gate refusal is a
  # deliberate exit(1), and we want that to STAY down for the operator (fail
  # closed on possible tampering), not crash-loop — while a real darkhttpd crash
  # (signal) still restarts.
  local e_label e_serve e_dir e_keyname e_bind e_port e_user e_group e_dark e_out e_err
  e_label="$(xml_escape "$label")"
  e_serve="$(xml_escape "$installed_serve")"
  e_dir="$(xml_escape "$GHA_CACHE_DIR")"
  e_keyname="$(xml_escape "$key_name")"
  e_bind="$(xml_escape "$bind_addr")"
  e_port="$(xml_escape "$port")"
  e_user="$(xml_escape "$serve_user")"
  e_group="$(xml_escape "$serve_group")"
  e_dark="$(xml_escape "$installed_darkhttpd")"
  e_out="$(xml_escape "$log_dir/serve.out.log")"
  e_err="$(xml_escape "$log_dir/serve.err.log")"
  cat <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$e_label</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$e_serve</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>GHA_CACHE_DIR</key>
        <string>$e_dir</string>
        <key>GHA_CACHE_KEY_NAME</key>
        <string>$e_keyname</string>
        <key>GHA_CACHE_BIND_ADDR</key>
        <string>$e_bind</string>
        <key>GHA_CACHE_PORT</key>
        <string>$e_port</string>
        <key>GHA_CACHE_USER</key>
        <string>$e_user</string>
        <key>GHA_CACHE_GROUP</key>
        <string>$e_group</string>
        <key>GHA_DARKHTTPD</key>
        <string>$e_dark</string>
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

# --- free-id helpers ---
id_in_use() {
  # $1 = "/Users"|"/Groups", $2 = "UniqueID"|"PrimaryGroupID", $3 = numeric id
  dscl . -list "$1" "$2" 2>/dev/null | awk -v want="$3" '$2 == want { found = 1 } END { exit found ? 0 : 1 }'
}
find_free_id() {
  local path=$1 key=$2 i
  for ((i = id_start; i <= id_end; i++)); do
    if ! id_in_use "$path" "$key" "$i"; then echo "$i"; return 0; fi
  done
  die "no free id in $id_start..$id_end for $path $key; widen GHA_CACHE_ID_START/END."
}

ensure_group() {
  if dscl . -read "/Groups/$serve_group" >/dev/null 2>&1; then
    gid="$(dscl . -read "/Groups/$serve_group" PrimaryGroupID 2>/dev/null | awk '{print $2}')"
    echo "group $serve_group exists (gid $gid)."
    return 0
  fi
  gid="$(find_free_id /Groups PrimaryGroupID)"
  echo "creating group $serve_group (gid $gid)..."
  dscl . -create "/Groups/$serve_group"
  dscl . -create "/Groups/$serve_group" PrimaryGroupID "$gid"
  dscl . -create "/Groups/$serve_group" RealName "GitHub Actions Mac cache server"
  dscl . -create "/Groups/$serve_group" Password "*"
}

ensure_user() {
  if dscl . -read "/Users/$serve_user" >/dev/null 2>&1; then
    uid="$(dscl . -read "/Users/$serve_user" UniqueID 2>/dev/null | awk '{print $2}')"
    echo "user $serve_user exists (uid $uid)."
  else
    uid="$(find_free_id /Users UniqueID)"
    echo "creating user $serve_user (uid $uid)..."
    dscl . -create "/Users/$serve_user"
    dscl . -create "/Users/$serve_user" UniqueID "$uid"
    dscl . -create "/Users/$serve_user" PrimaryGroupID "$gid"
    dscl . -create "/Users/$serve_user" RealName "GitHub Actions Mac cache server"
    # No login: false shell, no real home, no password, hidden from the login UI.
    dscl . -create "/Users/$serve_user" UserShell /usr/bin/false
    dscl . -create "/Users/$serve_user" NFSHomeDirectory /var/empty
    dscl . -create "/Users/$serve_user" Password "*"
    dscl . -create "/Users/$serve_user" IsHidden 1
  fi
  [ "$uid" -ne 0 ] || die "$serve_user resolved to uid 0; refusing (must be unprivileged)."
}

# The crux of the whole design: the service user must NOT be able to read the
# signing key. Verify by actually attempting the read as that user (real open(),
# not just a mode guess) and abort the install if it succeeds. Belt-and-braces:
# the key is 0600 AND its parent keys/ dir is 0700-owned-by-the-signer, so a
# non-owner is blocked at directory traversal regardless of the key's own mode.
assert_cannot_read_key() {
  local owner
  owner="$(stat -f '%u' "$secret_key")"
  [ "$owner" -ne "$uid" ] || die "$serve_user (uid $uid) OWNS the signing key — pick a different service user."
  [ "$owner" -ne 0 ] || die "signing key is owned by root; it must be owned by the (unprivileged) signing user, not root."
  if sudo -u "$serve_user" /bin/test -r "$secret_key" 2>/dev/null; then
    die "SECURITY: $serve_user can read $secret_key — the symlink/hardlink defense is void. Aborting before loading the daemon."
  fi
  if sudo -u "$serve_user" /bin/cat "$secret_key" >/dev/null 2>&1; then
    die "SECURITY: $serve_user could read the signing key bytes — aborting."
  fi
  echo "verified: $serve_user cannot read $secret_key (capability check passed)."
}

load_daemon() {
  # Replace any prior instance, then bootstrap + enable + (re)start. bootout of a
  # not-loaded service is fine to ignore; bootstrap fails if already loaded, so
  # always bootout first.
  launchctl bootout "system/$label" 2>/dev/null || true
  launchctl bootstrap system "$plist_path"
  launchctl enable "system/$label"
  launchctl kickstart -k "system/$label" 2>/dev/null || true
}

require_root() { [ "$(id -u)" -eq 0 ] || die "must run as root: sudo $0 ${1:-install}"; }

cmd_install() {
  require_root install
  prepare_paths
  resolve_darkhttpd

  [ -f "$serve_script" ] || die "serve-cache.sh not found next to this script ($serve_script)."
  [ -d "$cache_dir" ] && [ ! -L "$cache_dir" ] || die "docroot $cache_dir missing or a symlink; run init-cache.sh as the signing user first."
  [ -f "$cache_info" ] || die "$cache_info missing; run init-cache.sh first."
  [ -f "$secret_key" ] && [ ! -L "$secret_key" ] || die "signing key $secret_key missing or a symlink; run init-cache.sh first."
  case "$(stat -f '%Lp' "$secret_key")" in
    *00) : ;;
    *) die "signing key $secret_key is not owner-only (0600); re-run init-cache.sh." ;;
  esac

  ensure_group
  ensure_user
  assert_cannot_read_key

  install_scripts

  echo "creating log dir $log_dir (root:wheel 0755)..."
  mkdir -p "$log_dir"
  chown root:wheel "$log_dir"
  chmod 755 "$log_dir"

  echo "installing $plist_path..."
  local tmp
  tmp="$(mktemp "/Library/LaunchDaemons/.$label.XXXXXX")"
  emit_plist >"$tmp"
  plutil -lint "$tmp" >/dev/null || { rm -f "$tmp"; die "generated plist failed plutil -lint."; }
  chown root:wheel "$tmp"
  chmod 644 "$tmp"
  mv -f "$tmp" "$plist_path"

  echo "loading daemon $label..."
  load_daemon

  echo
  echo "Done. Cache server deployed:"
  echo "  docroot:   $cache_dir  (served read-only)"
  echo "  bind:      $bind_addr:$port   (loopback; guests reach it as host.lima.internal:$port)"
  echo "  as user:   $serve_user (uid $uid), chrooted into the docroot"
  echo "  scripts:   $install_dir  (root-owned copy the daemon runs)"
  echo "  plist:     $plist_path"
  echo "  logs:      $log_dir/serve.{out,err}.log"
  echo
  echo "Check it:  curl -sS http://$bind_addr:$port/nix-cache-info"
  echo "Status:    sudo launchctl print system/$label | grep -E 'state|pid'"
  echo "Tests:     ./test-cache.sh            # host-side (+)/(-) checks"
  echo "           ./test-cache.sh --vm NAME  # guest-side (+)/(-) (use a throwaway VM)"
}

cmd_uninstall() {
  require_root uninstall
  echo "booting out $label..."
  launchctl bootout "system/$label" 2>/dev/null || true
  if [ -f "$plist_path" ]; then
    rm -f "$plist_path"
    echo "removed $plist_path."
  fi
  # Remove only the files we installed, never `rm -rf` the dir: a custom
  # GHA_CACHE_LIBEXEC could point at a shared dir (e.g. /usr/local/libexec) whose
  # other contents must survive. rmdir (not rm -r) prunes the dir only if our
  # removals left it empty.
  rm -f "$installed_serve" "$install_dir/common.sh" "$installed_darkhttpd"
  echo "removed installed scripts + darkhttpd from $install_dir."
  rmdir "$install_dir" 2>/dev/null && echo "removed now-empty $install_dir." || true
  if [ "${1:-}" = "--purge-user" ]; then
    echo "deleting user/group $serve_user..."
    dscl . -delete "/Users/$serve_user" 2>/dev/null || true
    dscl . -delete "/Groups/$serve_group" 2>/dev/null || true
  else
    echo "left user $serve_user in place (pass --purge-user to delete it)."
  fi
  echo "logs left under $log_dir."
}

cmd_print_plist() {
  # No root needed — for review / plutil -lint. Resolve inputs so the emitted
  # plist matches a real install.
  prepare_paths
  resolve_darkhttpd
  emit_plist
}

case "${1:-install}" in
  install) cmd_install ;;
  uninstall) shift || true; cmd_uninstall "${1:-}" ;;
  print-plist) cmd_print_plist ;;
  *) die "unknown command '${1:-}'; use: install | uninstall [--purge-user] | print-plist" ;;
esac
