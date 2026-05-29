#!/usr/bin/env bash
# Serve the curated Mac signing cache over HTTP (Phase 3 / 3a, slice 2a).
#
# The READ side of the shared store: a dumb static file server (darkhttpd) over
# the curated docroot (cache/), so the ephemeral guests substitute signed
# aarch64-linux paths from the Mac ahead of cache.nixos.org.
#
# This script is the single ExecStart for the launchd daemon that slice 2b wires
# up. It (1) runs a serve-start INODE GATE that refuses to start unless the
# docroot is clean, then (2) execs darkhttpd confined to the docroot.
#
# The "signing key is never reachable from the served docroot" invariant is
# enforced in layers, strongest first:
#   - PRIMARY: served by a dedicated user (GHA_CACHE_USER, default `_gha-cache`)
#     that cannot read the 0600-`ci` signing key. Kernel-enforced per inode, so
#     a symlink OR hardlink to the key under the docroot still EACCESes. (Needs
#     root to drop into; established by slice 2b's setup-server.sh.)
#   - chroot: darkhttpd chroots into the docroot, so no path (symlink, `..`) can
#     name a file outside the served tree.
#   - this inode gate: refuses to start if any docroot entry is a symlink or
#     shares the key's (dev,ino). One ground-truth check covering every writer
#     (init-cache.sh, warm-cache.sh, manual edits, restores).
#   - darkhttpd --no-listing: no directory autoindex.
#   - bind to a specific address only (never 0.0.0.0); slice 2b sets it to the
#     guest-reachable host.lima.internal address + adds a pf rule.
#
# Run modes:
#   - as root (the launchd/production path): chroot + drop to GHA_CACHE_USER.
#   - as non-root (local dev/test): NO chroot, NO privilege drop — serves as the
#     invoking user. Prints a loud warning; NOT the hardened deployment.
set -euo pipefail

# Shared layout (base, key_name + validation, cache_dir, secret_key, ...).
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "$dir/common.sh"

# Root (the launchd/production path) has no sensible HOME-based default for the
# cache location: init-cache.sh runs as `ci` and writes under ci's $HOME, so a
# root start that fell back to common.sh's $HOME default (root's home) would
# miss the initialised cache or serve a different tree. Require it explicitly.
if [ "$(id -u)" -eq 0 ] && [ -z "${GHA_CACHE_DIR:-}" ]; then
  echo "error: running as root: set GHA_CACHE_DIR to the absolute cache dir (the launchd plist must pass it); root's \$HOME is not where init-cache.sh wrote." >&2
  exit 1
fi

bind_addr="${GHA_CACHE_BIND_ADDR:-}"
port="${GHA_CACHE_PORT:-8080}"
serve_user="${GHA_CACHE_USER:-_gha-cache}"
serve_group="${GHA_CACHE_GROUP:-$serve_user}"

darkhttpd_bin="${GHA_DARKHTTPD:-$(command -v darkhttpd || true)}"
if [ -z "$darkhttpd_bin" ]; then
  echo "error: darkhttpd not found; put it on PATH or set GHA_DARKHTTPD." >&2
  exit 1
fi

# Bind address: required, and a CANONICAL specific IPv4 — never an any-address.
# darkhttpd parses --addr with inet_aton, which ALSO accepts abbreviated forms
# (`0`, `0.0`, `000.000.000.000`, hex/octal) that all mean INADDR_ANY and would
# expose the cache on every interface. So don't blocklist `0.0.0.0`; instead
# require a canonical dotted-quad (four 0-255 octets, no leading zeros, no
# IPv6) and reject 0.0.0.0. The bind target is the vz host.lima.internal
# address (IPv4), determined in slice 2b.
require_specific_ipv4() {
  local addr=$1 oct allzero=1
  case "$addr" in
    # digits/dots only (rejects IPv6, hex, spaces); no leading/trailing dot or
    # empty octet — a trailing dot survives word-splitting as a dropped field
    # and would otherwise pass as a bogus "quad".
    "" | *[!0-9.]* | .* | *. | *..*) return 1 ;;
  esac
  local IFS=.
  # shellcheck disable=SC2206  # deliberate split on '.' into octets
  local parts=( $addr )
  [ "${#parts[@]}" -eq 4 ] || return 1
  for oct in "${parts[@]}"; do
    [ -n "$oct" ] || return 1             # no empty octet (1..2, leading/trailing dot)
    [ "${#oct}" -le 3 ] || return 1
    case "$oct" in 0?*) return 1 ;; esac  # no leading zero (00, 01, 000)
    [ "$oct" -le 255 ] || return 1
    [ "$oct" -eq 0 ] || allzero=0
  done
  [ "$allzero" -eq 0 ]                     # reject 0.0.0.0
}

if [ -z "$bind_addr" ]; then
  echo "error: GHA_CACHE_BIND_ADDR is required (the specific host.lima.internal IPv4 address)." >&2
  exit 1
fi
if ! require_specific_ipv4 "$bind_addr"; then
  echo "error: GHA_CACHE_BIND_ADDR='$bind_addr' is not a canonical specific IPv4 (no any-address / leading zeros / IPv6); set the host.lima.internal address." >&2
  exit 1
fi

# Docroot must be a real directory (not a symlink) holding an initialised cache.
if [ -L "$cache_dir" ]; then
  echo "error: docroot $cache_dir is a symlink." >&2
  exit 1
fi
if [ ! -d "$cache_dir" ]; then
  echo "error: docroot $cache_dir not found; run init-cache.sh first." >&2
  exit 1
fi
if [ ! -f "$cache_dir/nix-cache-info" ]; then
  echo "error: $cache_dir/nix-cache-info missing; run init-cache.sh first." >&2
  exit 1
fi

# In the production (root) path darkhttpd drops to $serve_user after chroot, so
# that user must traverse the docroot and read its files. The docroot is PUBLIC
# (no secret lives in it), so the gate below additionally asserts world rx/r in
# root mode and fails loud — rather than start a server that 403s every fetch
# (e.g. if init or the warmer ran under a restrictive umask). Dev mode serves as
# the owner, so the readability check is skipped.
am_root=0
[ "$(id -u)" -eq 0 ] && am_root=1

# --- serve-start inode gate ---
# Require the signing key to exist (proof the cache was initialised, and the
# concrete inode to exclude). It must not be a symlink.
if [ ! -e "$secret_key" ]; then
  echo "error: signing key $secret_key not found; run init-cache.sh first." >&2
  exit 1
fi
if [ -L "$secret_key" ]; then
  echo "error: signing key $secret_key is a symlink." >&2
  exit 1
fi
key_devino="$(stat -f '%d:%i' "$secret_key")"

# Walk the docroot physically (find -P, the default: it does NOT follow
# symlinks, so a symlinked entry is listed as the link itself). Reject any
# symlink at any depth, reject anything that is neither a regular file nor a
# directory, and abort if any file shares the key's (dev,ino) — i.e. is a hard
# link to the key. In root mode also assert world rx (dirs) / r (files) so the
# dropped user can serve the whole tree. -print0/read -d '' tolerates odd names.
while IFS= read -r -d '' entry; do
  if [ -L "$entry" ]; then
    echo "error: serve-start gate: docroot entry is a symlink: $entry" >&2
    exit 1
  fi
  if [ -d "$entry" ]; then
    if [ "$am_root" -eq 1 ]; then
      case "$(stat -f '%Lp' "$entry")" in
        *[1357]) : ;;  # 'other' octal digit is odd → +x → traversable
        *)
          echo "error: serve-start gate: docroot dir not world-traversable (o+x) for $serve_user: $entry" >&2
          exit 1 ;;
      esac
    fi
    continue
  fi
  if [ ! -f "$entry" ]; then
    echo "error: serve-start gate: docroot entry is not a regular file: $entry" >&2
    exit 1
  fi
  if [ "$(stat -f '%d:%i' "$entry")" = "$key_devino" ]; then
    echo "error: serve-start gate: docroot entry shares the signing key's inode: $entry" >&2
    exit 1
  fi
  if [ "$am_root" -eq 1 ]; then
    case "$(stat -f '%Lp' "$entry")" in
      *[4567]) : ;;  # 'other' octal digit has the +r bit (4)
      *)
        echo "error: serve-start gate: docroot file not world-readable (o+r) for $serve_user: $entry" >&2
        exit 1 ;;
    esac
  fi
done < <(find "$cache_dir" -print0)

darkhttpd_args=(
  "$cache_dir"
  --addr "$bind_addr"
  --port "$port"
  --no-listing
)

if [ "$am_root" -eq 1 ]; then
  # Production path (launchd): chroot into the docroot + drop privileges to the
  # dedicated user that cannot read the signing key.
  if ! id "$serve_user" >/dev/null 2>&1; then
    echo "error: user '$serve_user' does not exist; run setup-server.sh (slice 2b) first." >&2
    exit 1
  fi
  # Fail closed: the symlink/hardlink defense rests on $serve_user being UNABLE
  # to read the 0600-`ci` signing key. A misconfigured GHA_CACHE_USER (ci/root)
  # or a key whose mode drifted would silently defeat it — so verify before
  # exec, not just that the user exists. The drop user must not be uid 0, must
  # not own the key, and the key must carry no group/other permission bits.
  serve_uid="$(id -u "$serve_user")"
  if [ "$serve_uid" -eq 0 ]; then
    echo "error: '$serve_user' is uid 0; serve as an unprivileged user that cannot read the signing key." >&2
    exit 1
  fi
  if [ "$serve_uid" -eq "$(stat -f '%u' "$secret_key")" ]; then
    echo "error: '$serve_user' owns the signing key and could read it; serve as a different unprivileged user." >&2
    exit 1
  fi
  case "$(stat -f '%Lp' "$secret_key")" in
    *00) : ;;  # group+other octal digits are 0 → owner-only → non-owner EACCESes
    *)
      echo "error: signing key $secret_key is not owner-only (has group/other bits); re-run init-cache.sh or chmod 600." >&2
      exit 1 ;;
  esac
  echo "Serving $cache_dir on $bind_addr:$port as $serve_user (chroot, no-listing)."
  exec "$darkhttpd_bin" "${darkhttpd_args[@]}" \
    --chroot --uid "$serve_user" --gid "$serve_group"
else
  echo "WARNING: not running as root — DEV MODE: no chroot, no privilege drop." >&2
  echo "         Serves as $(id -un); this is for local testing, NOT deployment." >&2
  exec "$darkhttpd_bin" "${darkhttpd_args[@]}"
fi
