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
