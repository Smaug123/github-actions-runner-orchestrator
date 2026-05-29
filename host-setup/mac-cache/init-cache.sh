#!/usr/bin/env bash
# Initialise the Mac-side signing binary cache (Phase 3 / 3a, slice 1).
#
# This is the *read path* of the shared Nix store: a curated, signed
# aarch64-linux binary cache that the ephemeral guests substitute from (ahead
# of cache.nixos.org). This slice only lays the foundation — a signing keypair
# and the curated cache directory. The static HTTP server (launchd), the
# warm-cache.sh populator, and the guest substituter config (3b) are separate
# follow-up slices that build on what this produces.
#
# Two invariants are established here and relied on by every later slice:
#   1. The signing PRIVATE key lives OUTSIDE the served docroot. The HTTP server
#      is additionally locked down (slice 2: a dedicated user that can't read
#      the key, chrooted into the docroot) — but keeping the key out of the
#      served tree is the first layer, established here.
#   2. The cache advertises `Priority: 10` in nix-cache-info. Nix prefers a
#      substituter by this number (lower = preferred), NOT by substituter-list
#      order; cache.nixos.org advertises 40, so without an explicit lower
#      number a path present in both could be fetched from upstream instead.
#
# Idempotent: re-running never regenerates an existing keypair (that would
# invalidate the public key already baked into guests) and never clobbers the
# cache contents. Runs entirely as the invoking user (`ci`) under $HOME — no
# sudo, nothing under /etc.
set -euo pipefail

# Shared layout (base, key_name + validation, keys_dir, cache_dir, secret_key,
# public_key, cache_info). One definition, shared with serve-cache.sh.
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
. "$dir/common.sh"

if ! command -v nix-store >/dev/null 2>&1; then
  echo "error: nix-store not found on PATH." >&2
  exit 1
fi

# Refuse a symlinked cache/ or keys/ leaf BEFORE creating or writing anything.
# A `keys -> cache` symlink (or vice versa) would make the mkdir/chmod and the
# later key write follow into the served docroot, landing the 0600 secret where
# the server (running as ci) can read it — breaking invariant 1.
for d in "$cache_dir" "$keys_dir"; do
  if [ -L "$d" ]; then
    echo "error: $d is a symlink; GHA_CACHE_DIR must hold real, distinct cache/ and keys/ directories." >&2
    exit 1
  fi
done

# 0700 keys dir: defence in depth around the 0600 secret key.
mkdir -p "$cache_dir"
mkdir -p "$keys_dir"
chmod 700 "$keys_dir"
# The docroot is PUBLIC (served to guests; no secret lives in it — those stay in
# keys/). Force it world-traversable regardless of umask: the server drops to a
# dedicated user (_gha-cache) that must reach it, and under a restrictive umask
# mkdir would leave 0700, making every guest fetch 403.
chmod 755 "$cache_dir"

# Belt-and-braces over the leaf check: now both exist as real dirs, assert the
# keys dir does not RESOLVE to or inside the served cache dir (catches deeper
# aliasing a leaf-symlink check can't see, e.g. a symlinked ancestor). pwd -P
# canonicalises away every symlink in the path.
cache_real="$(cd "$cache_dir" && pwd -P)"
keys_real="$(cd "$keys_dir" && pwd -P)"
case "$keys_real/" in
  "$cache_real"/)
    echo "error: keys dir and cache dir resolve to the same path ($keys_real)." >&2
    exit 1
    ;;
  "$cache_real"/*)
    echo "error: keys dir ($keys_real) resolves inside the served cache dir ($cache_real); the signing key would be serveable." >&2
    exit 1
    ;;
esac

# The keys dir is real (checked above), but a key FILE could still be a
# pre-created symlink pointing into the docroot (a restore, a manual slip). The
# generate/chmod/convert steps below would follow it and write or expose the
# secret under cache/. Require the key paths to be regular files or absent —
# never symlinks (incl. dangling) or other special types.
for f in "$secret_key" "$public_key"; do
  if [ -L "$f" ] || { [ -e "$f" ] && [ ! -f "$f" ]; }; then
    echo "error: $f is a symlink or non-regular file; refusing to write the key through it." >&2
    exit 1
  fi
done

# Generate the keypair only on first run — never regenerate an existing one
# (that would invalidate the public key already baked into guests).
if [ -e "$secret_key" ]; then
  echo "Signing key already present at $secret_key — verifying."
else
  echo "Generating binary-cache signing keypair '$key_name'..."
  # nix-store --generate-binary-cache-key <name> <secret-file> <public-file>
  nix-store --generate-binary-cache-key "$key_name" "$secret_key" "$public_key"
fi

# Re-apply the secret mode on every run (invariant 1): a partial previous run,
# a restore, or a manual edit could have left it lax. Cheap and idempotent.
chmod 600 "$secret_key"

# A hard link from the docroot to the secret's inode would let the server serve
# the key under a second name even though the secret "lives" in keys/ — same
# inode, two paths, modes are per-inode so 0600 doesn't help. A freshly
# generated key has exactly one link; more than one means something else (maybe
# a docroot entry) references this inode. Fail closed and let the operator
# investigate rather than risk serving the key. (BSD stat: %l = link count.)
links="$(stat -f '%l' "$secret_key")"
if [ "$links" -ne 1 ]; then
  echo "error: $secret_key has $links hard links; an extra link (e.g. into the served docroot) could expose the key. Remove stray links and re-run." >&2
  exit 1
fi

# Derive the public key FROM the secret on every run, written atomically, so
# the value we print (and bake into guests at 3b) always matches the secret
# actually used to sign — even if .public was lost, never written, or went
# stale. A corrupt secret makes convert fail here (set -e), surfacing it rather
# than emitting a bogus key. The temp file is born 0700-dir-private; published
# 0644 only at the rename.
tmp_pub="$(mktemp "$keys_dir/.public.XXXXXX")"
nix key convert-secret-to-public \
  --extra-experimental-features nix-command \
  < "$secret_key" > "$tmp_pub"
chmod 644 "$tmp_pub"
mv -f "$tmp_pub" "$public_key"

# nix-cache-info describes the cache to substituters. It IS served (it lives in
# the docroot) and holds no secret. StoreDir must match the guests' /nix/store;
# WantMassQuery lets `nix path-info`/substitution probe efficiently; Priority
# wins over cache.nixos.org (see invariant 2). Rewritten each run so a changed
# priority takes effect; the cache payload (nar/, *.narinfo) is left alone.
#
# Written via temp+rename, not `>`: a pre-existing symlink here (e.g. a restore
# pointing at the secret key) would otherwise redirect the write and clobber
# its target. rename replaces the link itself rather than following it. The
# temp lives in the docroot, but holds only this non-secret content.
tmp_info="$(mktemp "$cache_dir/.nix-cache-info.XXXXXX")"
cat > "$tmp_info" <<'EOF'
StoreDir: /nix/store
WantMassQuery: 1
Priority: 10
EOF
chmod 644 "$tmp_info"
mv -f "$tmp_info" "$cache_info"

echo
echo "Mac signing cache initialised."
echo "  docroot (serve this, read-only):  $cache_dir"
echo "  signing private key (0600, NEVER serve/commit): $secret_key"
echo
echo "Public key — bake this into the guest's trusted-public-keys (3b):"
echo
cat "$public_key"
echo
echo "Next slices: static HTTP server over the docroot (launchd, Lima-only"
echo "bind), then warm-cache.sh to populate it. See README.md."
