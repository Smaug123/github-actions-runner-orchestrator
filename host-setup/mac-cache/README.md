# Mac signing cache (Phase 3 / 3a)

The *read path* of the shared Nix store. A curated, signed `aarch64-linux`
binary cache served from the Mac that the ephemeral guests substitute from —
prepended ahead of `cache.nixos.org` — so a job that would otherwise rebuild
the expensive Rust crate closure (`cargoArtifacts`) from source instead pulls
warm, signed paths over HTTP.

**Why a curated cache and not the live `/nix/store`:** serving the whole store
would let any reachable guest fetch any private path on the Mac by hash (other
repos' source and outputs included). The cache is a *dedicated directory* that
only ever holds what we deliberately published into it, served read-only with a
server that physically cannot reach outside its docroot.

**Trust domain:** all allowed repos share this one cache. Anyone who can land a
workflow in any allowed repo can fetch any path warmed for any other. That is
an accepted decision (see `ROLLOUT_PLAN.md`, "One shared cache = one trust
domain"). Segmenting per-repo is deferred (`DEFERRED.md`).

## Status — built so far

- **slice 1 (this commit): signing keypair + curated cache docroot.**
  `init-cache.sh` generates the keypair and the served directory skeleton.

Still to come (separate slices):

- Static HTTP server over the docroot, under launchd, bound Lima-only — with a
  positive test (guest fetches a signed path) and a negative test (a live
  `/nix/store` path is **not** fetchable, and a non-Lima address cannot
  connect).
- `warm-cache.sh <flake-target>`: `nix copy` the full **build closure** (not
  just outputs — outputs-only misses `cargoArtifacts`) into the docroot, force
  `aarch64-linux`, record a manifest, prune behind a host-level lock.
- Guest substituter config (`nix/guest.nix`, 3b): add this cache + its public
  key while **keeping** `cache.nixos.org` and its default key.

The automatic host warmer (3c) is deferred — v1 is populated manually by your
own dev `nix copy`s, with `cache.nixos.org` as fallback.

## One-time setup

From this directory, as the `ci` user (no sudo needed — everything lands under
`$HOME`):

    ./init-cache.sh

This is idempotent. It:

1. Generates a binary-cache signing keypair (`gha-mac-cache-1`) if absent. An
   existing key is **never** regenerated (that would invalidate the public key
   already baked into guests). Every run re-applies the private key's `0600`
   mode and re-derives the public key from the secret, so the printed value
   always matches the signing key even after a partial setup or restore.
2. Creates the curated cache docroot with a `nix-cache-info` advertising
   `Priority: 10`.
3. Prints the **public key** — bake this into the guest's
   `trusted-public-keys` in the 3b slice.

## Layout

Out-of-tree (host state; only the scripts here are version-controlled), under
`$GHA_CACHE_DIR` (default `~/.local/share/gha-mac-cache/`):

    keys/                      # NOT served — sibling of, never under, cache/
      gha-mac-cache-1.secret   # 0600 signing private key
      gha-mac-cache-1.public   # the trusted-public-keys string for guests
    cache/                     # the docroot the server will expose, read-only
      nix-cache-info           # StoreDir / WantMassQuery / Priority: 10
      # nar/ and *.narinfo land here once warm-cache.sh runs

**Invariant — secrets live outside the docroot.** The signing private key
(plus, later, netrc / staging dirs / logs) must never sit under `cache/`. The
server runs as `ci` and can read its own `0600` files, so anything inside the
docroot is serveable regardless of file mode. The docroot holds only `nar/`,
`*.narinfo`, and `nix-cache-info`.

**Invariant — Priority beats list order.** Nix prefers a substituter by the
`Priority:` in its `nix-cache-info` (lower = preferred), *not* by the order it
appears in `substituters`. `cache.nixos.org` advertises `40`; the `10` here
makes the Mac win for any path present in both. The 3b slice verifies this from
a guest.
