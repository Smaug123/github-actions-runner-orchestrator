# Handoff — self-hosted S3 cache + artifact store (`mac-cache-s3`)

Landed on `main` in one squashed commit. This note records what is **verified**,
what is **still outstanding to do/verify**, and the **known fragilities** — so the
next person (or session) can pick it up cold.

## What it is (one paragraph)

A dedicated MinIO (S3) server on the Mac, run by launchd as the unprivileged
`_gha-s3` user, bound to `127.0.0.1:9000` and reached by the ephemeral Lima
guests as `host.lima.internal:9000` (the same usernet path as the Nix
substituter). It backs the GitHub Actions **build cache** (`tespkg/actions-cache`
→ bucket `gha-actions-cache`) and the per-run **artifact handoff** (`mc cp` →
bucket `gha-actions-artifacts`), replacing GitHub's capped private-repo cache and
billed artifact storage. Its data lives in `/usr/local/var/gha-mac-s3`, never
`/nix/store`, so a guest gains only S3 PUT/GET into two buckets — no host-store
write path. See `README.md` for the full design and trust model.

## Verified in this session

- The host scripts pass `shellcheck -x`; the loopback validator and probe-bucket
  names were unit-checked under bash.
- The MinIO daemon **starts and serves** under launchd (after the log-dir fix —
  see history). 
- The guest image **builds** (`lima/build-nixos-image.sh`) — a transient builder
  miss self-cleared on rerun (see fragility #1).

## NOT yet verified / exercised — do these

These are the gaps between "code merged" and "actually working in CI". Roughly in
order:

1. **Confirm the store deploy end-to-end.** A clean `sudo ./setup-server.sh`
   run-through (buckets created + ILM rules set + the scoped-account `(-)` asserts
   all passing) was not observed start-to-finish here. Run:
   - `./test-s3.sh` (host-side; run as the user who ran setup) — must be all green.
   - `./test-s3.sh --vm <throwaway-vm>` (guest-side via `host.lima.internal`).
2. **Register the GitHub secret** (if not already): the
   `gh secret set S3_CACHE_SECRET_KEY -R <owner>/dumb-fsharp-lsp …` line that
   `setup-server.sh` prints (reads it from `keys/runner.env`).
3. **Redeploy the guest image**: point the consumer's `LIMA_TEMPLATE` at the
   freshly built `~/.local/share/gha-images/gha-guest-nixos-*.yaml` and restart
   the consumer when idle (pause → wait `in_flight=0` → restart, per the
   top-level `README.md` "Pausing").
4. **Land the consumer workflow.** The `dumb-fsharp-lsp/.github/workflows/ci.yml`
   changes (swap to `tespkg/actions-cache`, `mc`-based artifacts, secret wiring)
   are **uncommitted in that repo** — they are NOT part of this commit. Commit +
   push them there. The secret (step 2) MUST exist first: `use-fallback: false`
   means a missing secret or an unreachable store fails the step **loudly** rather
   than silently falling back to GitHub.
5. **Watch the first CI run** — this is the real end-to-end test, never yet done:
   - `tespkg/actions-cache` actually connecting to MinIO and round-tripping the
     `fcs-dump/{bin,obj}` cache. The `endpoint`/`port`/`insecure` triple is
     unverified against a live run (see fragility #4).
   - the `mc cp` artifact steps in the guest: `mc` on PATH, `MC_HOST_s3` built
     from the step `env:` secret, and `tar -xp` preserving the `+x` bit (so the
     old `chmod +x` is gone).

## Known fragilities / things worth fixing

1. **The UKI-copy `postBuild` in `nix/guest.nix` is hand-rolled and brittle.**
   This is the most likely thing to bite again. It `mcopy`s the UKI into the ESP
   manually (commit `dad7082` "Copy image manually") because repart's vfat
   `CopyFiles` "silently dropped it". The build failure seen during rollout was a
   **builder-store inconsistency** (the UKI's store path was valid-but-absent on
   the `linux-builder`), which a rerun cleared — the `postBuild` logic itself is
   correct (verified by reproducing the exact `mcopy` locally). But: it had never
   been successfully built before this rollout, it assumes the UKI input is
   realized on the builder, and it would break again on any builder-store hiccup
   or a future nixpkgs change to `system.build.uki`'s layout (currently a dir
   containing `nixos.efi`). **Recommended:** revisit placing the UKI via
   `systemd-repart`'s ESP partition `CopyFiles` (repart-native) instead of the
   manual `mcopy`, and re-test why CopyFiles dropped it. Predates this work but
   it's the shakiest part of the guest image.

2. **Deploy paths are only validated by running them once.** `setup-server.sh`'s
   `dscl` user creation, launchd wiring, and `mc` provisioning can only be tested
   as root on the real Mac — they were not runnable in the dev environment. The
   log-dir-ownership bug (launchd opens `StandardOut/ErrorPath` as the daemon
   user, so the dir must be owned by `_gha-s3`) was one such untested path that
   bit on first deploy and is now fixed. Re-running `setup-server.sh` is
   idempotent; `test-s3.sh` + the in-script scoped-account asserts are the
   guardrails for anything else lurking.

3. **ILM idempotency is best-effort.** `ensure_expiry` adds an expiry rule only
   if `mc ilm rule ls` shows none. After deploy, eyeball `mc ilm rule ls` on both
   buckets: exactly one expiry rule each (`gha-actions-cache` 14d,
   `gha-actions-artifacts` 1d), no duplicates from re-runs.

4. **`tespkg/actions-cache` endpoint form is unverified.** Set as
   `endpoint: host.lima.internal`, `port: "9000"`, `insecure: true`. If the first
   CI cache step errors on connection, confirm the action's expected endpoint
   format (with/without scheme/port) against its README and adjust `ci.yml`.

5. **Capacity / disk.** Growth is bounded only by ILM expiry; there is no
   disk-usage monitoring on `/usr/local/var/gha-mac-s3`. Watch the Mac's free
   space; tune `GHA_S3_CACHE_EXPIRE_DAYS` / `GHA_S3_ARTIFACTS_EXPIRE_DAYS` if it
   grows.

## Deferred / nice-to-have

- **Per-repo bucket segmentation.** All allowed repos currently share the two
  buckets (one trust domain — same accepted decision as the substituter). Per-repo
  prefixes/policies would confine cache-poisoning blast radius.
- **Harmonize the sibling substituter's bind check.** This store enforces
  loopback (`require_loopback_ipv4`, `127.0.0.0/8`). `../mac-cache` still uses the
  looser `require_specific_ipv4` (any IPv4) — lower risk there (read-only public
  docroot) but inconsistent.
- **Ubuntu interim guest has no `mc`.** Only the NixOS guest got `minio-client`.
  If CI ever runs on `lima/runner-aarch64.yaml`, the `mc` artifact steps fail; add
  `mc` there or retire the interim path.
- **Artifact transport alternative.** Artifacts use explicit `mc` (fail-loud, own
  lifecycle). The zero-guest-change alternative is `tespkg/actions-cache` for the
  handoff too (exact per-run key + `cache-hit` gate) — documented in `README.md`;
  switch if shipping `mc` in the guest becomes a burden.
- **One more Codex pass.** Review went 3 → 3 → 1 findings (all fixed); a 4th pass
  was offered but the branch was squashed as-is. Worth a final pass at leisure.
- **No graceful-shutdown story for the MinIO daemon.** Stopping it mid-CI fails
  in-flight cache/artifact ops loudly (acceptable, but note it for migrations).
