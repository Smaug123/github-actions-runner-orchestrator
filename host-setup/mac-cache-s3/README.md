# Mac S3 store (self-hosted Actions cache + artifacts)

A single **MinIO** (S3-compatible) server on the Mac that replaces the *external*
GitHub Actions dependencies the consumer workflows still hit:

- the **build cache** (`actions/cache`) — for private repos this is GitHub's
  free-but-capped 10 GB/repo LRU pool; large outputs (the FCS build) evict fast
  and tank the hit rate; and
- the **artifact storage** (`actions/upload-artifact` / `download-artifact`) —
  which counts against billed private-repo storage.

Both now land in two buckets on the Mac, reached by the ephemeral guests over
the **same loopback/usernet path** the Nix substituter uses
(`host.lima.internal`). This is the *write* counterpart to the sibling
[`../mac-cache`](../mac-cache) (the read-only Nix substituter) and is
deliberately **separate from it**.

## Why a separate service and not the Nix store

The tempting "reuse what's there" move is to make the host→guest Nix channel
bidirectional — have jobs `nix copy --to` their outputs into the host store so
the next job substitutes them. **We do not**, because that requires a guest to
**write into the host `/nix/store`** (a writable binary cache / trusted-user /
upload-capable `nix-serve`), handing untrusted job code a write path into the
host store. The substituter in `../mac-cache` is safe precisely because it is
read-only-by-transport (darkhttpd has no upload verb) and read-only-by-trust
(integrity is the narinfo signature). We keep that property and add a **second,
unrelated service** whose storage is a plain directory.

A guest's only new capability is **S3 PUT/GET into two buckets**. MinIO writes
those into its own backend dir (`data/`), which is **never** `/nix/store`. There
is no code path from a guest to a host-store write.

## Trust model — a non-secret id + a real generated secret

The runner connects with an access-key id + secret key:

- **Access-key id** (default `gha-runner`) — **not secret**. It's a
  bucket-scoped identifier, committed in the consumer workflow as `S3_ACCESS_KEY`.
- **Secret key** — a **real random secret** that `setup-server.sh` generates
  (`openssl rand`) and stores host-side in `keys/runner.env` (`0600`, owned by
  you, not the daemon). You register it as the consumer repo's
  **`S3_CACHE_SECRET_KEY` GitHub Actions secret**; `setup-server.sh` prints the
  `gh secret set` command. It is never committed and never on the guest image.

Defence is layered: the secret is real *and* the account is fenced by an **IAM
policy** to object CRUD + listing on exactly the two buckets — **no admin API,
no bucket creation, no other buckets** — *and* the server binds **loopback
only**, so the sole reachability is host-local processes plus Lima guests via
the usernet `host.lima.internal:9000 → 127.0.0.1:9000` forward. `setup-server.sh`
*verifies* the scoping holds (it tries the admin API and a bucket create as the
runner account and aborts if either succeeds); `test-s3.sh` re-checks it.

The MinIO **root** password (`keys/root.env`) is the daemon's own superuser,
used to start the server and to provision via `mc admin`. It is **root-owned,
service-group-readable (`0640`)** — the daemon reads it but cannot modify it, so
a `setup-server.sh` rerun (which reads it as root) can't be fed daemon-injected
content.

**Shared trust domain.** As with the substituter, all allowed repos share these
buckets: any workflow in any allowed repo can read/write any cache or artifact
object. Same accepted decision as `../mac-cache` ("one shared cache = one trust
domain"); the VM remains the isolation boundary. Per-repo bucket prefixes are a
later refinement.

## Buckets

| bucket | backs | written by | expiry (ILM) |
| ------ | ----- | ---------- | ------------ |
| `gha-actions-cache` | cross-run build cache | `tespkg/actions-cache` | 14 days |
| `gha-actions-artifacts` | per-run job→job handoff | `mc` (run steps) | 1 day |

Two lifetimes on purpose: the build cache should persist across runs (the whole
point), while the artifact handoff only needs to outlive a single run — the 1-day
expiry mirrors the workflow's old `retention-days: 1`. MinIO enforces both via
object-lifecycle rules set at deploy time; nothing accumulates unbounded.

## Deploying

```
brew install minio/stable/minio minio/stable/mc        # server + client
sudo ./setup-server.sh                                  # user, store, secrets, daemon, buckets, account
# register the runner secret with the consumer repo (setup-server.sh prints this):
( . /usr/local/var/gha-mac-s3/keys/runner.env && printf %s "$RUNNER_SECRET_KEY" ) \
  | gh secret set S3_CACHE_SECRET_KEY -R <owner>/<repo>
./test-s3.sh                                            # host-side (+)/(-) checks
```

`setup-server.sh` is the one privileged, all-in-one step (there is no separate
`init-store.sh` — a dedicated unprivileged daemon must own its store
end-to-end, so the store lives in a **system path**, `/usr/local/var/gha-mac-s3`,
that root creates; it can't sit under your `0700` home like `../mac-cache`'s
chroot-served docroot can). It is idempotent: re-run it after editing any script
or bumping the `minio`/`mc` binaries (the daemon runs **root-owned snapshots**
under `/usr/local/libexec/gha-mac-s3/`, never the checkout or Homebrew copies).
It **never regenerates** existing credentials (rotating `root.env` would lock the
running `mc admin` out; rotating `runner.env` would desync the GitHub secret +
the MinIO account). `sudo ./setup-server.sh uninstall [--purge-user]` reverses it,
leaving the data + credentials unless you remove `$GHA_S3_DIR` yourself.

**Bind model — loopback, no `pf` rule.** Identical to `../mac-cache`:
`host.lima.internal` (`192.168.5.2`) is virtual, inside Lima's in-process usernet
gateway, which forwards `host.lima.internal:PORT → 127.0.0.1:PORT`. Binding
`127.0.0.1` is exactly what guests reach (as `host.lima.internal:9000`) and is
not LAN-routable. `serve-s3.sh` **rejects any non-loopback `GHA_S3_BIND_ADDR`**
(`127.0.0.0/8` only), so the loopback boundary can't be misconfigured into
exposing the write-capable S3 + admin API on the LAN. The embedded web console is disabled (`MINIO_BROWSER=off`), so
no second port is exposed; `mc admin` still works over the API port.

### Testing

    ./test-s3.sh                 # host-side: runner round-trips both buckets; admin/mb DENIED
    ./test-s3.sh --vm NAME       # also: guest round-trips via host.lima.internal (use a THROWAWAY VM)

Run the tests as the user who owns `runner.env` (the one who ran `sudo
./setup-server.sh`) — they read the runner secret from it.

## Wiring the guests and the workflow

**Guest** (`nix/guest.nix`): add `pkgs.minio-client` to `environment.systemPackages`
so the artifact `run:` steps have `mc` (`tar`/`gzip`/`curl` are already
guaranteed by NixOS's `requiredPackages`). The **cache** action needs no guest
change — `tespkg/actions-cache` is a `node24` JS action that bundles its own S3
client (and node24 is the only runtime the guest ships).

**Workflow** (`dumb-fsharp-lsp/.github/workflows/ci.yml`): the non-secret
connection params (`S3_ENDPOINT`, `S3_PORT`, `S3_REGION`, `S3_BUCKET_*`,
`S3_ACCESS_KEY`) sit in the workflow `env:`; the secret key comes from
`${{ secrets.S3_CACHE_SECRET_KEY }}`. Then:

- `actions/cache@v5` → `tespkg/actions-cache@<sha>` (SHA-pinned) pointed at
  `endpoint: host.lima.internal`, `port: 9000`, `insecure: true`,
  `bucket: gha-actions-cache`, `secretKey: ${{ secrets.S3_CACHE_SECRET_KEY }}`,
  `use-fallback: false` (so a store outage fails the step loudly instead of
  silently falling back to GitHub and re-incurring the budget); and
- the `upload-artifact` / `download-artifact` pair → `mc cp` to/from
  `gha-actions-artifacts`, keyed by `${{ github.run_id }}/${{ github.run_attempt }}`.
  Each `mc` step takes the secret via step `env:` and builds the `MC_HOST_s3`
  connection string at runtime. The bundle is `tar`'d, which preserves the
  executable bit — so the post-download `chmod +x` workaround goes away.

### Alternative: one mechanism for both

You can also use `tespkg/actions-cache` for the artifact handoff (exact per-run
key, then gate the next step on its `cache-hit` output), which needs **zero guest
change** since it avoids `mc`. We chose explicit `mc` for artifacts instead: it's
fail-loud by default, makes "this is a per-run artifact, not a cross-run cache"
obvious, and gives the artifact bucket its own 1-day lifecycle cleanly.

## Layout

Host state under `$GHA_S3_DIR` (default `/usr/local/var/gha-mac-s3`), created by
`setup-server.sh`; only the scripts here are version-controlled:

    keys/                  # root-owned 0755, world-traversable (holds nothing world-readable)
      root.env             # MINIO_ROOT_USER / MINIO_ROOT_PASSWORD — root-owned, service-group-readable 0640 (daemon reads, can't modify)
      runner.env           # RUNNER_SECRET_KEY — owned by YOU, 0600 (register as the GitHub secret; daemon can't read)
    data/                  # MinIO backend — owned by the service user, 0700; NEVER /nix/store

**Why the split ownership.** The daemon (`_gha-s3`) needs `root.env` + `data/`
and must not read the runner secret; you need `runner.env` (to register it / run
tests) and not the daemon's superuser. `keys/` is root-owned and traversable so
each principal reaches its own `0600` file, and `data/` is `0700` so only the
daemon enters it.

**Invariant — the data dir is not the Nix store.** MinIO only ever writes under
`data/`. The guest has no mount of the host store (`mounts: []` in the Lima
template), so "write into the host `/nix/store`" is not expressible from a job —
the new capability is strictly S3 object writes into two buckets.
