# Local aarch64-linux builder

The guest VM image is built for `aarch64-linux`, but the host is
`aarch64-darwin` and Nix cannot build Linux derivations natively. This sets up
nixpkgs' `darwin.linux-builder` (a small NixOS QEMU VM) as a Nix *remote
builder* so the daemon offloads `aarch64-linux` builds to it. The same builder
is what populates the shared Nix store in a later phase.

This is plain upstream multi-user Nix on macOS (daemon `org.nixos.nix-daemon`),
not nix-darwin, so the wiring is installed by hand here rather than generated.

## One-time setup

1. Boot the builder VM **from a dedicated directory outside this repo** —
   `darwin.linux-builder` writes its SSH keypair (`keys/`, a private key) and
   VM disk (`nixos.qcow2`) into the current directory, and they must not land
   in the repo tree. On first run it also installs the key to
   `/etc/nix/builder_ed25519` (prompts for sudo). It then runs in the
   foreground — leave that terminal open:

       mkdir -p ~/.local/share/gha-linux-builder
       cd ~/.local/share/gha-linux-builder
       nix run nixpkgs#darwin.linux-builder

   (`.gitignore` also ignores `keys/`/`nixos.qcow2` as a safety net if you do
   run it inside the repo.)

2. In another terminal, from this directory, install the wiring and self-verify:

       ./install.sh

   It copies the files below into place, restarts the nix-daemon, and runs a
   trivial `aarch64-linux` build to confirm offload works.

## Files

- `machines` → `/etc/nix/machines`: registers `builder@linux-builder` as an
  `aarch64-linux` builder, keyed by `/etc/nix/builder_ed25519`, with the
  builder's public host key (base64) for verification. `max-jobs` is `1` to
  match the default single-vCPU `darwin.linux-builder` VM; if you size the VM
  up for concurrency, raise this field to match.
- `ssh_config` → `/etc/ssh/ssh_config.d/110-linux-builder.conf`: maps the
  `linux-builder` alias to `127.0.0.1:31022`, user `builder`.
- `known_hosts` → `/etc/nix/known_hosts`: the builder's host key under that
  alias, so SSH verifies without prompts.

The host key is the well-known public nix-darwin builder key — not a secret.

## Persistence

The builder VM only runs while the `nix run` terminal is open. A launchd plist
to keep it running across reboots is a planned follow-up.

## Troubleshooting

**Build fails citing a "valid but missing"/absent store path.** Occasionally a
guest-image build (`lima/build-nixos-image.sh`) fails referencing a store path
that is absent from the builder's store — a transient builder-store
inconsistency. One observed cause: the builder runs Nix **auto-GC mid-build**
and deletes a path the in-flight derivation depends on (e.g. the UKI input),
after which the build aborts. `nix/guest.nix` asserts its inputs so this fails
loudly instead of producing an unbootable image, and the build script retries
once — which recopies the inputs and usually clears it. If it persists, repair
the builder's store and re-run (the `linux-builder` alias comes from the
installed `ssh_config`; before `install.sh`, use
`-F host-setup/linux-builder/ssh_config`):

    ssh linux-builder 'nix-store --verify --check-contents --repair'

`--repair` re-fetches or rebuilds any path whose contents are missing or
corrupt; then re-run the build. If auto-GC races builds frequently, raise the
builder VM's `min-free`/`max-free` or its disk size so GC is not triggered
during a build.
