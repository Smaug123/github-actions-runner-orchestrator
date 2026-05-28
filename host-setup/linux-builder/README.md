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
