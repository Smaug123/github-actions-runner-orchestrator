#!/usr/bin/env bash
# Install the host-side wiring that lets the local Nix daemon offload
# aarch64-linux builds to the nixpkgs darwin.linux-builder VM.
#
# The guest image is aarch64-linux but the host is aarch64-darwin, so Nix
# cannot build it natively; it must offload to a Linux builder.
#
# Prerequisite: start the builder VM once so its SSH key is installed at
# /etc/nix/builder_ed25519 (first run prompts for sudo, then runs in the
# foreground — leave it running):
#
#     nix run nixpkgs#darwin.linux-builder
#
# Then run this script (idempotent; safe to re-run). It needs sudo for the
# /etc/nix and /etc/ssh writes and the daemon restart.
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f /etc/nix/builder_ed25519 ]; then
  echo "error: /etc/nix/builder_ed25519 not found." >&2
  echo "Run 'nix run nixpkgs#darwin.linux-builder' first (it installs the key" >&2
  echo "and boots the VM), then re-run this script." >&2
  exit 1
fi

# Validate sudo up front (prompts once). With set -e this aborts if sudo isn't
# usable, so a later `sudo test`/`sudo grep` failure in merge_into means the
# file is genuinely absent — not an auth/policy failure we could misread as
# "no existing config" and clobber.
sudo -v

echo "Installing builder wiring (sudo required)..."

# Merge our entry without clobbering other builders the host may already have:
# drop any prior linux-builder line, then append ours. Idempotent across re-runs.
merge_into() {
  # $1 = source (the line to ensure present), $2 = dest, $3 = -F match to drop.
  # Reads via sudo so a root-only dest still merges, and distinguishes grep's
  # "no match" (exit 1, fine) from a real read error (exit >1) so we abort
  # rather than silently clobbering existing builders/host keys.
  local src=$1 dest=$2 pat=$3 tmp rc
  tmp=$(mktemp)
  if sudo test -e "$dest"; then
    rc=0
    sudo grep -vF -- "$pat" "$dest" > "$tmp" || rc=$?
    if [ "$rc" -gt 1 ]; then
      echo "error: failed to read $dest; aborting to avoid clobbering it." >&2
      rm -f "$tmp"; exit 1
    fi
  fi
  cat "$src" >> "$tmp"
  sudo install -m 0644 "$tmp" "$dest"
  rm -f "$tmp"
}
merge_into "$dir/machines"    /etc/nix/machines    "builder@linux-builder"
merge_into "$dir/known_hosts" /etc/nix/known_hosts "linux-builder "

# This drop-in file is entirely ours, so replacing it wholesale is correct.
# Ensure the drop-in dir exists (BSD install has no -D); it's present by
# default on macOS but create it defensively for a clean host.
sudo mkdir -p /etc/ssh/ssh_config.d
sudo install -m 0644 "$dir/ssh_config" /etc/ssh/ssh_config.d/110-linux-builder.conf

echo "Restarting nix-daemon..."
sudo launchctl kickstart -k system/org.nixos.nix-daemon

echo "Verifying builder@linux-builder is reachable over the installed wiring..."
# Talk to the builder directly rather than via the daemon's scheduler, so this
# validates *this* builder's wiring (ssh_config alias, key, host key) with no
# false positives from the daemon routing to — or falling back from — some other
# aarch64-linux machine. Run as root: only root can read the 0600 SSH key, and
# root's ssh picks up the /etc/ssh/ssh_config.d drop-in we just installed.
sudo "$(command -v nix)" store info \
  --extra-experimental-features nix-command \
  --store ssh-ng://builder@linux-builder
echo "OK: builder@linux-builder reachable; offload wiring verified."
