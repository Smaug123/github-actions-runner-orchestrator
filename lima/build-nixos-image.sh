#!/usr/bin/env bash
# Build the NixOS runner guest image from the flake and emit a Lima template.
#
# Builds .#gha-guest-image (an aarch64-linux raw UEFI image; Nix offloads the
# build to the host-setup/linux-builder), copies the image out of the read-only
# Nix store to a versioned, GC-safe location, and writes a Lima template that
# boots it with NO per-job provisioning. Point the consumer's LIMA_TEMPLATE at
# the emitted template and restart the consumer when it is idle.
#
# Unlike the interim build-prebuilt-image.sh (which boots an Ubuntu template
# once and snapshots it), the whole guest here is declared in nix/guest.nix, so
# this is a pure `nix build` (systemd-repart; no VM boot, no cleanup pass).
#
# Re-run whenever nix/guest.nix or its inputs change. Output defaults outside
# the repo (override with OUTDIR); the image is multi-GB. Old
# gha-guest-nixos-*.{raw,yaml} can be deleted once no consumer references them.
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$dir/.." && pwd)"
outdir="${OUTDIR:-$HOME/.local/share/gha-images}"

command -v nix >/dev/null || { echo "error: nix not found on PATH" >&2; exit 1; }
mkdir -p "$outdir"
# Resolve to an absolute path so the emitted file:// URL works regardless of cwd.
outdir="$(cd "$outdir" && pwd)"

echo ">> Building .#gha-guest-image (offloads aarch64-linux to the linux-builder)..."
# --no-link: we copy the artifact out ourselves below, so we don't want a
# result symlink rooting the (large) store path in the repo.
#
# Retry once: the aarch64 build offloads to host-setup/linux-builder, which has
# intermittently presented a just-built store path as valid-but-absent (a
# transient builder-store inconsistency that self-clears on a rerun). Bounded to
# 2 attempts so a genuine build failure still surfaces quickly.
attempts=2
attempt=1
store_out=""
while :; do
  if store_out="$(nix build "$repo#gha-guest-image" --no-link --print-out-paths --print-build-logs)"; then
    break
  fi
  if [ "$attempt" -ge "$attempts" ]; then
    echo "error: nix build failed after $attempts attempts." >&2
    echo "  If it cites a store path the builder reports valid-but-absent, repair" >&2
    echo "  the builder store and re-run:" >&2
    echo "    ssh -F host-setup/linux-builder/ssh_config linux-builder \\" >&2
    echo "        'nix-store --verify --check-contents --repair'" >&2
    exit 1
  fi
  echo ">> nix build failed (attempt $attempt/$attempts); retrying..." >&2
  attempt=$((attempt + 1))
done

# systemd-repart's output is a directory holding gha-guest.raw; be tolerant of
# it being the file directly or a differently-named *.raw.
if [ -f "$store_out" ]; then
  img_src="$store_out"
elif [ -f "$store_out/gha-guest.raw" ]; then
  img_src="$store_out/gha-guest.raw"
else
  img_src="$(echo "$store_out"/*.raw)"
fi
[ -f "$img_src" ] || { echo "error: no raw image found under $store_out" >&2; exit 1; }

# Version the artifacts so a re-run never overwrites an image a running consumer
# may still have staged (a clobbered image fails Lima's digest check). Switching
# LIMA_TEMPLATE to the new file is then a clean cutover.
ts="$(date +%Y%m%d-%H%M%S)"
img="$outdir/gha-guest-nixos-$ts.raw"
tmpl="$outdir/gha-guest-nixos-$ts.yaml"

echo ">> Copying image out of the Nix store -> $img ..."
# Store paths are read-only and vanish under nix-collect-garbage; copy to a
# stable, writable location so `nix store gc` can't pull the image out from
# under a running consumer. Write to a temp then rename so a failure can't
# leave a half-written image in place.
install -m 0644 "$img_src" "$img.tmp"
mv -f "$img.tmp" "$img"

# Defense in depth on top of nix/guest.nix's in-derivation verification: re-read
# the UKI straight from the staged image's ESP so a corrupt copy-out (or any
# future regression that slips past the build) fails here, before we advertise
# the image — not at the next VM boot. util-linux's sfdisk is Linux-only, so on
# this Darwin host find the ESP start sector with gptfdisk (EF00 = ESP) and read
# the FAT with mtools, both via nix shell (same pattern as qemu-img elsewhere).
# ukiFile mirrors config.system.boot.loader.ukiFile in nix/guest.nix.
echo ">> Smoke-checking the staged image's ESP contains the UKI..."
ukiFile="nixos.efi"
esp_start="$(nix shell nixpkgs#gptfdisk -c sgdisk -p "$img" | awk '$6=="EF00"{print $2; exit}')"
case "$esp_start" in
  "" | *[!0-9]*) echo "error: could not find an ESP (EF00) partition in $img" >&2; exit 1 ;;
esac
nix shell nixpkgs#mtools -c mdir -i "$img@@$((esp_start * 512))" "::/EFI/Linux/$ukiFile" >/dev/null 2>&1 \
  || { echo "error: UKI ($ukiFile) missing from the staged image's ESP" >&2; exit 1; }
echo ">> ESP smoke check passed."

digest="sha256:$(shasum -a 256 "$img" | awk '{print $1}')"
echo ">> Image digest: $digest"

echo ">> Writing template $tmpl ..."
# cpus/memory/disk mirror the interim runner template; keep them in sync if that
# changes. Empty provisioning: the whole guest is baked by nix/guest.nix.
cat > "$tmpl" <<EOF
# Pre-baked NixOS aarch64 GitHub Actions runner guest.
# Generated by lima/build-nixos-image.sh from the flake (.#gha-guest-image).
# Boots with NO per-job provisioning. Host-specific (absolute path + digest) —
# regenerate with the script rather than editing by hand.
vmType: vz
arch: aarch64
images:
  - location: "file://$img"
    arch: aarch64
    digest: "$digest"
cpus: 4
memory: "12GiB"
disk: "40GiB"
user:
  name: lima
mounts: []
# The guest installs no containerd/nerdctl (its installer fails on NixOS, and
# we don't need it); tell Lima not to wait on it, or readiness never completes.
containerd:
  system: false
  user: false
EOF
# The consumer rejects a group/world-writable LIMA_TEMPLATE; force a safe mode
# regardless of the operator's umask.
chmod 0644 "$tmpl"

echo ""
echo "Done. Point the consumer at the pre-baked image with:"
echo "    LIMA_TEMPLATE=$tmpl"
echo "Restart the consumer with that env when it is idle. Older"
echo "gha-guest-nixos-*.{raw,yaml} in $outdir can be deleted once unused."
