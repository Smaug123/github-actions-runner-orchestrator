# NixOS guest image for the ephemeral GitHub Actions runner VMs.
#
# Built for aarch64-linux (via the host-setup/linux-builder offload) into a
# UEFI disk image with systemd-repart, then booted by Lima (vmType: vz) with
# NO per-job provisioning. One VM runs exactly one JIT job then is destroyed.
#
# Why systemd-repart and not make-disk-image / nixos-generators: those assemble
# the image inside a nested VM that requires the `kvm` build feature, which the
# linux-builder can't provide on this Apple-Silicon (M1) host (no nested virt).
# systemd-repart builds the image as a plain sandboxed derivation (mkfs + file
# copy), so it works on the KVM-less builder. The result is a self-contained
# "appliance" image (no nixos-rebuild profile) booted via a Unified Kernel
# Image that systemd-boot auto-discovers.
#
# Lima drives a Linux guest through cloud-init's NoCloud datasource, reading
# the `cidata` disk it attaches at boot: it creates the lima admin user,
# injects its per-install SSH key, and runs a per-boot script that execs
# Lima's own boot.sh. NixOS's default cloud.cfg already enables the modules
# Lima needs (write-files, growpart, users-groups, scripts-per-boot). But
# Lima's boot scripts assume an FHS distro, so several fail harmlessly here;
# the two pieces that matter — /bin/bash and the lima-guestagent service — we
# provide declaratively below rather than let Lima install them at runtime.
# See ROLLOUT_PLAN.md "Lima boot contract" for the ground truth.
{ config, lib, pkgs, modulesPath, ... }:

let
  # pkgs.github-runner is the runner patched to run on NixOS (the official
  # tarball is dynamically linked against FHS paths that don't exist here).
  # It bundles JS runtimes for node-based actions; we ship only node24 — node20
  # is EOL and nixpkgs marks it insecure, and we'd rather not carry an insecure
  # runtime than keep node20-action compatibility. Actions pinned to an old
  # `using: node20` need bumping to a node24 release to run here.
  github-runner = pkgs.github-runner.override { nodeRuntimes = [ "node24" ]; };

  # Run exactly one JIT job as the unprivileged `runner` user, then exit.
  # The consumer copies the JIT config into the guest and invokes this over
  # `limactl shell` as `sudo gha-run-once /tmp/jit` (runs as root, drops to
  # runner). `exec` propagates the runner's exit code back to the consumer.
  # The wrapped run.sh sets RUNNER_ROOT=$HOME/.github-runner, so with `-H`
  # the runner writes _work/_diag under /home/runner.
  gha-run-once = pkgs.writeShellApplication {
    name = "gha-run-once";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      if [ "$#" -ne 1 ]; then
        echo "usage: gha-run-once <jit-config-path>" >&2
        exit 2
      fi
      jit_path="$1"
      exec /run/wrappers/bin/sudo -H -u runner \
        ${github-runner}/bin/run.sh --jitconfig "$(cat "$jit_path")"
    '';
  };

  efiArch = pkgs.stdenv.hostPlatform.efiArch;
in
{
  imports = [
    # virtio kernel drivers for the Lima (vz) guest.
    "${modulesPath}/profiles/qemu-guest.nix"
    # systemd-repart-based image builder (config.system.build.image).
    "${modulesPath}/image/repart.nix"
  ];

  # --- Bootable UEFI appliance via a Unified Kernel Image ---
  # vz provides EFI firmware that boots the removable-media path
  # /EFI/BOOT/BOOTAA64.EFI (systemd-boot), which then auto-discovers the UKI in
  # /EFI/Linux. No in-place bootloader install — the ESP is baked below.
  boot.loader.grub.enable = false;
  boot.kernelParams = [ "console=hvc0" ]; # vz's virtio console; surfaces in Lima's serial log
  boot.growPartition = true; # grow the root partition when Lima resizes the disk

  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "ext4";
    autoResize = true;
  };

  image.repart = {
    name = "gha-guest";
    # vz's EFI (like OVMF) does not handle repart's 4096-byte default; VM disk
    # images use 512-byte sectors.
    sectorSize = 512;
    partitions = {
      "esp" = {
        contents = {
          "/EFI/BOOT/BOOT${lib.toUpper efiArch}.EFI".source =
            "${pkgs.systemd}/lib/systemd/boot/efi/systemd-boot${efiArch}.efi";
          # Boot the single UKI immediately, no menu.
          "/loader/loader.conf".source = pkgs.writeText "loader.conf" "timeout 0\n";
        };
        repartConfig = {
          Type = "esp";
          Format = "vfat";
          # Keep the ESP at 512M for two independent reasons, both of which
          # silently produce an unbootable image if violated:
          #   1. FAT cluster minimum: mkfs.vfat builds a malformed filesystem
          #      below ~32M (too few clusters), which some UEFI firmwares (vz's
          #      included) reject — empty serial, VM halts a few seconds in.
          #   2. UKI headroom: the UKI (kernel+initrd) is ~86M and must fit whole.
          # We also copy the UKI into the FAT image in postBuild below rather than
          # via repart's contents/CopyFiles, because that path silently dropped it
          # while reporting success (see the postBuild override and its verify).
          SizeMinBytes = "512M";
        };
      };
      "root" = {
        storePaths = [ config.system.build.toplevel ];
        repartConfig = {
          Type = "root";
          Format = "ext4";
          Label = "nixos";
          Minimize = "guess";
        };
      };
    };
  };

  system.build.image = lib.mkForce (config.image.repart.image.overrideAttrs (old: {
    # sfdisk (util-linux) + jq locate the ESP from the partition table; mtools
    # does the FAT copy/verify. mtools is already on PATH for the vfat partition,
    # but list it so this override does not depend on that implementation detail.
    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [
      pkgs.util-linux
      pkgs.jq
      pkgs.mtools
      pkgs.coreutils
    ];
    postBuild = (old.postBuild or "") + ''
      echo "Copying UKI into ESP..."
      img=${config.image.baseName}.raw
      uki=${config.system.build.uki}/${config.system.boot.loader.ukiFile}

      # Fail loudly if the UKI input is not where we expect, rather than baking
      # an empty, unbootable ESP. Two causes seen/anticipated: a future nixpkgs
      # change to system.build.uki's layout (today a dir holding
      # ${config.system.boot.loader.ukiFile}), or the input store path being
      # GC'd off the builder mid-build (auto-GC has raced this build; the
      # lima/build-nixos-image.sh retry recovers — see linux-builder/README.md).
      [ -f "$uki" ] || { echo "error: UKI not found at $uki (build.uki layout changed, or input GC'd on the builder?)" >&2; exit 1; }

      # Locate the ESP by its GPT type GUID instead of assuming repart's default
      # 1 MiB first-partition offset: if repart's alignment/padding ever changes,
      # a hard-coded offset would make mtools silently target the wrong region.
      esp_guid=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
      esp_start=$(sfdisk -J "$img" | jq -r --arg g "$esp_guid" \
        '.partitiontable.partitions[] | select((.type | ascii_upcase) == $g) | .start')
      case "$esp_start" in
        "" | *[!0-9]*) echo "error: could not locate ESP (type $esp_guid) in $img" >&2; exit 1 ;;
      esac
      esp="$img@@$(( esp_start * ${toString config.image.repart.sectorSize} ))"

      if ! mdir -i "$esp" ::/EFI/Linux >/dev/null 2>&1; then
        mmd -i "$esp" ::/EFI/Linux
      fi
      mcopy -o -i "$esp" "$uki" ::/EFI/Linux/${config.system.boot.loader.ukiFile}

      # Verify the copy actually landed: repart's own vfat CopyFiles reported
      # success while dropping the UKI, so re-read it straight from the FAT and
      # fail the build on any miss (absent / truncated / not a PE image) instead
      # of shipping an appliance that builds clean but does not boot.
      mdir -i "$esp" ::/EFI/Linux/${config.system.boot.loader.ukiFile} >/dev/null \
        || { echo "error: UKI absent from ESP after copy" >&2; exit 1; }
      check=$(mktemp)
      mcopy -o -i "$esp" ::/EFI/Linux/${config.system.boot.loader.ukiFile} "$check"
      want=$(stat -c %s "$uki")
      got=$(stat -c %s "$check")
      [ "$got" -ge "$want" ] || { echo "error: ESP UKI truncated ($got < $want bytes)" >&2; exit 1; }
      [ "$(head -c 2 "$check")" = "MZ" ] || { echo "error: ESP UKI is not a PE image" >&2; exit 1; }
      rm -f "$check"
      echo "UKI verified in ESP: /EFI/Linux/${config.system.boot.loader.ukiFile} ($got bytes)."
    '';
  }));

  # --- Lima boot contract: cloud-init NoCloud from the cidata disk ---
  # NoCloud auto-detects the `cidata` disk by label; pinning the datasource
  # list skips the slow EC2/GCE/Azure probes (and their network timeouts).
  services.cloud-init = {
    enable = true;
    network.enable = false; # we configure DHCP via networkd below
    settings.datasource_list = [ "NoCloud" ];
  };

  # Lima's hostagent reaches the guest over SSH; cloud-init drops Lima's
  # per-install key into the lima user's authorized_keys.
  services.openssh.enable = true;

  # Lima's SSH readiness probe (`ssh ... -- /bin/bash -c ...`) and several of
  # its guest boot scripts hardcode /bin/bash, which NixOS does not provide
  # (only /bin/sh). Without it the probe returns 127 forever and `limactl
  # start` never sees the VM reach "running". tmpfiles runs in sysinit, well
  # before the probe or any boot script.
  systemd.tmpfiles.rules = [ "L+ /bin/bash - - - - ${pkgs.bash}/bin/bash" ];

  # Lima's hostagent connects to the guest agent (vsock port 2222) for port
  # forwarding. Lima normally installs it at runtime via boot.sh, but that
  # writes a unit into /etc/systemd/system, which is read-only on NixOS — the
  # install fails ("read-only file system"). Declare the service natively
  # instead, taking the static binary and the vsock/virtio port from the cidata
  # disk Lima attaches (identical on every boot). Mirrors the port selection in
  # Lima's own 25-guestagent-base.sh.
  #
  # cidata is an iso9660 disk Lima mounts late, from its per-boot cloud-init
  # script (run by cloud-final.service) — there is no early .mount unit to order
  # against — so we start after cloud-final, by which point /mnt/lima-cidata is
  # mounted. The hostagent retries until then, so the agent need not be first up.
  systemd.services.lima-guestagent = {
    description = "Lima guest agent";
    wantedBy = [ "multi-user.target" ];
    after = [ "cloud-final.service" ];
    serviceConfig = {
      Type = "simple";
      Restart = "on-failure";
      ExecStart = pkgs.writeShellScript "lima-guestagent-daemon" ''
        set -a
        . /mnt/lima-cidata/lima.env
        set +a
        args=()
        if [ "''${LIMA_CIDATA_VSOCK_PORT:-0}" != "0" ]; then
          args=(--vsock-port "$LIMA_CIDATA_VSOCK_PORT")
        elif [ -n "''${LIMA_CIDATA_VIRTIO_PORT:-}" ]; then
          args=(--virtio-port "$LIMA_CIDATA_VIRTIO_PORT")
        fi
        exec /mnt/lima-cidata/lima-guestagent daemon "''${args[@]}" \
          --runtime-dir=/run/lima-guestagent
      '';
    };
  };

  # systemd-networkd + DHCP on the virtio NIC. cloud-init's init/final stages
  # (which create the lima user and run Lima's boot.sh) order after
  # network-online.target, so the link must actually come up or boot stalls.
  networking.useNetworkd = true;
  networking.useDHCP = false;
  systemd.network.networks."10-lima-dhcp" = {
    matchConfig.Name = "en* eth*";
    networkConfig.DHCP = "yes";
    linkConfig.RequiredForOnline = "routable";
  };

  # Lima's admin user. cloud-init injects Lima's per-install SSH key into its
  # authorized_keys at boot (mutableUsers lets it write there). We declare it
  # natively — rather than letting cloud-init create it — so its sudo rights
  # come from `wheel` below: NixOS's sudoers does not @includedir
  # /etc/sudoers.d, so the drop-in cloud-init writes for it would be ignored.
  # The uid is left to NixOS (with no mounts, Lima reaches lima by name over
  # SSH and never depends on the host uid matching).
  users.mutableUsers = true;
  users.users.lima = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
  };

  # The unprivileged user that actually executes each job (the runner refuses
  # to run as root, so the job always lands here).
  users.users.runner = {
    isNormalUser = true;
    home = "/home/runner";
    extraGroups = [ "wheel" ];
  };

  # Passwordless sudo for both: the consumer runs `sudo gha-run-once` as lima,
  # and workflows expect passwordless sudo as runner (matching GitHub-hosted
  # runners; many actions, e.g. the Determinate Nix installer, call sudo).
  # Root inside this throwaway VM is fine — the VM is the isolation boundary.
  security.sudo.wheelNeedsPassword = false;
  # Pin secure_path so `sudo gha-run-once` resolves the wrapper deterministically
  # regardless of the (non-login) SSH command environment limactl shell hands us.
  security.sudo.extraConfig = ''
    Defaults secure_path="/run/wrappers/bin:/run/current-system/sw/bin:/usr/bin:/bin"
  '';

  # Minimal job toolchain: the runner itself, gha-run-once, plus git + node
  # for actions/checkout and node-based actions.
  #
  # minio-client (`mc`) is the artifact transport to the self-hosted Mac S3 store
  # (host-setup/mac-cache-s3): the workflow's `mc cp` steps push/pull the per-run
  # job→job bundle over host.lima.internal instead of GitHub artifact storage.
  # The build *cache* needs nothing here — tespkg/actions-cache is a node24 JS
  # action that carries its own S3 client.
  environment.systemPackages = [
    gha-run-once
    github-runner
    pkgs.git
    pkgs.nodejs_24
    pkgs.minio-client
  ];

  # Nix is provided by the OS here, so workflows must NOT run the Determinate
  # (or any) Nix installer — it refuses on NixOS and would fight the
  # daemon-managed, read-only /etc/nix. Enable the modern CLI + flakes
  # system-wide so jobs can call `nix build` / `nix develop` / `nix flake`
  # directly (the daemon + `nix` on PATH come from NixOS by default). The
  # runner stays a non-trusted daemon user; Phase 3 bakes the shared substituter
  # into this system config so jobs get a warm store without needing
  # trusted-user (which would let untrusted job code add arbitrary caches).
  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  # Phase 3 (3b): add the Mac signing cache as an EXTRA substituter so jobs fetch
  # warm, signed aarch64-linux paths from the host ahead of cache.nixos.org.
  #
  # Use `extra-substituters` / `extra-trusted-public-keys`, NOT the bare
  # `substituters` / `trusted-public-keys`: the bare options REPLACE NixOS's
  # defaults, which would silently drop cache.nixos.org and its signing key and
  # break fallback for anything the Mac hasn't warmed. The `extra-*` forms append
  # to the defaults, so the final config trusts BOTH keys and queries BOTH caches.
  #
  # Reachability: the URL is the Lima usernet name host.lima.internal, which the
  # in-process usernet gateway forwards to the host's loopback-bound darkhttpd
  # (see host-setup/mac-cache). Plain HTTP is fine — integrity comes from the
  # narinfo signature verified against the key below, not from the transport; an
  # unreachable cache (server down / not yet deployed) just fast-fails to
  # cache.nixos.org. The Mac cache advertises `Priority: 10` (< cache.nixos.org's
  # 40), so it WINS for any path present in both — substituter list order is not
  # preference. Baked into the system config (not added per job) so the runner
  # stays a non-trusted daemon user.
  nix.settings.extra-substituters = [ "http://host.lima.internal:8080" ];
  nix.settings.extra-trusted-public-keys = [
    "gha-mac-cache-1:b2Z+TC5MgDzPdvNOLm5RB9NAAQV5r7Emi6his95XR+s="
  ];

  # Ephemeral, single-job VM: stateVersion only governs stateful-service
  # migration semantics we never hit, so track the pinned nixpkgs.
  system.stateVersion = config.system.nixos.release;
}
