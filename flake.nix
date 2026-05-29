{
  description = "GitHub Actions runner factory: consumes a gh-webhook-spool queue and runs each job in an ephemeral Lima VM.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, flake-utils, crane, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = (import nixpkgs { inherit system; }).extend (import rust-overlay);

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "clippy" "rustfmt" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain (_: rustToolchain);

        # control.rs embeds the web-UI assets at compile time via include_str!,
        # but crane's default filter keeps only Cargo/Rust files and would drop
        # src/web/*, breaking `nix build`. Union the web assets back in beside
        # the usual cargo sources.
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            (pkgs.lib.hasInfix "/src/web/" path) || (craneLib.filterCargoSources path type);
          name = "source";
        };

        commonArgs = {
          inherit src;
          strictDeps = true;
          pname = "gh-actions-consumer";
          version = "0.1.0";
        };

        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          cargoExtraArgs = "--locked";
        });

        gh-actions-consumer = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          cargoExtraArgs = "--locked";
          meta = {
            description = "Consume a gh-webhook-spool queue and run each job in a Lima VM.";
            mainProgram = "gh-actions-consumer";
          };
        });
      in
      {
        packages = {
          default = gh-actions-consumer;
          gh-actions-consumer = gh-actions-consumer;

          # The ephemeral runner guest, built for aarch64-linux regardless of
          # the host system (Nix offloads to host-setup/linux-builder). Built
          # with systemd-repart (no VM/KVM — make-disk-image's nested VM can't
          # run on this Apple-Silicon host), producing a UEFI appliance image
          # that boots under Lima with no per-job provisioning. See nix/guest.nix.
          gha-guest-image = (nixpkgs.lib.nixosSystem {
            system = "aarch64-linux";
            modules = [ ./nix/guest.nix ];
          }).config.system.build.image;
        };

        devShells.default = craneLib.devShell {
          packages = [
            pkgs.git
            pkgs.lima
          ];
        };
      });
}
