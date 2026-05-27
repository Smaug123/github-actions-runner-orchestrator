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

        src = craneLib.cleanCargoSource ./.;

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
        };

        devShells.default = craneLib.devShell {
          packages = [
            pkgs.git
            pkgs.lima
          ];
        };
      });
}
