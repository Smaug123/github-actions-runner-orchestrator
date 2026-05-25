{
  description = "GitHub Actions runner factory: consumes a gh-webhook-spool queue and runs each job in an ephemeral Lima VM.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    let
      inherit (nixpkgs) lib;

      mkPkgs = system: import nixpkgs { inherit system; };

      mkSource = pkgs:
        let
          sourceRoot = toString ./.;
        in
        pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let
              rel = lib.removePrefix "${sourceRoot}/" (toString path);
            in
            rel == "Cargo.lock"
            || rel == "Cargo.toml"
            || rel == "src"
            || lib.hasPrefix "src/" rel
            || rel == "tests"
            || lib.hasPrefix "tests/" rel;
        };

      # Mirror gh-webhook-spool's flake: only evaluate the package derivation
      # once Cargo.lock exists, so the devshell still works on first use.
      hasLockfile = builtins.pathExists ./Cargo.lock;

      mkConsumer = pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "gh-actions-consumer";
          version = "0.1.0";
          src = mkSource pkgs;
          cargoLock.lockFile = ./Cargo.lock;
          meta = {
            description = "Consume a gh-webhook-spool queue and run each job in a Lima VM.";
            mainProgram = "gh-actions-consumer";
          };
        };
    in
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = mkPkgs system;
      in
      {
        packages = lib.optionalAttrs hasLockfile (
          let consumer = mkConsumer pkgs; in {
            default = consumer;
            gh-actions-consumer = consumer;
          }
        );

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.git
            pkgs.pkg-config
            pkgs.lima
          ];
        };
      });
}
