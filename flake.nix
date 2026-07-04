{
  description = "Cross-platform stackable hooks framework for Nim";

  inputs = {
    nixos-modules.url = "github:metacraft-labs/nixos-modules";
    nixpkgs.follows = "nixos-modules/nixpkgs-unstable";
    flake-parts.follows = "nixos-modules/flake-parts";
    git-hooks.follows = "nixos-modules/git-hooks-nix";
  };

  outputs =
    inputs@{ flake-parts, nixos-modules, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        nixos-modules.modules.flake.git-hooks
      ];

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        { pkgs, config, ... }:
        let
          version = "0.1.0";
        in
        {
          pre-commit.settings.hooks = {
            shellcheck.enable = true;
            nixfmt.enable = true;
          };

          packages.default = pkgs.stdenv.mkDerivation {
            pname = "stackable-hooks";
            inherit version;
            src = ./.;

            installPhase = ''
              runHook preInstall
              mkdir -p "$out"
              cp -r src "$out/src"
              runHook postInstall
            '';
          };

          devShells.default = pkgs.mkShell {
            inputsFrom = [ config.pre-commit.devShell ];
            packages = [
              pkgs.just
              pkgs.nim2
              pkgs.nimble
              pkgs.git
              pkgs.nixfmt
            ];
          };
        };
    };
}
