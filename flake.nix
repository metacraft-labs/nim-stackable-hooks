{
  description = "Cross-platform stackable hooks framework for Nim";

  inputs = {
    nixos-modules.url = "github:metacraft-labs/devops-modules";
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
          version = builtins.replaceStrings [ "\n" "\r" ] [ "" "" ] (builtins.readFile ./version.txt);
          # git-hooks.nix installs `.pre-commit-config.yaml` and git hooks into
          # `git rev-parse --show-toplevel` of the directory the shell is entered
          # from, so `nix develop /path/to/this-repo` run inside another checkout
          # would plant this repository's hooks there. `ownRepoOnly` runs a snippet
          # only when that toplevel is this repository, recognised by a `flake.nix`
          # identical to the one this shell was evaluated from; anything it cannot
          # establish counts as another repository, so it fails safe.
          # tests/dev_shell_writes_nothing_elsewhere.sh
          ownRepoOnly = script: ''
            _own_repo_root="$(${pkgs.git}/bin/git rev-parse --show-toplevel 2>/dev/null || true)"
            if [ -n "$_own_repo_root" ] && [ -f "$_own_repo_root/flake.nix" ] \
              && [ "$(${pkgs.coreutils}/bin/sha256sum "$_own_repo_root/flake.nix" | ${pkgs.coreutils}/bin/cut -d' ' -f1)" \
                = "${builtins.hashFile "sha256" ./flake.nix}" ]; then
            ${script}
            # git-hooks.nix's installer leaves core.hooksPath as the RELATIVE
            # `.git/hooks`, in the config every worktree shares. A linked worktree
            # cannot resolve it (there `.git` is a file), so git silently runs no
            # hooks there. Point it at the common hooks directory instead.
            if [ "$(${pkgs.git}/bin/git config --local --get core.hooksPath 2>/dev/null)" = .git/hooks ]; then
              ${pkgs.git}/bin/git config --local core.hooksPath "$(${pkgs.git}/bin/git rev-parse --path-format=absolute --git-common-dir)/hooks"
            fi
            fi
            unset _own_repo_root
          '';
        in
        {
          pre-commit.settings.hooks = {
            shellcheck.enable = true;
            nixfmt.enable = true;
            check-license = {
              enable = true;
              name = "Check License File";
              entry = "bash -c 'if [ ! -f LICENSE ] && [ ! -f LICENSE-APACHE ] && [ ! -f LICENSE-MIT ]; then echo \"Error: No license file (LICENSE, LICENSE-APACHE, LICENSE-MIT) found in repository root!\"; exit 1; fi'";
              files = "^$";
              pass_filenames = false;
            };
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

          devShells.default = pkgs.mkShell (
            {
              # Not `inputsFrom = [ config.pre-commit.devShell ]`: that shell's
              # hook installs the git hooks without `ownRepoOnly`.
              shellHook = ownRepoOnly config.pre-commit.installationScript;
              packages = config.pre-commit.settings.enabledPackages ++ [
                config.pre-commit.settings.package
                pkgs.just
                pkgs.nim2
                pkgs.nimble
                pkgs.git
                pkgs.nixfmt
              ];
            }
            // pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
              # Nimble links OpenSSL but also loads SSL symbols dynamically.
              # Keep both paths on the same implementation instead of Apple's
              # incompatible LibreSSL, which crashes before the test task runs.
              DYLD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.openssl ];
            }
          );
        };
    };
}
