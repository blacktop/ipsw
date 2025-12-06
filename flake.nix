{
  inputs = {
    # module system for nix flakes
    # https://flake.parts
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} (let
      systems = import inputs.systems;
      flakeModules.default = import ./nix/flake-module.nix;
    in {
      # https://flake.parts/debug.html
      # debug = true

      # https://nixos.wiki/wiki/NixOS_modules
      # https://flake.parts/best-practices-for-module-writing.html
      imports = [
        flakeModules.default
        flake-parts.flakeModules.partitions
      ];

      inherit systems;

      # see https://flake.parts/options/flake-parts-partitions.html
      partitionedAttrs = {
        apps = "dev";
        checks = "dev";
        devShells = "dev";
        formatter = "dev";
      };
      partitions.dev = {
        # specifies directory with inputs-only flake.nix
        extraInputsFlake = ./nix/dev;
        module = {
          imports = [./nix/dev];
        };
      };
      # module defining local flake outputs and config
      # for definition of "local flake" see:
      # https://flake.parts/define-module-in-separate-file.html#importapply
      perSystem = {
        config,
        lib,
        ...
      }: {
        options = {
          # used to avoid relative paths with parent references
          src = lib.mkOption {
            default = builtins.path {
              path = ./.;
              name = "ipsw";
            };
          };
        };
        config.packages.default = config.packages.ipsw;
      };

      # exports
      flake = {
        inherit flakeModules;
      };
    });
}
