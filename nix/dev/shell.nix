# shell for developer mode (`nix develop`)
# recommended: automatic activation via nix-direnv (https://github.com/nix-community/nix-direnv)
# ```sh
# direnv allow .
# ```
{
  perSystem = {
    config,
    pkgs,
    ...
  }: let
    inherit (config) pre-commit;
  in {
    devShells.default = pkgs.mkShell.override {inherit (config) stdenv;} ({
        packages = pre-commit.settings.enabledPackages;

        shellHook = ''
          ${pre-commit.installationScript}
        '';
      }
      // config.commonArgs);
  };
}
