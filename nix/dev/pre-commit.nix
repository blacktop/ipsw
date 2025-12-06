{
  perSystem = {
    config,
    pkgs,
    ...
  }: {
    pre-commit = {
      check.enable = true;

      settings.hooks = {
        # go linting

        # TODO: `staticcheck` takes time to run and might not provide best `nix develop`
        # activation experience. either re-enable after fixing codebase issues
        # (U1000, SA4009, etc.), or remove from hooks and use manually as
        # `staticcheck ./...` from active `nix develop` shell

        # staticcheck = {
        #   enable = true;
        #   package = config.packages.go-tools;
        # };

        # markdown linting
        # TODO: enable and fix the issues
        # markdownlint.enable = true;

        # nix code linting
        deadnix.enable = true;
        nil.enable = true;
        alejandra.enable = true;
        statix.enable = true;

        # spell checking
        # TODO: enable, filtering out go files, as it catches some legitimate stuff like "udid".
        # alternative would be literal exclusion list if supported by the tool

        # typos.enable = true;
      };
    };

    # hooks installer
    # NOTE: updates to this file are not immediately picked up, remove symlink first:
    # ```sh
    # rm .pre-commit-config.yaml && nix run .#install-hooks
    # ```
    #
    # if using nix-direnv, changes to ./nix/dev require refreshing direnv cache:
    # ```sh
    # direnv reload
    # ```
    # direnv is not installed by this flake, install it with `nix profile add nixpkgs#direnv`

    apps.install-hooks = {
      type = "app";
      program = toString (pkgs.writeShellScript "install-hooks" ''
        ${config.pre-commit.installationScript}
        echo "Pre-commit hooks installed!"
      '');
      meta.description = "install pre-commit hooks";
    };
  };
}
