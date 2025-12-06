{inputs, ...}: {
  imports = [
    inputs.git-hooks.flakeModule
    ../common
    ./formatter.nix
    ./go-tools.nix
    ./pre-commit.nix
    ./shell.nix
  ];
}
