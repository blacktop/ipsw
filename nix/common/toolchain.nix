# toolchain configuration, shared between dev and build
{lib, ...}: {
  perSystem = {pkgs, ...}: let
    inherit (pkgs) go_1_25 buildGo125Module;
    inherit (pkgs.llvmPackages_latest) bintools clang stdenv;
  in {
    options = {
      stdenv = lib.mkOption {
        default = stdenv;
      };
      toolchain = lib.mkOption {
        type = lib.types.attrs;
        default = {
          # bintools is a nix wrapper for llvm binutils, we use it for lld linker
          inherit bintools clang;

          # use latest go compiler, overriding the nixpkgs default (go_1_24)
          go = go_1_25;
          buildGoModule = buildGo125Module.override {inherit stdenv;};
        };
      };
    };
  };
}
