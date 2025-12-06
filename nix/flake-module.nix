# main flake module which builds `ipsw`
{lib, ...}: {
  imports = [
    ./config.nix
    ./common
  ];

  perSystem = {config, ...}: let
    inherit
      (config.commonArgs)
      CGO_CFLAGS
      CGO_CXXFLAGS
      CGO_LDFLAGS
      ;

    # config.commonArgs is an attrset, not a derivation, so overrideAttrs cannot be used.
    # we remove the attrs we want to override, then re-add them extended with compiler flags
    commonArgsStripped = builtins.removeAttrs config.commonArgs ["CGO_CFLAGS" "CGO_CXXFLAGS" "CGO_LDFLAGS"];

    compileFlags = "-O3 -mcpu=native -flto=thin -Wall -pipe";
    linkFlags = "-flto=thin -Wl,-dead_strip";

    concatFlags = flags: lib.concatStringsSep " " flags;
  in {
    packages.ipsw = config.toolchain.buildGoModule (commonArgsStripped
      // {
        pname = "ipsw";
        inherit (config) src version vendorHash;

        ldflags = [
          "-s"
          "-w"
          "-X github.com/blacktop/ipsw/cmd/ipsw/cmd.AppVersion=${config.version}"
        ];

        subPackages = ["./cmd/ipsw"];

        enableParallelBuilding = true;

        hardeningDisable = ["all"];
        NIX_ENFORCE_NO_NATIVE = 0;

        CGO_CFLAGS = concatFlags [CGO_CFLAGS compileFlags];
        CGO_CXXFLAGS = concatFlags [CGO_CXXFLAGS compileFlags];
        CGO_LDFLAGS = concatFlags [CGO_LDFLAGS linkFlags];

        # TODO: fine-grained disabling of tests which require network or hardware
        doCheck = false;
      });
  };
}
