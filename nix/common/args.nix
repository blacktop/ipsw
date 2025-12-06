# common arguments, shared between dev and build
{lib, ...}: {
  perSystem = {
    config,
    pkgs,
    ...
  }: let
    inherit (config) frida;

    compileFlags = lib.optionalString (frida.dev-kit != null) "-I${frida.dev-kit}/include";
    linkFlags = lib.optionalString (frida.dev-kit != null) "-L${frida.dev-kit}/lib -lfrida-core";

    mkTags = tags: ["-tags=${lib.concatStringsSep "," tags}"];
  in {
    options = {
      commonArgs = lib.mkOption {
        type = lib.types.attrs;
        default = {
          buildInputs = with pkgs;
            [
              libusb1
              unicorn
            ]
            ++ lib.optionals config.stdenv.hostPlatform.isDarwin [pkgs.apple-sdk_15]
            ++ lib.optionals (frida.dev-kit != null) [frida.dev-kit];

          env.CGO_ENABLED = 1;

          nativeBuildInputs = with config.toolchain; [
            clang
            bintools
          ];

          CGO_CFLAGS = compileFlags;
          CGO_CXXFLAGS = compileFlags;
          CGO_LDFLAGS = linkFlags;
          GOFLAGS = mkTags [
            "unicorn"
            (lib.optionalString (frida.dev-kit != null) "frida")
          ];
        };
      };
    };
  };
}
