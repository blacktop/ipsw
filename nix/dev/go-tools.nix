# overrides for nixpkgs.go-tools (a.k.a. https://staticcheck.dev)
# to build it with go_1_25 (currently built with go_1_24 by default)
{lib, ...}: {
  perSystem = {
    config,
    pkgs,
    ...
  }: let
    inherit (config.toolchain) go;
  in {
    packages.go-tools =
      (pkgs.go-tools.override {
        inherit (config.toolchain) buildGoModule;
      }).overrideAttrs (old: {
        nativeBuildInputs = (old.nativeBuildInputs or []) ++ [pkgs.makeWrapper];

        # allow runtime reference to go (needed for wrapper)
        disallowedReferences = [];

        postFixup = ''
          wrapProgram $out/bin/staticcheck \
            --prefix PATH : ${lib.makeBinPath [go]}
        '';

        enableParallelBuilding = true;
        NIX_ENFORCE_NO_NATIVE = 0;
        doCheck = false;
      });
  };
}
