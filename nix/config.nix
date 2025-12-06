# configuration options (version, vendorHash, frida)
{lib, ...}: let
  # config.json contains:
  # - current ipsw version
  # - vendorHash (must be updated upon go deps update)
  # - pinned frida versions for supported platforms
  cfg = builtins.fromJSON (builtins.readFile ./config.json);
in {
  perSystem = {
    options = {
      version = lib.mkOption {
        default = cfg.version;
      };
      vendorHash = lib.mkOption {
        default = cfg.vendorHash;
      };
      frida = lib.mkOption {
        type = lib.types.submodule {
          options = {
            config = lib.mkOption {
              default = cfg.frida;
            };
            dev-kit = lib.mkOption {
              type = lib.types.nullOr lib.types.package;
              default = null;
            };
          };
        };
      };
    };
  };
}
