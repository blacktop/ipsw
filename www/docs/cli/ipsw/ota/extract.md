---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract OTA payload files
---
## ipsw ota extract

Extract OTA payload files

```
ipsw ota extract <OTA> [FILENAME] [flags]
```

### Examples

```bash
# Extract the dyld_shared_cache files from an OTA
❯ ipsw ota extract OTA.zip --dyld --output ./out
# Same, but non-interactive with a machine-readable report on stdout
❯ ipsw ota extract OTA.zip --dyld --json --output ./out > report.json
# Extract only arm64e cache-family files
❯ ipsw ota extract OTA.zip --dyld --dyld-arch arm64e --output ./out
# Extract the kernelcache, flattening the output directory structure
❯ ipsw ota extract OTA.zip --kernel --flat --output ./out
# Extract every file matching a regex, limited to some payloadv2 members
❯ ipsw ota extract OTA.zip --pattern 'AppleH1[0-9]CameraInterface' --range 'payload.0[0-3]\d' --confirm
```

### Options

```
  -y, --confirm                 Skip prompt and search payloadv2 files (requires --pattern or --dyld)
  -c, --cryptex string          Extract cryptex as DMG (requires full OTA)
  -x, --decomp                  Decompress pbzx files
  -d, --dyld                    Extract dyld_shared_cache files
  -a, --dyld-arch stringArray   dyld_shared_cache architecture(s) to extract (requires --dyld)
  -f, --flat                    Do NOT preserve directory structure when extracting
  -h, --help                    help for extract
  -j, --json                    Output a single JSON dyld_shared_cache extraction report to stdout (requires --dyld)
  -k, --kernel                  Extract kernelcache
  -o, --output string           Output folder
  -p, --pattern string          Regex pattern to match files
  -r, --range string            Regex pattern to limit payloadv2 files searched (requires --pattern or --dyld)
```

### Options inherited from parent commands

```
      --color            colorize output
      --config string    config file (default is $HOME/.config/ipsw/config.yaml)
      --insecure         Allow insecure connections when fetching AEA keys
      --key-db string    Path to AEA keys JSON database (auto-lookup by filename)
      --key-val string   Base64 encoded AEA symmetric encryption key
      --no-color         disable colorize output
  -V, --verbose          verbose output
```

### SEE ALSO

* [ipsw ota](/docs/cli/ipsw/ota)	 - Parse OTAs

