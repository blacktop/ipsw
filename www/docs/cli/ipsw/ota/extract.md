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

### Options

```
  -y, --confirm          Skip prompt and search payloadv2 files (requires --pattern)
  -c, --cryptex string   Extract cryptex as DMG (requires full OTA)
  -x, --decomp           Decompress pbzx files
  -d, --dyld             Extract dyld_shared_cache files
  -f, --flat             Do NOT preserve directory structure when extracting
  -h, --help             help for extract
  -k, --kernel           Extract kernelcache
  -o, --output string    Output folder
  -p, --pattern string   Regex pattern to match files
  -r, --range string     Regex pattern to limit payloadv2 files searched (requires --pattern)
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

