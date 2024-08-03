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
ipsw ota extract <OTA> [FILENAME]> [flags]
```

### Options

```
  -y, --confirm          Confirm searching for pattern in payloadv2 files
  -x, --decomp           Decompress pbzx files
  -d, --dyld             Extract dyld_shared_cache files
  -h, --help             help for extract
  -k, --kernel           Extract kernelcache
  -o, --output string    Output folder
  -p, --pattern string   Regex pattern to match files
  -r, --range string     Regex pattern control the payloadv2 file range to search
```

### Options inherited from parent commands

```
      --color            colorize output
      --config string    config file (default is $HOME/.config/ipsw/config.yaml)
      --key-val string   Base64 encoded symmetric encryption key
      --no-color         disable colorize output
  -V, --verbose          verbose output
```

### SEE ALSO

* [ipsw ota](/docs/cli/ipsw/ota)	 - Parse OTAs

