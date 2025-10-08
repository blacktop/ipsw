---
id: rsr
title: rsr
hide_title: true
hide_table_of_contents: true
sidebar_label: rsr
description: Patch RSR OTAs
---
## ipsw ota patch rsr

Patch RSR OTAs

```
ipsw ota patch rsr [flags]
```

### Options

```
  -c, --cryptex string          Cryptex file from OTA
  -a, --dyld-arch stringArray   dyld_shared_cache architecture to extract
  -h, --help                    help for rsr
  -i, --input string            Input folder
  -o, --output string           Output folder
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

* [ipsw ota patch](/docs/cli/ipsw/ota/patch)	 - Patch OTAs

