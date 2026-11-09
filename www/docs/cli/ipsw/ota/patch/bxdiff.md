---
id: bxdiff
title: bxdiff
hide_title: true
hide_table_of_contents: true
sidebar_label: bxdiff
description: Patch BXDIFF50 OTAs (patches and basesystem_patches)
---
## ipsw ota patch bxdiff

Patch BXDIFF50 OTAs (patches and basesystem_patches)

```
ipsw ota patch bxdiff <OTA> | -s <DELTA> <TARGET> [flags]
```

### Options

```
  -h, --help[=true|false]     help for bxdiff
  -i, --input string          Input folder containing base files to patch
  -o, --output string         Output folder
  -s, --single[=true|false]   Patch single file
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --insecure[=true|false]   Allow insecure connections when fetching AEA keys
      --key-db string           Path to AEA keys JSON database (auto-lookup by filename)
      --key-val string          Base64 encoded AEA symmetric encryption key
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw ota patch](/docs/cli/ipsw/ota/patch)	 - Patch OTAs

