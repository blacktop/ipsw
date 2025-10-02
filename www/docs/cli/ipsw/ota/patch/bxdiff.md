---
id: bxdiff
title: bxdiff
hide_title: true
hide_table_of_contents: true
sidebar_label: bxdiff
description: Patch BXDIFF50 OTAs
---
## ipsw ota patch bxdiff

Patch BXDIFF50 OTAs

```
ipsw ota patch bxdiff <DELTA> <TARGET> [flags]
```

### Options

```
  -h, --help            help for bxdiff
  -o, --output string   Output folder
  -s, --single          Patch single file
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

