---
id: softlinks
title: softlinks
hide_title: true
hide_table_of_contents: true
sidebar_label: softlinks
description: Enumerate SOFT_LINK globals in a DSC image
---
## ipsw dyld softlinks

Enumerate SOFT_LINK globals in a DSC image

```
ipsw dyld softlinks <DSC> [flags]
```

### Options

```
      --filter string   Regex filter for softlink symbol/helper names
  -O, --format string   Output format: tsv, jsonl (default "tsv")
  -h, --help            help for softlinks
      --image string    Image path/name in the DSC
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

