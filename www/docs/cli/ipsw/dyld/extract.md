---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract dylib from dyld_shared_cache
last_update:
  date: 2023-01-16T23:18:46-07:00
  author: blacktop
---
## ipsw dyld extract

Extract dylib from dyld_shared_cache

```
ipsw dyld extract <DSC> <DYLIB> [flags]
```

### Options

```
  -a, --all             Split ALL dylibs
      --force           Overwrite existing extracted dylib(s)
  -h, --help            help for extract
  -o, --output string   Directory to extract the dylib(s)
      --slide           Apply slide info to extracted dylib(s)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

