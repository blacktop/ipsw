---
id: info
title: info
hide_title: true
hide_table_of_contents: true
sidebar_label: info
description: Parse dyld_shared_cache
---
## ipsw dyld info

Parse dyld_shared_cache

```
ipsw dyld info <DSC> [flags]
```

### Options

```
  -c, --closures   Dump program launch closures
      --delta      Delta two DSC's image's versions
      --diff       Diff two DSC's images
  -d, --dlopen     Dump all dylibs and bundles with dlopen closures
  -l, --dylibs     List dylibs and their versions
  -h, --help       help for info
  -j, --json       Output as JSON
  -s, --sig        Print code signature
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

