---
id: info
title: info
hide_title: true
hide_table_of_contents: true
sidebar_label: info
description: Parse dyld_shared_cache
last_update:
  date: 2022-12-17T17:42:11-07:00
  author: blacktop
---
## ipsw dyld info

Parse dyld_shared_cache

```
ipsw dyld info <dyld_shared_cache> [flags]
```

### Options

```
  -c, --closures   Dump program launch closures
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
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

