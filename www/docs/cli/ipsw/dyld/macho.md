---
id: macho
title: macho
hide_title: true
hide_table_of_contents: true
sidebar_label: macho
description: Parse a dylib file
last_update:
  date: 2022-11-30T12:14:58-07:00
  author: blacktop
---
## ipsw dyld macho

Parse a dylib file

```
ipsw dyld macho <dyld_shared_cache> <dylib> [flags]
```

### Options

```
  -a, --all             Parse ALL dylibs
  -x, --extract         🚧 Extract the dylib
      --force           Overwrite existing extracted dylib(s)
  -h, --help            help for macho
  -l, --loads           Print the load commands
  -o, --objc            Print ObjC info
  -r, --objc-refs       Print ObjC references
      --output string   Directory to extract the dylib(s)
      --search string   Search for byte pattern
  -f, --starts          Print function starts
  -s, --strings         Print cstrings
  -b, --stubs           Print stubs
  -n, --symbols         Print symbols
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

