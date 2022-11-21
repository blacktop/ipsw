---
date: 2022-11-20T23:11:40-07:00
title: "ipsw dyld macho"
slug: ipsw_dyld_macho
url: /commands/ipsw_dyld_macho/
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

* [ipsw dyld](/cmd/ipsw_dyld/)	 - Parse dyld_shared_cache

