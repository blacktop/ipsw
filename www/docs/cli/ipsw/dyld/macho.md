---
id: macho
title: macho
hide_title: true
hide_table_of_contents: true
sidebar_label: macho
description: Parse an incache dylib file
---
## ipsw dyld macho

Parse an incache dylib file

```
ipsw dyld macho <DSC> <DYLIB> [flags]
```

### Options

```
  -a, --all             Parse ALL dylibs
      --demangle        Demangle symbol names
  -x, --extract         🚧 Extract the dylib
      --force           Overwrite existing extracted dylib(s)
  -h, --help            help for macho
  -j, --json            Print the TOC as JSON
  -l, --loads           Print the load commands
  -o, --objc            Print ObjC info
  -r, --objc-refs       Print ObjC references
      --output string   Directory to extract the dylib(s)
      --search string   Search for byte pattern
  -f, --starts          Print function starts
  -s, --strings         Print cstrings
  -b, --stubs           Print stubs
  -w, --swift           Print Swift info
      --swift-all       Print all other Swift sections info
  -n, --symbols         Print symbols
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

