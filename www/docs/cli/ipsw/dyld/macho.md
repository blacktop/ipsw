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
  -a, --all[=true|false]         Parse ALL dylibs
      --demangle[=true|false]    Demangle symbol names
  -x, --extract[=true|false]     🚧 Extract the dylib
      --force[=true|false]       Overwrite existing extracted dylib(s)
  -h, --help[=true|false]        help for macho
  -j, --json[=true|false]        Print the TOC as JSON
  -l, --loads[=true|false]       Print the load commands
  -o, --objc[=true|false]        Print ObjC info
  -r, --objc-refs[=true|false]   Print ObjC references
      --output string            Directory to extract the dylib(s)
      --search string            Search for byte pattern
  -f, --starts[=true|false]      Print function starts
  -s, --strings[=true|false]     Print cstrings
  -b, --stubs[=true|false]       Print stubs
  -w, --swift[=true|false]       Print Swift info
      --swift-all[=true|false]   Print all other Swift sections info
  -n, --symbols[=true|false]     Print symbols
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

