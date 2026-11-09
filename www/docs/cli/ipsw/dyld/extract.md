---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract dylib(s) for reverse engineering
---
## ipsw dyld extract

Extract dylib(s) for reverse engineering

```
ipsw dyld extract <DSC> <DYLIB> [flags]
```

### Options

```
  -a, --all[=true|false]     Extract all dylibs
  -c, --cache string         Path to .a2s addr to sym cache file (speeds up analysis)
      --force[=true|false]   Overwrite existing extracted dylib(s)
  -h, --help[=true|false]    help for extract
      --objc[=true|false]    Add ObjC metadata to extracted dylib(s) symtab (implies --slide)
  -o, --output string        Directory to extract the dylib(s)
      --slide[=true|false]   Apply slide info to extracted dylib(s)
      --stubs[=true|false]   Add stub islands to extracted dylib(s) symtab
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

