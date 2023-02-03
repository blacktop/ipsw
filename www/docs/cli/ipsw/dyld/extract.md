---
id: extract
title: extract
hide_title: true
hide_table_of_contents: true
sidebar_label: extract
description: Extract dylib from dyld_shared_cache
---
## ipsw dyld extract

Extract dylib from dyld_shared_cache

```
ipsw dyld extract <DSC> <DYLIB> [flags]
```

### Options

```
  -a, --all             Split ALL dylibs
  -c, --cache string    Path to .a2s addr to sym cache file (speeds up analysis)
      --force           Overwrite existing extracted dylib(s)
  -h, --help            help for extract
      --objc            Add ObjC metadata to extracted dylib(s) symtab
  -o, --output string   Directory to extract the dylib(s)
      --slide           Apply slide info to extracted dylib(s)
      --stubs           Add stub islands to extracted dylib(s) symtab
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

