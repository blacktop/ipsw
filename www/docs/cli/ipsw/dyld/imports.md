---
id: imports
title: imports
hide_title: true
hide_table_of_contents: true
sidebar_label: imports
description: List all dylibs that load a given dylib
---
## ipsw dyld imports

List all dylibs that load a given dylib

```
ipsw dyld imports <DSC> <DYLIB> [flags]
```

### Options

```
  -h, --help          help for imports
  -i, --ipsw string   Path to IPSW to scan for MachO files that import dylib
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

