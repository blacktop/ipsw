---
id: imports
title: imports
hide_title: true
hide_table_of_contents: true
sidebar_label: imports
description: List all dylibs that load a given dylib
last_update:
  date: 2022-11-29T11:50:35-07:00
  author: blacktop
---
## ipsw dyld imports

List all dylibs that load a given dylib

```
ipsw dyld imports [flags]
```

### Options

```
  -f, --file-system   Scan File System in IPSW for MachO files that import dylib
  -h, --help          help for imports
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

