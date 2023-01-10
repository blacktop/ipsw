---
id: patches
title: patches
hide_title: true
hide_table_of_contents: true
sidebar_label: patches
description: Dump dyld patch info
last_update:
  date: 2023-01-10T12:52:46-07:00
  author: blacktop
---
## ipsw dyld patches

Dump dyld patch info

```
ipsw dyld patches <dyld_shared_cache> [flags]
```

### Options

```
  -h, --help           help for patches
  -i, --image string   dylib image to search
  -s, --sym string     dylib image symbol to dump patches for
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

