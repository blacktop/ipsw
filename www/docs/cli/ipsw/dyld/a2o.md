---
id: a2o
title: a2o
hide_title: true
hide_table_of_contents: true
sidebar_label: a2o
description: Convert dyld_shared_cache address to offset
last_update:
  date: 2023-01-10T12:52:46-07:00
  author: blacktop
---
## ipsw dyld a2o

Convert dyld_shared_cache address to offset

```
ipsw dyld a2o <dyld_shared_cache> <vaddr> [flags]
```

### Options

```
  -d, --dec    Return address in decimal
  -h, --help   help for a2o
  -x, --hex    Return address in hexadecimal
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

