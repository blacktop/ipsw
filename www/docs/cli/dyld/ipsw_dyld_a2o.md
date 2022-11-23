---
id: ipsw_dyld_a2o
title: ipsw dyld a2o
hide_title: true
sidebar_label: a2o
description: Convert dyld_shared_cache address to offset
last_update:
  date: 2022-11-23T16:33:46-07:00
  author: blacktop
---
# ipsw dyld a2o

Convert dyld_shared_cache address to offset

```
ipsw dyld a2o <dyld_shared_cache> <vaddr> [flags]
```

## Options

```
  -d, --dec    Return address in decimal
  -h, --help   help for a2o
  -x, --hex    Return address in hexadecimal
```

## Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

## See also

* [ipsw dyld](/docs/cli/dyld/ipsw_dyld)	 - Parse dyld_shared_cache

