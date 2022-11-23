---
id: ipsw_dyld_symaddr
title: ipsw dyld symaddr
hide_title: true
sidebar_label: symaddr
description: Lookup or dump symbol(s)
last_update:
  date: 2022-11-23T16:33:46-07:00
  author: blacktop
---
# ipsw dyld symaddr

Lookup or dump symbol(s)

```
ipsw dyld symaddr <dyld_shared_cache> [flags]
```

## Options

```
  -a, --all            Find all symbol matches
  -b, --binds          Also search LC_DYLD_INFO binds
  -h, --help           help for symaddr
  -i, --image string   dylib image to search
      --in string      Path to JSON file containing list of symbols to lookup
      --out string     Path to output JSON file
```

## Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

## See also

* [ipsw dyld](/docs/cli/dyld/ipsw_dyld)	 - Parse dyld_shared_cache

