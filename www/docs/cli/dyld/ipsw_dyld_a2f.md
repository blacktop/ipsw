---
id: ipsw_dyld_a2f
title: ipsw dyld a2f
hide_title: true
sidebar_label: a2f
description: Lookup function containing unslid address
last_update:
  date: 2022-11-21T19:10:35-07:00
  author: blacktop
---
# ipsw dyld a2f

Lookup function containing unslid address

```
ipsw dyld a2f <dyld_shared_cache> <vaddr> [flags]
```

## Options

```
  -c, --cache string   Path to .a2s addr to sym cache file (speeds up analysis)
  -h, --help           help for a2f
  -i, --in string      Path to file containing list of addresses to lookup
  -j, --json           Output as JSON
  -o, --out string     Path to output JSON file
  -s, --slide uint     dyld_shared_cache slide to apply
```

## Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

## See also

* [ipsw dyld](/docs/cli/dyld/ipsw_dyld)	 - Parse dyld_shared_cache

