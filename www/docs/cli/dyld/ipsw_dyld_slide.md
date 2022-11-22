---
id: ipsw_dyld_slide
title: ipsw dyld slide
hide_title: true
sidebar_label: slide
description: Dump slide info
last_update:
  date: 2022-11-21T19:10:35-07:00
  author: blacktop
---
# ipsw dyld slide

Dump slide info

```
ipsw dyld slide <dyld_shared_cache> [flags]
```

## Options

```
  -a, --auth           Print only slide info for mappings with auth flags
  -c, --cache string   path to addr to sym cache file
  -h, --help           help for slide
      --json           Output as JSON
```

## Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

## See also

* [ipsw dyld](/docs/cli/dyld/ipsw_dyld)	 - Parse dyld_shared_cache

