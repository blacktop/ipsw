---
id: slide
title: slide
hide_title: true
sidebar_label: slide
description: Dump slide info
last_update:
  date: 2022-11-24T13:58:11-07:00
  author: blacktop
---
## ipsw dyld slide

Dump slide info

```
ipsw dyld slide <dyld_shared_cache> [flags]
```

### Options

```
  -a, --auth           Print only slide info for mappings with auth flags
  -c, --cache string   path to addr to sym cache file
  -h, --help           help for slide
      --json           Output as JSON
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

