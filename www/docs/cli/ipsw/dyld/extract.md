---
id: extract
title: extract
hide_title: true
sidebar_label: extract
description: Extract dyld_shared_cache from DMG in IPSW
last_update:
  date: 2022-11-24T13:58:11-07:00
  author: blacktop
---
## ipsw dyld extract

Extract dyld_shared_cache from DMG in IPSW

```
ipsw dyld extract <IPSW> <DEST> [flags]
```

### Options

```
  -a, --dyld-arch stringArray   dyld_shared_cache architecture to extract
  -h, --help                    help for extract
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache
