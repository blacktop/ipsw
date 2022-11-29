---
id: o2a
title: o2a
hide_title: true
hide_table_of_contents: true
sidebar_label: o2a
description: Convert dyld_shared_cache offset to address
last_update:
  date: 2022-11-29T11:50:35-07:00
  author: blacktop
---
## ipsw dyld o2a

Convert dyld_shared_cache offset to address

```
ipsw dyld o2a <dyld_shared_cache> <offset> [flags]
```

### Options

```
  -d, --dec    Return address in decimal
  -h, --help   help for o2a
  -x, --hex    Return address in hexadecimal
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

