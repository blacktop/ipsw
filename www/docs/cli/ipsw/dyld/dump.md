---
id: dump
title: dump
hide_title: true
hide_table_of_contents: true
sidebar_label: dump
description: Dump dyld_shared_cache data at given virtual address
last_update:
  date: 2022-11-27T12:58:11-07:00
  author: blacktop
---
## ipsw dyld dump

Dump dyld_shared_cache data at given virtual address

```
ipsw dyld dump <dyld_shared_cache> <address> [flags]
```

### Options

```
  -a, --addr            Output as addresses/uint64s
  -b, --bytes           Output as bytes
  -c, --count uint      The number of total items to display
  -h, --help            help for dump
  -o, --output string   Output to a file
  -s, --size uint       Size of data in bytes
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

