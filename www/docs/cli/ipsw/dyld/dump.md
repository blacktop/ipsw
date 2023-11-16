---
id: dump
title: dump
hide_title: true
hide_table_of_contents: true
sidebar_label: dump
description: Dump data at given virtual address
---
## ipsw dyld dump

Dump data at given virtual address

```
ipsw dyld dump <DSC> <ADDR> [flags]
```

### Options

```
  -a, --addr             Output as addresses/uint64s
  -b, --bytes            Output as bytes
  -c, --count uint       The number of total items to display
  -h, --help             help for dump
  -i, --image string     Dump from image (requires --section)
  -o, --output string    Output to a file
  -x, --section string   Dump a specific segment/section (i.e. __TEXT.__text)
  -s, --size uint        Size of data in bytes
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

